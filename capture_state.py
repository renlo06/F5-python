#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Relevé en lecture seule de l'état runtime BIG-IP : virtual servers, pools,
membres, nodes. Les pools sont relevés sur TOUTES les partitions via /*/*.

Fichiers produits (captures/<label>_<phase>_<horodatage>/) :
    state_virtual.txt      show ltm virtual field-fmt
    state_pool.txt         show ltm pool /*/* members field-fmt
    state_node.txt         show ltm node field-fmt
    state_summary.json     synthèse parsée
    _meta_state.json       métadonnées (shell, durées, tailles, SHA256)

Usage:
    python capture_state.py --host 10.0.0.11 --label bigip-a [--phase before|after]
    python capture_state.py -f equipements.txt [--phase before|after]

Format de equipements.txt (une ligne par équipement, '#' = commentaire) :
    10.0.0.11  bigip-a
    10.0.0.12  bigip-b

Le mot de passe peut être fourni via la variable d'environnement BIGIP_PASSWORD.
"""

import argparse
import getpass
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import paramiko
except ImportError:
    print("[ERREUR] paramiko requis : pip install paramiko")
    sys.exit(2)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

TIMEOUT_CONNEXION = 15      # secondes
TIMEOUT_COMMANDE = 180      # secondes
REPERTOIRE_SORTIE = "captures"

# (fichier de sortie, commande tmsh)
COMMANDES_TMSH = [
    ("state_virtual.txt", "show ltm virtual field-fmt"),
    ("state_pool.txt", "show ltm pool /*/* members field-fmt"),
    ("state_node.txt", "show ltm node field-fmt"),
]


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #

def sha256_texte(texte: str) -> str:
    return hashlib.sha256(texte.encode("utf-8", errors="replace")).hexdigest()


def demander_phase() -> str:
    while True:
        rep = input("Phase de la capture [before/after] : ").strip().lower()
        if rep in ("before", "after"):
            return rep
        print("  Réponse invalide, tapez 'before' ou 'after'.")


def lire_fichier_equipements(chemin: str) -> List[Tuple[str, str]]:
    """Lit 'ip [label]' par ligne ; '#' = commentaire."""
    equipements: List[Tuple[str, str]] = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            ligne = ligne.split("#", 1)[0].strip()
            if not ligne:
                continue
            parties = ligne.split()
            hote = parties[0]
            label = parties[1] if len(parties) > 1 else hote
            equipements.append((hote, label))
    return equipements


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #

def ouvrir_connexion(hote: str, port: int, utilisateur: str, mot_de_passe: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=hote,
        port=port,
        username=utilisateur,
        password=mot_de_passe,
        timeout=TIMEOUT_CONNEXION,
        banner_timeout=TIMEOUT_CONNEXION,
        auth_timeout=TIMEOUT_CONNEXION,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def executer(client: paramiko.SSHClient, commande: str, timeout: int = TIMEOUT_COMMANDE) -> Tuple[int, str, str]:
    _stdin, stdout, stderr = client.exec_command(commande, timeout=timeout)
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, sortie, erreur


def detecter_shell(client: paramiko.SSHClient) -> str:
    """Retourne 'tmsh' si le shell de connexion est tmsh, sinon 'bash'."""
    code, sortie, _err = executer(client, "show sys version", timeout=30)
    if code == 0 and "Sys::Version" in sortie:
        return "tmsh"
    return "bash"


def construire_commande(shell: str, cmd_tmsh: str) -> str:
    """Adapte la commande au shell de connexion (guillemets simples : '*' protégé)."""
    if shell == "bash":
        return "tmsh -c '{}'".format(cmd_tmsh)
    return cmd_tmsh


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def _extraire_valeur(bloc: str, champ: str) -> Optional[str]:
    m = re.search(r"^\s*{}\s+(\S+)".format(re.escape(champ)), bloc, re.MULTILINE)
    return m.group(1) if m else None


def _decouper_blocs(texte: str, prefixe: str) -> List[Tuple[str, str]]:
    """Découpe 'prefixe <nom> {' ... '}' de premier niveau en (nom, contenu)."""
    blocs: List[Tuple[str, str]] = []
    motif = re.compile(r"^{}\s+(\S+)\s*\{{".format(re.escape(prefixe)), re.MULTILINE)
    for m in motif.finditer(texte):
        nom = m.group(1)
        debut = m.end()
        profondeur = 1
        i = debut
        while i < len(texte) and profondeur > 0:
            if texte[i] == "{":
                profondeur += 1
            elif texte[i] == "}":
                profondeur -= 1
            i += 1
        blocs.append((nom, texte[debut:i - 1]))
    return blocs


def parser_virtuals(texte: str) -> List[Dict[str, Optional[str]]]:
    resultat = []
    for nom, bloc in _decouper_blocs(texte, "ltm virtual"):
        resultat.append({
            "nom": nom,
            "destination": _extraire_valeur(bloc, "destination"),
            "disponibilite": _extraire_valeur(bloc, "status.availability-state"),
            "etat": _extraire_valeur(bloc, "status.enabled-state"),
            "raison": _extraire_valeur(bloc, "status.status-reason"),
        })
    return resultat


def parser_pools(texte: str) -> List[Dict[str, object]]:
    resultat = []
    for nom, bloc in _decouper_blocs(texte, "ltm pool"):
        membres = []
        m = re.search(r"^\s*members\s*\{", bloc, re.MULTILINE)
        if m:
            debut = m.end()
            profondeur = 1
            i = debut
            while i < len(bloc) and profondeur > 0:
                if bloc[i] == "{":
                    profondeur += 1
                elif bloc[i] == "}":
                    profondeur -= 1
                i += 1
            zone = bloc[debut:i - 1]
            for adresse, contenu in re.findall(r"(\S+:\S+)\s*\{((?:[^{}]|\{[^{}]*\})*)\}", zone):
                membres.append({
                    "membre": adresse,
                    "disponibilite": _extraire_valeur(contenu, "status.availability-state"),
                    "etat": _extraire_valeur(contenu, "status.enabled-state"),
                    "raison": _extraire_valeur(contenu, "status.status-reason"),
                })
        resultat.append({
            "nom": nom,
            "disponibilite": _extraire_valeur(bloc, "status.availability-state"),
            "etat": _extraire_valeur(bloc, "status.enabled-state"),
            "membres": membres,
        })
    return resultat


def parser_nodes(texte: str) -> List[Dict[str, Optional[str]]]:
    resultat = []
    for nom, bloc in _decouper_blocs(texte, "ltm node"):
        resultat.append({
            "nom": nom,
            "adresse": _extraire_valeur(bloc, "addr"),
            "disponibilite": _extraire_valeur(bloc, "status.availability-state"),
            "etat": _extraire_valeur(bloc, "status.enabled-state"),
            "raison": _extraire_valeur(bloc, "status.status-reason"),
        })
    return resultat


# --------------------------------------------------------------------------- #
# Capture d'un équipement
# --------------------------------------------------------------------------- #

def capturer_equipement(hote: str, label: str, phase: str, utilisateur: str,
                        mot_de_passe: str, port: int, racine: Path) -> bool:
    print("\n=== {} ({}) [{}] ===".format(label, hote, phase))
    debut_global = time.time()

    try:
        client = ouvrir_connexion(hote, port, utilisateur, mot_de_passe)
    except Exception as exc:
        print("  [ERREUR] Connexion impossible : {}".format(exc))
        return False

    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier = racine / "{}_{}_{}".format(label, phase, horodatage)
    dossier.mkdir(parents=True, exist_ok=True)

    meta: Dict[str, object] = {
        "hote": hote,
        "label": label,
        "phase": phase,
        "horodatage": horodatage,
        "fichiers": {},
    }
    contenus: Dict[str, str] = {}
    succes = True

    try:
        shell = detecter_shell(client)
        meta["shell"] = shell
        print("  Shell détecté : {}".format(shell))

        for nom_fichier, cmd_tmsh in COMMANDES_TMSH:
            commande = construire_commande(shell, cmd_tmsh)
            t0 = time.time()
            try:
                code, sortie, erreur = executer(client, commande)
            except Exception as exc:
                print("  [ERREUR] '{}' : {}".format(cmd_tmsh, exc))
                succes = False
                continue
            duree = round(time.time() - t0, 2)

            if code != 0:
                print("  [ERREUR] '{}' (code {}) : {}".format(cmd_tmsh, code, (erreur or sortie).strip()))
                succes = False
                continue

            (dossier / nom_fichier).write_text(sortie, encoding="utf-8")
            contenus[nom_fichier] = sortie
            meta["fichiers"][nom_fichier] = {
                "commande": cmd_tmsh,
                "octets": len(sortie.encode("utf-8", errors="replace")),
                "sha256": sha256_texte(sortie),
                "duree_s": duree,
            }
            print("  OK  {:<20} {:>8} octets  ({} s)".format(nom_fichier, len(sortie), duree))
    finally:
        client.close()

    synthese = {
        "virtuals": parser_virtuals(contenus.get("state_virtual.txt", "")),
        "pools": parser_pools(contenus.get("state_pool.txt", "")),
        "nodes": parser_nodes(contenus.get("state_node.txt", "")),
    }
    (dossier / "state_summary.json").write_text(
        json.dumps(synthese, indent=2, ensure_ascii=False), encoding="utf-8")

    meta["duree_totale_s"] = round(time.time() - debut_global, 2)
    meta["succes"] = succes
    (dossier / "_meta_state.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    print("  Synthèse : {} virtuals, {} pools, {} nodes".format(
        len(synthese["virtuals"]), len(synthese["pools"]), len(synthese["nodes"])))
    print("  Dossier  : {}".format(dossier))
    return succes


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(description="Relevé d'état runtime BIG-IP (lecture seule)")
    parser.add_argument("--host", help="Adresse IP ou nom de l'équipement")
    parser.add_argument("--label", help="Nom court utilisé pour nommer les fichiers")
    parser.add_argument("-f", "--file", help="Fichier listant les équipements")
    parser.add_argument("--phase", choices=["before", "after"], help="Phase de la capture")
    parser.add_argument("--user", help="Utilisateur SSH")
    parser.add_argument("--port", type=int, default=22, help="Port SSH (défaut : 22)")
    parser.add_argument("--output", default=REPERTOIRE_SORTIE, help="Répertoire de sortie")
    args = parser.parse_args()

    if args.file:
        equipements = lire_fichier_equipements(args.file)
    elif args.host:
        equipements = [(args.host, args.label or args.host)]
    else:
        parser.error("Indiquer --host ou -f")
        return 2

    if not equipements:
        print("[ERREUR] Aucun équipement à traiter.")
        return 2

    phase = args.phase or demander_phase()

    utilisateur = args.user or input("Utilisateur SSH : ").strip()
    mot_de_passe = os.environ.get("BIGIP_PASSWORD") or getpass.getpass("Mot de passe : ")

    racine = Path(args.output)
    racine.mkdir(parents=True, exist_ok=True)

    bilan: List[Tuple[str, bool]] = []
    for hote, label in equipements:
        ok = capturer_equipement(hote, label, phase, utilisateur, mot_de_passe, args.port, racine)
        bilan.append((label, ok))

    print("\n=== Bilan [{}] ===".format(phase))
    for label, ok in bilan:
        print("  {:<30} {}".format(label, "OK" if ok else "ERREUR"))
    return 0 if all(ok for _l, ok in bilan) else 1


if __name__ == "__main__":
    sys.exit(main())
