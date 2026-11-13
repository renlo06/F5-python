#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Relevé en lecture seule de l'état runtime BIG-IP : virtual servers, pools, membres, nodes.

Fichiers produits (captures/<label>_<phase>_<horodatage>/) :
    state_virtual.txt      show ltm virtual field-fmt
    state_pool.txt         show ltm pool members field-fmt
    state_node.txt         show ltm node field-fmt
    state_summary.json     synthèse parsée (états stables uniquement)
    _meta_state.json       métadonnées (shell, durées, tailles, SHA256)

Usage:
    python capture_state.py --host 10.0.0.11 --label bigip-a [--phase before|after]
    python capture_state.py -f equipements.txt [--phase before|after]

Format de equipements.txt (une ligne par équipement, '#' = commentaire) :
    10.0.0.11  bigip-a
    10.0.0.12  bigip-b
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

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------
SORTIE_RACINE = Path("captures")
TIMEOUT_CONNEXION = 15
TIMEOUT_COMMANDE = 120

# (nom du fichier, commande tmsh). Uniquement des commandes en lecture seule.
COMMANDES_TMSH = [
    ("state_virtual.txt", "show ltm virtual field-fmt"),
    ("state_pool.txt", "show ltm pool members field-fmt"),
    ("state_node.txt", "show ltm node field-fmt"),
]

# Champs stables conservés dans le résumé (les compteurs volatils sont exclus).
CHAMPS_STABLES = (
    "status.availability-state",
    "status.enabled-state",
    "status.status-reason",
)


# ----------------------------------------------------------------------
# Utilitaires
# ----------------------------------------------------------------------
def sha256_texte(texte: str) -> str:
    return hashlib.sha256(texte.encode("utf-8", errors="replace")).hexdigest()


def demander_phase() -> str:
    """Demande interactivement l'état de la capture : before ou after."""
    while True:
        choix = input("État de la capture [before/after] (b/a) : ").strip().lower()
        if choix in ("b", "before"):
            return "before"
        if choix in ("a", "after"):
            return "after"
        print("Réponse invalide : saisir 'before' (b) ou 'after' (a).")


def lire_equipements(chemin: Path) -> List[Tuple[str, str]]:
    equipements = []
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#"):
            continue
        parties = ligne.split()
        hote = parties[0]
        label = parties[1] if len(parties) > 1 else hote
        equipements.append((hote, label))
    return equipements


# ----------------------------------------------------------------------
# SSH
# ----------------------------------------------------------------------
def connecter(hote: str, utilisateur: str, mot_de_passe: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # pas de vérification de clé
    client.connect(
        hote,
        username=utilisateur,
        password=mot_de_passe,
        timeout=TIMEOUT_CONNEXION,
        banner_timeout=TIMEOUT_CONNEXION,
        auth_timeout=TIMEOUT_CONNEXION,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def executer(client: paramiko.SSHClient, commande: str) -> Tuple[int, str, str]:
    _in, out, err = client.exec_command(commande, timeout=TIMEOUT_COMMANDE)
    sortie = out.read().decode("utf-8", errors="replace")
    erreur = err.read().decode("utf-8", errors="replace")
    code = out.channel.recv_exit_status()
    return code, sortie, erreur


def detecter_shell(client: paramiko.SSHClient) -> str:
    """Retourne 'tmsh' si le shell de connexion est tmsh, sinon 'bash'.

    Sous tmsh, 'echo' n'existe pas comme commande shell : la commande échoue.
    Sous bash, elle renvoie la chaîne.
    """
    code, sortie, _err = executer(client, "echo __SHELL_BASH__")
    if code == 0 and "__SHELL_BASH__" in sortie:
        return "bash"
    return "tmsh"


def adapter_commande(shell: str, commande_tmsh: str) -> str:
    """Adapte la commande tmsh selon le shell détecté."""
    if shell == "tmsh":
        return commande_tmsh
    return "tmsh -q {}".format(commande_tmsh)


# ----------------------------------------------------------------------
# Parsing (format field-fmt)
# ----------------------------------------------------------------------
RE_OBJET = re.compile(r"^ltm\s+(virtual|pool|node)\s+(\S+)\s*\{\s*$")
RE_MEMBRE = re.compile(r"^(\S+)\s*\{\s*$")
RE_CHAMP = re.compile(r"^([\w\.\-]+)\s+(.*?)\s*$")


def parser_field_fmt(texte: str) -> Dict[str, Dict[str, Dict[str, str]]]:
    """Parse la sortie field-fmt en {type: {nom: {champ: valeur}}}.

    Pour les pools, les membres sont indexés 'pool::adresse:port'.
    Seuls les champs stables (CHAMPS_STABLES) sont conservés.
    """
    resultat: Dict[str, Dict[str, Dict[str, str]]] = {"virtual": {}, "pool": {}, "node": {}}
    pile: List[str] = []
    type_courant: Optional[str] = None
    nom_courant: Optional[str] = None
    membre_courant: Optional[str] = None

    for brut in texte.splitlines():
        ligne = brut.strip()
        if not ligne:
            continue

        if ligne == "}":
            if pile:
                depile = pile.pop()
                if depile == "membre":
                    membre_courant = None
                elif depile == "objet":
                    type_courant = None
                    nom_courant = None
            continue

        m = RE_OBJET.match(ligne)
        if m and not pile:
            type_courant, nom_courant = m.group(1), m.group(2)
            pile.append("objet")
            resultat[type_courant].setdefault(nom_courant, {})
            continue

        if type_courant is None:
            continue

        if ligne.endswith("{"):
            nom_bloc = ligne[:-1].strip()
            if nom_bloc == "members":
                pile.append("members")
                continue
            if pile and pile[-1] == "members":
                m2 = RE_MEMBRE.match(ligne)
                if m2:
                    membre_courant = m2.group(1)
                    cle = "{}::{}".format(nom_courant, membre_courant)
                    resultat["pool"].setdefault(cle, {})
                    pile.append("membre")
                    continue
            pile.append("autre")
            continue

        mc = RE_CHAMP.match(ligne)
        if mc and mc.group(1) in CHAMPS_STABLES:
            champ, valeur = mc.group(1), mc.group(2)
            if membre_courant is not None:
                cle = "{}::{}".format(nom_courant, membre_courant)
                resultat["pool"][cle][champ] = valeur
            elif nom_courant is not None:
                resultat[type_courant][nom_courant][champ] = valeur

    return resultat


def construire_resume(textes: Dict[str, str]) -> Dict[str, Dict[str, Dict[str, str]]]:
    resume: Dict[str, Dict[str, Dict[str, str]]] = {"virtual": {}, "pool": {}, "node": {}}
    for nom_fichier, texte in textes.items():
        parse = parser_field_fmt(texte)
        for type_obj, objets in parse.items():
            for nom, champs in objets.items():
                if champs:
                    resume[type_obj].setdefault(nom, {}).update(champs)
    return resume


# ----------------------------------------------------------------------
# Capture
# ----------------------------------------------------------------------
def capturer(hote: str, label: str, phase: str,
             utilisateur: str, mot_de_passe: str) -> bool:
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier = SORTIE_RACINE / "{}_{}_{}".format(label, phase, horodatage)
    dossier.mkdir(parents=True, exist_ok=True)

    print("\n=== {} ({}) [{}] ===".format(label, hote, phase))
    debut = time.time()
    meta = {
        "host": hote,
        "label": label,
        "phase": phase,
        "timestamp": horodatage,
        "shell": None,
        "files": {},
        "errors": [],
    }

    try:
        client = connecter(hote, utilisateur, mot_de_passe)
    except Exception as exc:
        print("  [ERREUR] connexion : {}".format(exc))
        meta["errors"].append("connexion: {}".format(exc))
        (dossier / "_meta_state.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        return False

    ok_global = True
    textes: Dict[str, str] = {}
    try:
        shell = detecter_shell(client)
        meta["shell"] = shell
        print("  Shell détecté : {}".format(shell))

        for nom_fichier, cmd_tmsh in COMMANDES_TMSH:
            commande = adapter_commande(shell, cmd_tmsh)
            t0 = time.time()
            try:
                code, sortie, erreur = executer(client, commande)
            except Exception as exc:
                print("  [ERREUR] {} : {}".format(nom_fichier, exc))
                meta["files"][nom_fichier] = {"status": "ERREUR", "detail": str(exc)}
                meta["errors"].append("{}: {}".format(nom_fichier, exc))
                ok_global = False
                continue

            duree = round(time.time() - t0, 2)
            if code != 0 or "error" in sortie.lower()[:200]:
                detail = (erreur or sortie).strip()[:300]
                print("  [ERREUR] {} (code {}) : {}".format(nom_fichier, code, detail))
                meta["files"][nom_fichier] = {
                    "status": "ERREUR", "exit_code": code, "detail": detail}
                meta["errors"].append("{}: code {}".format(nom_fichier, code))
                ok_global = False
                continue

            (dossier / nom_fichier).write_text(sortie, encoding="utf-8")
            textes[nom_fichier] = sortie
            statut = "OK" if sortie.strip() else "VIDE"
            meta["files"][nom_fichier] = {
                "status": statut,
                "bytes": len(sortie.encode("utf-8", errors="replace")),
                "sha256": sha256_texte(sortie),
                "seconds": duree,
                "command": commande,
            }
            print("  [{}] {} ({} octets, {} s)".format(
                statut, nom_fichier, meta["files"][nom_fichier]["bytes"], duree))
            if statut == "VIDE":
                print("      Avertissement : sortie vide (aucun objet ou droits insuffisants).")
    finally:
        client.close()

    resume = construire_resume(textes)
    (dossier / "state_summary.json").write_text(
        json.dumps(resume, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    print("  Résumé : {} VS, {} entrées pool/membre, {} nodes".format(
        len(resume["virtual"]), len(resume["pool"]), len(resume["node"])))

    meta["duration_seconds"] = round(time.time() - debut, 2)
    (dossier / "_meta_state.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print("  Dossier : {}".format(dossier))
    return ok_global


# ----------------------------------------------------------------------
# Programme principal
# ----------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Relevé en lecture seule de l'état runtime BIG-IP (VS, pools, membres, nodes).")
    parser.add_argument("--host", help="adresse de l'équipement")
    parser.add_argument("--label", help="nom court de l'équipement (défaut : l'adresse)")
    parser.add_argument("-f", "--file", help="fichier liste d'équipements")
    parser.add_argument("--phase", choices=("before", "after"), default=None,
                        help="état de la capture ; demandé au lancement si omis")
    parser.add_argument("--user", help="utilisateur SSH (sinon BIGIP_USER ou saisie)")
    args = parser.parse_args()

    if args.file:
        chemin = Path(args.file)
        if not chemin.is_file():
            print("[ERREUR] fichier introuvable : {}".format(chemin))
            return 2
        equipements = lire_equipements(chemin)
    elif args.host:
        equipements = [(args.host, args.label or args.host)]
    else:
        parser.print_help()
        return 2

    if not equipements:
        print("[ERREUR] aucun équipement à traiter.")
        return 2

    # Phase : option ou demande interactive (une seule fois pour tous les équipements)
    if args.phase:
        phase = args.phase
    else:
        try:
            phase = demander_phase()
        except EOFError:
            print("[ERREUR] pas de terminal interactif : utiliser --phase before|after")
            return 2

    utilisateur = args.user or os.environ.get("BIGIP_USER") or input("Utilisateur SSH : ").strip()
    mot_de_passe = os.environ.get("BIGIP_PASSWORD") or getpass.getpass("Mot de passe : ")

    bilan = []
    for hote, label in equipements:
        ok = capturer(hote, label, phase, utilisateur, mot_de_passe)
        bilan.append((label, ok))

    print("\n=== Récapitulatif ({}) ===".format(phase))
    for label, ok in bilan:
        print("  {:<30} {}".format(label, "OK" if ok else "ERREUR"))
    return 0 if all(ok for _l, ok in bilan) else 1


if __name__ == "__main__":
    sys.exit(main())
