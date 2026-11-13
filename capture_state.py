#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capture de l'état runtime d'un BIG-IP (avant / après une intervention).

Relève, pour TOUTES les partitions :
    - virtual servers
    - pools et membres
    - nodes

Produit dans captures/<label>_<phase>_<horodatage>/ :
    state_virtual.txt, state_pool.txt, state_node.txt   (sorties brutes tmsh)
    state_summary.json                                  (données structurées)

Usage:
    python capture_state.py --host 10.0.0.1 --label bigip-a --phase before
    python capture_state.py -f equipements.txt --phase after

Format du fichier -f (une ligne par équipement, # = commentaire) :
    label;host;utilisateur[;port]

Le mot de passe est demandé une fois (ou variable d'environnement BIGIP_PASSWORD).

Dépendance : paramiko  (pip install paramiko)
"""

import argparse
import getpass
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import paramiko

REPERTOIRE_CAPTURES = "captures"
TIMEOUT_SSH = 30
TIMEOUT_COMMANDE = 120

# /*/* = toutes les partitions (sans cela, seule /Common est retournée)
COMMANDES_TMSH = [
    ("state_virtual.txt", "show ltm virtual /*/* field-fmt"),
    ("state_pool.txt",    "show ltm pool /*/* members field-fmt"),
    ("state_node.txt",    "show ltm node /*/* field-fmt"),
]


# ---------------------------------------------------------------- SSH

def executer_tmsh(client: paramiko.SSHClient, commande: str) -> str:
    """Exécute une commande tmsh. Passe par 'tmsh -c' pour être indépendant
    du shell de connexion (bash ou tmsh)."""
    cmd = "tmsh -c '{}'".format(commande.replace("'", "'\\''"))
    _, stdout, stderr = client.exec_command(cmd, timeout=TIMEOUT_COMMANDE)
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace")
    if not sortie.strip() and erreur.strip():
        raise RuntimeError("tmsh : {}".format(erreur.strip()))
    return sortie


def connecter(host: str, port: int, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password,
                   timeout=TIMEOUT_SSH, look_for_keys=False, allow_agent=False)
    return client


# ------------------------------------------------------------- Parseurs

def decouper_blocs(texte: str, prefixe: str) -> List[List[str]]:
    """Découpe une sortie 'field-fmt' en blocs, un par objet.
    Un bloc commence par une ligne '<prefixe> <nom>' (ex. 'ltm virtual /Common/vs')
    et se termine par '}' au niveau 0. Gère les sous-blocs imbriqués."""
    blocs, courant, profondeur = [], None, 0
    for ligne in texte.splitlines():
        brut = ligne.strip()
        if courant is None:
            if brut.startswith(prefixe + " ") and brut.endswith("{"):
                courant = [brut]
                profondeur = 1
            continue
        courant.append(brut)
        profondeur += brut.count("{") - brut.count("}")
        if profondeur <= 0:
            blocs.append(courant)
            courant, profondeur = None, 0
    return blocs


def nom_du_bloc(bloc: List[str], prefixe: str) -> str:
    entete = bloc[0][len(prefixe):].strip()
    return entete.rstrip("{").strip()


def valeur(bloc: List[str], cle: str) -> Optional[str]:
    """Première valeur d'une clé simple 'cle valeur' dans le bloc."""
    motif = re.compile(r"^{}\s+(.+)$".format(re.escape(cle)))
    for ligne in bloc:
        m = motif.match(ligne)
        if m:
            return m.group(1).strip()
    return None


def extraire_statut(bloc: List[str]) -> Dict[str, Optional[str]]:
    return {
        "disponibilite": valeur(bloc, "status.availability-state"),
        "etat": valeur(bloc, "status.enabled-state"),
        "raison": valeur(bloc, "status.status-reason"),
    }


def parser_virtuals(texte: str) -> Dict[str, dict]:
    resultat = {}
    for bloc in decouper_blocs(texte, "ltm virtual"):
        nom = nom_du_bloc(bloc, "ltm virtual")
        entree = extraire_statut(bloc)
        entree["destination"] = valeur(bloc, "destination")
        resultat[nom] = entree
    return resultat


def parser_nodes(texte: str) -> Dict[str, dict]:
    resultat = {}
    for bloc in decouper_blocs(texte, "ltm node"):
        nom = nom_du_bloc(bloc, "ltm node")
        entree = extraire_statut(bloc)
        entree["adresse"] = valeur(bloc, "addr")
        resultat[nom] = entree
    return resultat


def parser_pools(texte: str):
    """Retourne (pools, membres).
    pools   : {nom_pool: {disponibilite, etat}}
    membres : {'nom_pool / adresse:port': {disponibilite, etat, raison}}"""
    pools, membres = {}, {}
    for bloc in decouper_blocs(texte, "ltm pool"):
        nom_pool = nom_du_bloc(bloc, "ltm pool")
        pools[nom_pool] = extraire_statut(bloc)
        pools[nom_pool].pop("raison", None)

        # Membres : sous-blocs 'members { <nom> { ... } }'
        dans_membres, profondeur_membres = False, 0
        membre_nom, membre_lignes, profondeur_membre = None, [], 0
        for ligne in bloc[1:]:
            if not dans_membres:
                if ligne.startswith("members") and ligne.endswith("{"):
                    dans_membres, profondeur_membres = True, 1
                continue
            if membre_nom is None:
                if ligne.endswith("{") and not ligne.startswith("}"):
                    membre_nom = ligne.rstrip("{").strip()
                    membre_lignes, profondeur_membre = [], 1
                else:
                    profondeur_membres += ligne.count("{") - ligne.count("}")
                    if profondeur_membres <= 0:
                        dans_membres = False
                continue
            membre_lignes.append(ligne)
            profondeur_membre += ligne.count("{") - ligne.count("}")
            if profondeur_membre <= 0:
                cle = "{} / {}".format(nom_pool, membre_nom)
                membres[cle] = extraire_statut(membre_lignes)
                membre_nom = None
    return pools, membres


# ----------------------------------------------------------- Capture

def capturer_equipement(label: str, host: str, port: int, user: str,
                        password: str, phase: str, racine: Path) -> Path:
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier = racine / "{}_{}_{}".format(label, phase, horodatage)
    dossier.mkdir(parents=True, exist_ok=True)

    client = connecter(host, port, user, password)
    try:
        sorties = {}
        for fichier, commande in COMMANDES_TMSH:
            texte = executer_tmsh(client, commande)
            (dossier / fichier).write_text(texte, encoding="utf-8")
            sorties[fichier] = texte
            print("  [OK] {:<20} {} octets".format(fichier, len(texte)))
    finally:
        client.close()

    virtuals = parser_virtuals(sorties["state_virtual.txt"])
    pools, membres = parser_pools(sorties["state_pool.txt"])
    nodes = parser_nodes(sorties["state_node.txt"])

    resume = {
        "label": label,
        "host": host,
        "phase": phase,
        "horodatage": horodatage,
        "ltm_virtual": virtuals,
        "ltm_pool": pools,
        "ltm_pool_member": membres,
        "ltm_node": nodes,
    }
    (dossier / "state_summary.json").write_text(
        json.dumps(resume, indent=2, ensure_ascii=False), encoding="utf-8")

    print("  Résumé : {} virtual(s), {} pool(s), {} membre(s), {} node(s)".format(
        len(virtuals), len(pools), len(membres), len(nodes)))

    # Contrôle : combien d'objets hors /Common ?
    hors_common = sum(1 for n in virtuals if not n.startswith("/Common/"))
    print("  Dont {} virtual(s) hors /Common".format(hors_common))
    return dossier


# ------------------------------------------------------------- Entrée

def lire_fichier_equipements(chemin: str):
    equipements = []
    for numero, ligne in enumerate(Path(chemin).read_text(encoding="utf-8").splitlines(), 1):
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#"):
            continue
        champs = [c.strip() for c in ligne.split(";")]
        if len(champs) < 3:
            print("Ligne {} ignorée (format label;host;user[;port]) : {}".format(numero, ligne))
            continue
        port = int(champs[3]) if len(champs) > 3 and champs[3] else 22
        equipements.append((champs[0], champs[1], champs[2], port))
    return equipements


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture de l'état runtime BIG-IP.")
    parser.add_argument("--phase", required=True, choices=["before", "after"])
    parser.add_argument("--host")
    parser.add_argument("--label")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("-f", "--fichier", help="fichier d'équipements (label;host;user[;port])")
    parser.add_argument("--captures", default=REPERTOIRE_CAPTURES)
    args = parser.parse_args()

    if args.fichier:
        equipements = lire_fichier_equipements(args.fichier)
    elif args.host and args.label:
        equipements = [(args.label, args.host, args.user, args.port)]
    else:
        parser.error("Fournir --host et --label, ou -f fichier.")

    if not equipements:
        print("Aucun équipement à traiter.")
        return 2

    password = os.environ.get("BIGIP_PASSWORD") or getpass.getpass("Mot de passe : ")
    racine = Path(args.captures)
    racine.mkdir(parents=True, exist_ok=True)

    erreurs = 0
    for label, host, user, port in equipements:
        print("=== {} ({}) - phase {} ===".format(label, host, args.phase))
        try:
            dossier = capturer_equipement(label, host, port, user, password,
                                          args.phase, racine)
            print("  -> {}".format(dossier))
        except Exception as exc:  # noqa: BLE001
            erreurs += 1
            print("  [ERREUR] {}".format(exc))

    return 1 if erreurs else 0


if __name__ == "__main__":
    sys.exit(main())
