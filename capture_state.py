#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capture de l'état runtime de BIG-IP (avant / après une intervention).

Relève, pour TOUTES les partitions :
    - virtual servers
    - pools et membres
    - nodes

Produit dans captures/<label>_<phase>_<horodatage>/ :
    state_virtual.txt, state_pool.txt, state_node.txt   (sorties brutes tmsh)
    state_summary.json                                  (données structurées)

Usage:
    python capture_state.py -f hosts.txt
    python capture_state.py -f hosts.txt --phase before -u admin
    python capture_state.py --host 10.0.0.1 --label bigip-a
    python capture_state.py                      (tout en interactif)

Fichier d'équipements (-f), une ligne par équipement, # = commentaire :
    10.0.0.1                         (IP seule : le label = l'IP)
    bigip-a;10.0.0.1                 (label;host)
    bigip-a;10.0.0.1;admin           (label;host;user)
    bigip-a;10.0.0.1;admin;2222      (label;host;user;port)

Les lignes sans user utilisent l'utilisateur global (-u ou saisi).
Si --phase est absent, l'état (before / after) est demandé.
Le mot de passe est demandé une fois (ou variable BIGIP_PASSWORD).

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
from typing import Dict, List, Optional, Tuple

import paramiko

REPERTOIRE_CAPTURES = "captures"
TIMEOUT_SSH = 30
TIMEOUT_COMMANDE = 120
PORT_DEFAUT = 22

# /*/* = toutes les partitions (sans cela, seule /Common est retournée)
COMMANDES_TMSH = [
    ("state_virtual.txt", "show ltm virtual /*/* field-fmt"),
    ("state_pool.txt",    "show ltm pool /*/* members field-fmt"),
    ("state_node.txt",    "show ltm node /*/* field-fmt"),
]

# (label, host, user ou None, port)
Equipement = Tuple[str, str, Optional[str], int]


# ------------------------------------------------------- Saisie interactive

def demander_phase() -> str:
    """Demande l'état de la capture : before ou after."""
    print("Quel est l'état de cette capture ?")
    print("  1) before (avant l'intervention)")
    print("  2) after  (après l'intervention)")
    while True:
        choix = input("Choix [1/2 ou before/after] : ").strip().lower()
        if choix in ("1", "before", "b", "avant"):
            return "before"
        if choix in ("2", "after", "a", "apres", "après"):
            return "after"
        print("Réponse invalide, tape 1, 2, before ou after.")


def demander_equipement_unique() -> List[Equipement]:
    """Demande un équipement à la main (aucun fichier ni argument fourni)."""
    label = input("Nom de l'équipement (label) : ").strip()
    host = input("Adresse IP ou nom d'hôte : ").strip()
    if not host:
        print("L'hôte est obligatoire.")
        sys.exit(2)
    port_saisi = input("Port SSH [{}] : ".format(PORT_DEFAUT)).strip()
    port = int(port_saisi) if port_saisi else PORT_DEFAUT
    return [(label or host, host, None, port)]


# ------------------------------------------------------- Fichier d'hôtes

def lire_fichier_hosts(chemin: str) -> List[Equipement]:
    """Lit le fichier d'équipements.

    Formats acceptés (séparateur ';') :
        host
        label;host
        label;host;user
        label;host;user;port
    Les lignes vides et les commentaires (#) sont ignorés. Les doublons
    (même host + port) sont supprimés."""
    fichier = Path(chemin)
    if not fichier.is_file():
        print("Fichier introuvable : {}".format(chemin))
        sys.exit(2)

    equipements: List[Equipement] = []
    vus = set()
    for numero, ligne in enumerate(fichier.read_text(encoding="utf-8").splitlines(), 1):
        ligne = ligne.split("#", 1)[0].strip()
        if not ligne:
            continue
        champs = [c.strip() for c in ligne.split(";")]

        if len(champs) == 1:
            label, host, user, port_txt = champs[0], champs[0], "", ""
        elif len(champs) == 2:
            label, host, user, port_txt = champs[0], champs[1], "", ""
        else:
            label, host, user = champs[0], champs[1], champs[2]
            port_txt = champs[3] if len(champs) > 3 else ""

        if not host:
            print("Ligne {} ignorée (hôte vide) : {}".format(numero, ligne))
            continue
        try:
            port = int(port_txt) if port_txt else PORT_DEFAUT
        except ValueError:
            print("Ligne {} ignorée (port invalide) : {}".format(numero, ligne))
            continue

        cle = (host, port)
        if cle in vus:
            print("Ligne {} ignorée (doublon) : {}".format(numero, host))
            continue
        vus.add(cle)
        equipements.append((label or host, host, user or None, port))
    return equipements


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
    Un bloc commence par '<prefixe> <nom> {' et se termine par '}' au
    niveau 0. Gère les sous-blocs imbriqués."""
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
    nom_sain = re.sub(r"[^\w.\-]", "_", label)
    dossier = racine / "{}_{}_{}".format(nom_sain, phase, horodatage)
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
    hors_common = sum(1 for n in virtuals if not n.startswith("/Common/"))
    print("  Dont {} virtual(s) hors /Common".format(hors_common))
    return dossier


# ------------------------------------------------------------- Entrée

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture de l'état runtime BIG-IP (multi-équipements).")
    parser.add_argument("-f", "--fichier",
                        help="fichier d'équipements (label;host[;user[;port]])")
    parser.add_argument("--phase", choices=["before", "after"],
                        help="état de la capture (demandé si absent)")
    parser.add_argument("-u", "--user",
                        help="utilisateur par défaut (demandé si absent)")
    parser.add_argument("--host", help="équipement unique (sans fichier)")
    parser.add_argument("--label", help="label de l'équipement unique")
    parser.add_argument("--port", type=int, default=PORT_DEFAUT)
    parser.add_argument("--captures", default=REPERTOIRE_CAPTURES)
    args = parser.parse_args()

    # 1) État before / after
    phase = args.phase or demander_phase()

    # 2) Équipements : fichier, arguments, ou saisie interactive
    if args.fichier:
        equipements = lire_fichier_hosts(args.fichier)
    elif args.host:
        equipements = [(args.label or args.host, args.host, None, args.port)]
    else:
        equipements = demander_equipement_unique()

    if not equipements:
        print("Aucun équipement à traiter.")
        return 2

    # 3) Identifiants : utilisateur par défaut + mot de passe unique
    user_defaut = args.user or input("Utilisateur par défaut [admin] : ").strip() or "admin"
    password = os.environ.get("BIGIP_PASSWORD") or getpass.getpass("Mot de passe : ")

    print("\nPhase : {} | {} équipement(s)".format(phase.upper(), len(equipements)))

    racine = Path(args.captures)
    racine.mkdir(parents=True, exist_ok=True)

    ok, erreurs = 0, []
    for label, host, user, port in equipements:
        utilisateur = user or user_defaut
        print("\n=== {} ({}:{}) - {} - phase {} ===".format(
            label, host, port, utilisateur, phase))
        try:
            dossier = capturer_equipement(label, host, port, utilisateur,
                                          password, phase, racine)
            print("  -> {}".format(dossier))
            ok += 1
        except Exception as exc:  # noqa: BLE001
            erreurs.append((label, str(exc)))
            print("  [ERREUR] {}".format(exc))

    # 4) Bilan
    print("\n==== Bilan : {} OK, {} en erreur ====".format(ok, len(erreurs)))
    for label, message in erreurs:
        print("  - {} : {}".format(label, message))

    return 1 if erreurs else 0


if __name__ == "__main__":
    sys.exit(main())
