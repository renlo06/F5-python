#!/usr/bin/env python3
"""Capture en lecture seule la configuration GTM (DNS) de plusieurs BIG-IP,
et génère une arborescence WideIP -> Pool -> Pool member construite en direct.

Usage :
    python3 capture_gtm.py -f equipements.txt [-o sortie] [--shell auto|bash|tmsh] [--port 22]

Format du fichier d'équipements (une adresse par ligne, '#' pour commenter) :
    10.0.0.10
    10.0.0.11
"""

import argparse
import getpass
import os
import re
import sys
import traceback
from datetime import datetime

import paramiko


COMMANDES_GTM = {
    "gtm_wideip":         "list gtm wideip",
    "gtm_pool":           "list gtm pool",
    "gtm_server":         "list gtm server",
    "gtm_datacenter":     "list gtm datacenter",
    "gtm_monitor":        "list gtm monitor",
    "gtm_prober_pool":    "list gtm prober-pool",
    "gtm_region":         "list gtm region",
    "gtm_topology":       "list gtm topology",
    "gtm_global_setting": "list gtm global-settings",
}


# ---------------------------------------------------------------------------
# Fichier d'équipements et saisie utilisateur
# ---------------------------------------------------------------------------

def lire_equipements(chemin):
    hotes = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            ligne = ligne.strip()
            if ligne and not ligne.startswith("#"):
                hotes.append(ligne)
    return hotes


def demander_etat():
    while True:
        choix = input("Etat de la capture (1 = before, 2 = after) : ").strip()
        if choix == "1":
            return "before"
        if choix == "2":
            return "after"
        print("Saisie invalide, entre 1 ou 2.")


# ---------------------------------------------------------------------------
# Connexion SSH et exécution de commandes
# ---------------------------------------------------------------------------

def connecter(hote, port, utilisateur, mdp):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hote, port=port, username=utilisateur, password=mdp,
                   timeout=20, look_for_keys=False, allow_agent=False)
    return client


def detecter_mode(client):
    """Renvoie 'tmsh' si le shell de login est tmsh, sinon 'bash'."""
    _, stdout, stderr = client.exec_command("tmsh show sys version")
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace")
    if "unexpected argument" in erreur or "unexpected argument" in sortie:
        return "tmsh"
    return "bash"


def executer(client, commande_tmsh, mode):
    """Exécute une commande tmsh (lecture seule) selon le mode.

    En mode 'bash', on préfixe par 'tmsh'. En mode 'tmsh', la commande
    est passée telle quelle au shell tmsh, donc on n'ajoute rien.
    """
    if mode == "bash":
        commande = "tmsh " + commande_tmsh
    else:
        commande = commande_tmsh
    _, stdout, stderr = client.exec_command(commande, timeout=120)
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace")
    if erreur.strip() and not sortie.strip():
        return "[ERREUR] {}\n".format(erreur.strip())
    return sortie


# ---------------------------------------------------------------------------
# Arborescence construite en direct
# ---------------------------------------------------------------------------

def noms_objets(sortie, type_objet):
    """Extrait les noms d'objets depuis une sortie 'list gtm <type>'."""
    noms = []
    for ligne in sortie.splitlines():
        ligne = ligne.strip()
        if ligne.endswith("{") and type_objet in ligne.split():
            mots = ligne[:-1].split()
            idx = mots.index(type_objet)
            if idx + 1 < len(mots):
                noms.append(mots[idx + 1])
    return noms


def noms_dans_bloc(sortie, mot_cle):
    """Renvoie les noms listés juste sous un bloc 'pools {' ou 'members {'."""
    noms = []
    dans_bloc = False
    profondeur = 0
    for ligne in sortie.splitlines():
        brut = ligne.strip()
        if not dans_bloc:
            if brut.startswith(mot_cle) and brut.endswith("{"):
                dans_bloc = True
                profondeur = 1
            continue
        if brut.endswith("{"):
            profondeur += 1
            continue
        if brut == "}":
            profondeur -= 1
            if profondeur <= 0:
                break
            continue
        if profondeur == 1 and brut:
            nom = brut.split()[0]
            if nom not in ("}", "{"):
                noms.append(nom)
    return noms


def arborescence_en_direct(client, mode):
    lignes = ["ARBORESCENCE GTM : WideIP -> Pool -> Pool member", "=" * 60, ""]

    sortie_wideip = executer(client, "list gtm wideip", mode)
    wideips = noms_objets(sortie_wideip, "wideip")

    if not wideips:
        lignes.append("Aucun WideIP trouvé. Sortie reçue :")
        lignes.append(sortie_wideip[:500])
        return "\n".join(lignes) + "\n"

    for wip in sorted(wideips):
        lignes.append("WideIP : {}".format(wip))
        sortie_wip = executer(client, "list gtm wideip {}".format(wip), mode)
        noms_pools = noms_dans_bloc(sortie_wip, "pools")

        if not noms_pools:
            lignes.append("  └── (aucun pool référencé)")
            lignes.append("")
            continue

        for i, pool in enumerate(noms_pools):
            dernier = (i == len(noms_pools) - 1)
            lignes.append("  {}Pool : {}".format("└── " if dernier else "├── ", pool))
            pref = "    " if dernier else "│   "

            sortie_pool = executer(client, "list gtm pool {}".format(pool), mode)
            membres = noms_dans_bloc(sortie_pool, "members")
            if not membres:
                lignes.append("  {}└── (aucun pool member)".format(pref))
                continue
            for j, m in enumerate(membres):
                lignes.append("  {}{}Pool member : {}".format(
                    pref, "└── " if j == len(membres) - 1 else "├── ", m))
        lignes.append("")

    return "\n".join(lignes) + "\n"


# ---------------------------------------------------------------------------
# Capture d'un équipement
# ---------------------------------------------------------------------------

def capturer_equipement(hote, args, utilisateur, mdp, etat, horodatage):
    dossier = os.path.join(args.sortie, "{}_{}".format(hote, horodatage))
    os.makedirs(dossier, exist_ok=True)
    print("\n[*] {} : connexion...".format(hote))

    client = connecter(hote, args.port, utilisateur, mdp)
    try:
        if args.shell == "auto":
            mode = detecter_mode(client)
        else:
            mode = args.shell
        print("[*] {} : mode détecté : {}".format(hote, mode))

        sorties = {}
        for nom_fichier, commande in COMMANDES_GTM.items():
            sortie = executer(client, commande, mode)
            sorties[nom_fichier] = sortie
            chemin = os.path.join(dossier, "{}_{}.txt".format(nom_fichier, etat))
            with open(chemin, "w", encoding="utf-8") as f:
                f.write("# Commande : tmsh {}\n# Mode : {}\n\n".format(commande, mode))
                f.write(sortie)
            print("[*] {} : {} -> {} ({} octets)".format(
                hote, commande, os.path.basename(chemin), len(sortie)))

        chemin_arbo = os.path.join(dossier, "arborescence_gtm_{}.txt".format(etat))
        with open(chemin_arbo, "w", encoding="utf-8") as f:
            f.write(arborescence_en_direct(client, mode))
        print("[*] {} : arborescence écrite dans {}".format(
            hote, os.path.basename(chemin_arbo)))
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Capture GTM en lecture seule")
    parser.add_argument("-f", "--fichier", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--shell", choices=["auto", "bash", "tmsh"], default="auto")
    parser.add_argument("-o", "--sortie", default="capture_gtm")
    args = parser.parse_args()

    try:
        hotes = lire_equipements(args.fichier)
    except OSError as e:
        print("[!] Lecture du fichier impossible : {}".format(e), file=sys.stderr)
        sys.exit(1)

    if not hotes:
        print("[!] Aucun équipement trouvé dans {}".format(args.fichier), file=sys.stderr)
        sys.exit(1)

    utilisateur = input("Utilisateur : ").strip()
    mdp = getpass.getpass("Mot de passe : ")
    etat = demander_etat()
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")

    print("[*] {} équipement(s), sortie dans : {}".format(
        len(hotes), os.path.abspath(args.sortie)))

    echecs = []
    for hote in hotes:
        try:
            capturer_equipement(hote, args, utilisateur, mdp, etat, horodatage)
        except Exception as e:
            print("[!] {} : erreur : {}".format(hote, e), file=sys.stderr)
            traceback.print_exc()
            echecs.append(hote)

    print("\n[*] Terminé ({}) : {} réussi(s), {} échec(s)".format(
        etat, len(hotes) - len(echecs), len(echecs)))
    if echecs:
        print("[!] Échecs : {}".format(", ".join(echecs)))
        sys.exit(2)


if __name__ == "__main__":
    main()
