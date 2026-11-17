#!/usr/bin/env python3
"""Capture en lecture seule la configuration GTM (DNS) de plusieurs BIG-IP,
et génère une arborescence WideIP -> Pool -> Pool member.

Usage :
    python3 capture_gtm.py -f equipements.txt [-o sortie] [--shell auto|bash|tmsh] [--port 22]

Le script demande :
    - l'utilisateur et le mot de passe
    - l'état de la capture : 1 = before, 2 = after

Format du fichier d'équipements (une adresse par ligne) :
    # commentaire
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


# Commandes GTM en lecture seule : nom du fichier de sortie -> commande tmsh
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
# Lecture du fichier d'équipements et saisie utilisateur
# ---------------------------------------------------------------------------

def lire_equipements(chemin):
    """Lit le fichier d'équipements et renvoie la liste des hôtes."""
    hotes = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne or ligne.startswith("#"):
                continue
            hotes.append(ligne)
    return hotes


def demander_etat():
    """Demande à l'utilisateur l'état de la capture (before ou after)."""
    while True:
        choix = input("État de la capture : 1) before  2) after  [1/2] : ").strip()
        if choix == "1":
            return "before"
        if choix == "2":
            return "after"
        print("Réponse invalide, saisir 1 ou 2.")


# ---------------------------------------------------------------------------
# Connexion SSH et exécution des commandes
# ---------------------------------------------------------------------------

def ouvrir_connexion(hote, port, utilisateur, mdp):
    """Ouvre une connexion SSH vers l'équipement."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=hote,
        port=port,
        username=utilisateur,
        password=mdp,
        look_for_keys=False,
        allow_agent=False,
        timeout=30,
    )
    return client


def executer(client, commande, shell_mode):
    """Exécute une commande tmsh en lecture seule et renvoie sa sortie.

    shell_mode :
      - "tmsh" : la session ouvre directement tmsh, on envoie la commande seule
      - "bash" ou "auto" : appel explicite via tmsh
    """
    if shell_mode == "tmsh":
        cmd = commande
    else:
        cmd = "tmsh {}".format(commande)

    _, stdout, stderr = client.exec_command(cmd, timeout=120)
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace")

    if not sortie.strip() and erreur.strip():
        return "ERREUR : {}".format(erreur.strip())
    return sortie


# ---------------------------------------------------------------------------
# Parsing de la sortie tmsh (accolades imbriquées)
# ---------------------------------------------------------------------------

RE_OBJET = re.compile(
    r"^[ \t]*(?:ltm\s+|gtm\s+)?(wideip|pool|server)\s+(\S+)\s*\{",
    re.MULTILINE,
)


def _bloc(texte, pos_accolade):
    """Renvoie le contenu entre l'accolade ouvrante à pos_accolade et son fermant."""
    profondeur = 0
    for i in range(pos_accolade, len(texte)):
        c = texte[i]
        if c == "{":
            profondeur += 1
        elif c == "}":
            profondeur -= 1
            if profondeur == 0:
                return texte[pos_accolade + 1:i]
    return texte[pos_accolade + 1:]


def parser_objets(texte, type_attendu):
    """Renvoie {nom: bloc_texte} pour les objets d'un type donné."""
    objets = {}
    for m in RE_OBJET.finditer(texte):
        if m.group(1) == type_attendu:
            objets[m.group(2)] = _bloc(texte, m.end() - 1)
    return objets


def pools_du_wideip(bloc_wideip):
    """Renvoie la liste des noms de pools référencés dans un WideIP."""
    m = re.search(r"^\s*pools\s*\{", bloc_wideip, re.MULTILINE)
    if not m:
        return []
    contenu = _bloc(bloc_wideip, m.end() - 1)
    return [x.group(1) for x in re.finditer(
        r"^\s*(/?\S+)\s*\{", contenu, re.MULTILINE)]


def membres_du_pool(bloc_pool):
    """Renvoie la liste des membres (serveur:service) d'un pool."""
    m = re.search(r"^\s*members\s*\{", bloc_pool, re.MULTILINE)
    if not m:
        return []
    contenu = _bloc(bloc_pool, m.end() - 1)
    return [x.group(1) for x in re.finditer(
        r"^\s*(/?[^\s{}:]+:[^\s{}]+)\s*\{", contenu, re.MULTILINE)]


def construire_arborescence(sortie_wideip, sortie_pool):
    """Construit le texte de l'arborescence WideIP -> Pool -> Pool member."""
    lignes = []
    lignes.append("ARBORESCENCE GTM : WideIP -> Pool -> Pool member")
    lignes.append("=" * 60)

    wideips = parser_objets(sortie_wideip, "wideip")
    pools = parser_objets(sortie_pool, "pool")

    lignes.append("(diagnostic : {} caractère(s) en entrée wideip, {} en entrée pool, "
                  "{} WideIP et {} pool analysé(s))".format(
                      len(sortie_wideip), len(sortie_pool), len(wideips), len(pools)))
    lignes.append("")

    if not wideips:
        lignes.append("Aucun WideIP trouvé. Voir gtm_wideip_<etat>.txt.")
        return "\n".join(lignes) + "\n"

    for nom_wideip, bloc_wideip in sorted(wideips.items()):
        lignes.append("WideIP : {}".format(nom_wideip))
        noms_pools = pools_du_wideip(bloc_wideip)
        if not noms_pools:
            lignes.append("  └── (aucun pool référencé)")
            lignes.append("")
            continue

        for i, nom_pool in enumerate(noms_pools):
            dernier_pool = (i == len(noms_pools) - 1)
            branche = "└── " if dernier_pool else "├── "
            prefixe_pool = "    " if dernier_pool else "│   "
            lignes.append("  {}Pool : {}".format(branche, nom_pool))

            bloc_pool = pools.get(nom_pool)
            if bloc_pool is None:
                lignes.append("  {}  └── (pool non trouvé dans la capture)".format(prefixe_pool))
                continue

            membres = membres_du_pool(bloc_pool)
            if not membres:
                lignes.append("  {}  └── (aucun pool member)".format(prefixe_pool))
                continue

            for j, membre in enumerate(membres):
                dernier_membre = (j == len(membres) - 1)
                branche_m = "└── " if dernier_membre else "├── "
                lignes.append("  {}  {}Pool member : {}".format(
                    prefixe_pool, branche_m, membre))
        lignes.append("")

    return "\n".join(lignes) + "\n"


# ---------------------------------------------------------------------------
# Capture d'un équipement
# ---------------------------------------------------------------------------

def capturer_equipement(hote, args, utilisateur, mdp, etat, horodatage):
    """Capture toutes les commandes GTM d'un équipement et écrit les fichiers."""
    dossier = os.path.join(args.sortie, hote)
    os.makedirs(dossier, exist_ok=True)

    print("[*] {} : connexion...".format(hote))
    client = ouvrir_connexion(hote, args.port, utilisateur, mdp)

    sorties = {}
    try:
        for nom_fichier, commande in COMMANDES_GTM.items():
            print("    - {}".format(commande))
            sortie = executer(client, commande, args.shell)
            sorties[nom_fichier] = sortie
            chemin = os.path.join(dossier, "{}_{}.txt".format(nom_fichier, etat))
            with open(chemin, "w", encoding="utf-8") as f:
                f.write("# {} | {} | {} | {}\n\n".format(
                    hote, commande, etat, horodatage))
                f.write(sortie)
    finally:
        client.close()

    chemin_arbo = os.path.join(dossier, "arborescence_gtm_{}.txt".format(etat))
    with open(chemin_arbo, "w", encoding="utf-8") as f:
        f.write(construire_arborescence(
            sorties.get("gtm_wideip", ""),
            sorties.get("gtm_pool", "")))
    print("[*] {} : arborescence écrite dans {}".format(hote, os.path.basename(chemin_arbo)))


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Capture GTM en lecture seule")
    parser.add_argument("-f", "--fichier", required=True,
                        help="fichier contenant la liste des équipements")
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

    print("[*] {} équipement(s) à traiter, sortie dans : {}".format(
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
