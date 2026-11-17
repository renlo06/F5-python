#!/usr/bin/env python3
"""Capture en lecture seule la configuration GTM (DNS) de plusieurs BIG-IP,
et génère une arborescence WideIP -> Pool -> Pool member.

Usage :
    python3 capture_gtm.py -f equipements.txt [-o sortie] [--shell auto|bash|tmsh] [--port 22]
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
        choix = input("État de la capture : 1) before  2) after  [1/2] : ").strip()
        if choix == "1":
            return "before"
        if choix == "2":
            return "after"
        print("Réponse invalide, saisir 1 ou 2.")


# ---------------------------------------------------------------------------
# Connexion SSH et exécution
# ---------------------------------------------------------------------------

def ouvrir_connexion(hote, port, utilisateur, mdp):
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


def _lancer(client, cmd):
    """Lance une commande et renvoie (sortie, erreur, code_retour)."""
    _, stdout, stderr = client.exec_command(cmd, timeout=120)
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return sortie, erreur, code


def detecter_mode(client):
    """En mode auto, détermine si la session répond à 'tmsh' explicite ou non."""
    sortie, erreur, code = _lancer(client, "tmsh list sys version")
    if code == 0 and sortie.strip():
        return "bash"
    sortie, erreur, code = _lancer(client, "list sys version")
    if code == 0 and sortie.strip():
        return "tmsh"
    return "bash"


def executer(client, commande, mode):
    """Exécute une commande GTM. Renvoie un texte complet, avec erreur si besoin."""
    cmd = commande if mode == "tmsh" else "tmsh {}".format(commande)
    sortie, erreur, code = _lancer(client, cmd)
    if code != 0 or (not sortie.strip() and erreur.strip()):
        return ("# ERREUR (code {}) pour la commande : {}\n# {}\n"
                .format(code, cmd, erreur.strip() or "(pas de message d'erreur)")
                + sortie)
    return sortie


# ---------------------------------------------------------------------------
# Parsing tolérant de la sortie tmsh
# ---------------------------------------------------------------------------

def _bloc(texte, pos_accolade):
    """Contenu entre l'accolade ouvrante à pos_accolade et sa fermante."""
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


def _lignes_blocs_niveau1(texte):
    """Renvoie (entête, contenu) pour chaque bloc de premier niveau.

    Un bloc est une ligne 'entête {' suivie de son contenu jusqu'à l'accolade
    fermante correspondante. Ne dépend ni du préfixe ltm/gtm ni de l'indentation.
    """
    resultats = []
    pos = 0
    while True:
        i = texte.find("{", pos)
        if i == -1:
            break
        debut_ligne = texte.rfind("\n", 0, i) + 1
        entete = texte[debut_ligne:i].strip()
        bloc = _bloc(texte, i)
        resultats.append((entete, bloc))
        # on continue après le bloc entier pour ne lire que le niveau 1
        pos = i + len(bloc) + 2
    return resultats


def parser_objets(texte, type_attendu):
    """Renvoie {nom: bloc} pour les objets 'type_attendu nom {' de premier niveau."""
    objets = {}
    for entete, bloc in _lignes_blocs_niveau1(texte):
        mots = entete.split()
        if len(mots) >= 2 and type_attendu in mots[:-1]:
            # ex: 'gtm wideip www.example.com' ou 'wideip www.example.com'
            idx = mots.index(type_attendu)
            if idx + 1 < len(mots):
                objets[mots[idx + 1]] = bloc
    return objets


def sous_bloc(bloc, mot_cle):
    """Renvoie le contenu du sous-bloc 'mot_cle {' dans bloc, ou None."""
    for entete, contenu in _lignes_blocs_niveau1_ou_profonds(bloc):
        if entete.split() and entete.split()[-1] == mot_cle:
            return contenu
    return None


def _lignes_blocs_niveau1_ou_profonds(texte):
    """Tous les blocs 'entête {' du texte, y compris imbriqués."""
    resultats = []
    for m in re.finditer(r"([^\n{}]*)\{", texte):
        entete = m.group(1).strip()
        contenu = _bloc(texte, m.end() - 1)
        resultats.append((entete, contenu))
    return resultats


def entrees_sous_bloc(bloc_sous, ):
    """Renvoie les noms d'entrées d'un sous-bloc (un nom par ligne, suivi de '{' ou non).

    Gère 'nom {', 'nom { ratio 1 }', 'nom' seul sur une ligne, et 'nom:port'.
    """
    noms = []
    for ligne in bloc_sous.splitlines():
        ligne = ligne.strip()
        if not ligne or ligne in ("{", "}"):
            continue
        m = re.match(r"^(/?[^\s{}]+)", ligne)
        if m and m.group(1) not in ("ratio", "order", "priority", "member-order"):
            noms.append(m.group(1))
    return noms


def pools_du_wideip(bloc_wideip):
    sous = sous_bloc(bloc_wideip, "pools")
    return entrees_sous_bloc(sous) if sous else []


def membres_du_pool(bloc_pool):
    sous = sous_bloc(bloc_pool, "members")
    return entrees_sous_bloc(sous) if sous else []


def construire_arborescence(sortie_wideip, sortie_pool):
    lignes = []
    lignes.append("ARBORESCENCE GTM : WideIP -> Pool -> Pool member")
    lignes.append("=" * 60)

    wideips = parser_objets(sortie_wideip, "wideip")
    pools = parser_objets(sortie_pool, "pool")

    lignes.append("(diagnostic : {} caractère(s) wideip, {} caractère(s) pool, "
                  "{} WideIP et {} pool analysé(s))".format(
                      len(sortie_wideip), len(sortie_pool), len(wideips), len(pools)))
    lignes.append("")

    if not wideips:
        lignes.append("Aucun WideIP analysé. Voir gtm_wideip_<etat>.txt.")
        return "\n".join(lignes) + "\n"

    for nom_wideip in sorted(wideips):
        lignes.append("WideIP : {}".format(nom_wideip))
        noms_pools = pools_du_wideip(wideips[nom_wideip])
        if not noms_pools:
            lignes.append("  └── (aucun pool référencé)")
            lignes.append("")
            continue

        for i, nom_pool in enumerate(noms_pools):
            dernier = (i == len(noms_pools) - 1)
            branche = "└── " if dernier else "├── "
            pref = "    " if dernier else "│   "
            lignes.append("  {}Pool : {}".format(branche, nom_pool))

            bloc_pool = pools.get(nom_pool)
            if bloc_pool is None:
                lignes.append("  {}└── (pool non trouvé dans la capture)".format(pref))
                continue

            membres = membres_du_pool(bloc_pool)
            if not membres:
                lignes.append("  {}└── (aucun pool member)".format(pref))
                continue

            for j, membre in enumerate(membres):
                dm = (j == len(membres) - 1)
                lignes.append("  {}{}Pool member : {}".format(
                    pref, "└── " if dm else "├── ", membre))
        lignes.append("")

    return "\n".join(lignes) + "\n"


# ---------------------------------------------------------------------------
# Capture d'un équipement
# ---------------------------------------------------------------------------

def capturer_equipement(hote, args, utilisateur, mdp, etat, horodatage):
    dossier = os.path.join(args.sortie, hote)
    os.makedirs(dossier, exist_ok=True)

    print("[*] {} : connexion...".format(hote))
    client = ouvrir_connexion(hote, args.port, utilisateur, mdp)

    try:
        mode = args.shell if args.shell != "auto" else detecter_mode(client)
        print("    mode utilisé : {}".format(mode))

        sorties = {}
        for nom_fichier, commande in COMMANDES_GTM.items():
            print("    - {}".format(commande))
            sortie = executer(client, commande, mode)
            sorties[nom_fichier] = sortie
            chemin = os.path.join(dossier, "{}_{}.txt".format(nom_fichier, etat))
            with open(chemin, "w", encoding="utf-8") as f:
                f.write("# {} | {} | {} | {}\n\n".format(hote, commande, etat, horodatage))
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
