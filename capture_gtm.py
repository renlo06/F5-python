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
        print("Choix invalide, saisir 1 ou 2.")


# ---------------------------------------------------------------------------
# Connexion SSH et exécution de commandes
# ---------------------------------------------------------------------------

def connecter(hote, utilisateur, mot_de_passe, port=22):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hote, port=port, username=utilisateur,
                   password=mot_de_passe, timeout=30,
                   look_for_keys=False, allow_agent=False)
    return client


def run(client, cmd, timeout=180):
    """Exécute une commande et renvoie (stdout, stderr, code_retour)."""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return out, err, rc


def detecter_shell(client):
    """Renvoie 'bash' si un shell classique répond, 'tmsh' sinon."""
    try:
        out, _, rc = run(client, "echo __SHELL_OK__", timeout=15)
        if rc == 0 and "__SHELL_OK__" in out:
            return "bash"
    except Exception as e:
        print("    (détection shell : {})".format(e))
    return "tmsh"


def _tmsh(client, shell, commande):
    """Exécute une commande tmsh en lecture seule et renvoie sa sortie."""
    cmd = "tmsh {}".format(commande) if shell == "bash" else commande
    out, err, rc = run(client, cmd, timeout=180)
    if rc != 0 or "Syntax Error" in out:
        raise RuntimeError("commande '{}' : rc={} stderr={} stdout={}".format(
            cmd, rc, err.strip()[:300], out.strip()[:300]))
    print("    OK : {} ({} caractères)".format(cmd, len(out)))
    return out


def recuperer_gtm(client, shell):
    """Récupère toutes les commandes GTM. Renvoie un dict nom -> contenu."""
    resultats = {}
    for nom, commande in COMMANDES_GTM.items():
        try:
            resultats[nom] = _tmsh(client, shell, commande)
        except Exception as e:
            print("    [!] {} : {}".format(nom, e))
            resultats[nom] = "ERREUR : {}\n".format(e)
    return resultats


# ---------------------------------------------------------------------------
# Parsing de la sortie tmsh et construction de l'arborescence
# ---------------------------------------------------------------------------

# Entrées de premier niveau : "gtm wideip /Common/www.example.com {"
RE_OBJET = re.compile(r"^(?:ltm |gtm )?(wideip|pool|server)\s+(\S+)\s*\{", re.MULTILINE)


def _bloc(texte, debut_pos):
    """Renvoie le texte du bloc { ... } qui commence après debut_pos."""
    ouverture = texte.find("{", debut_pos)
    if ouverture == -1:
        return ""
    niveau = 0
    for i in range(ouverture, len(texte)):
        if texte[i] == "{":
            niveau += 1
        elif texte[i] == "}":
            niveau -= 1
            if niveau == 0:
                return texte[ouverture + 1:i]
    return texte[ouverture + 1:]


def parser_objets(texte, type_attendu):
    """Renvoie {nom: bloc_texte} pour les objets d'un type donné."""
    objets = {}
    for m in RE_OBJET.finditer(texte):
        if m.group(1) == type_attendu:
            objets[m.group(2)] = _bloc(texte, m.end() - 1)
    return objets


def pools_du_wideip(bloc_wideip):
    """Renvoie la liste des noms de pools référencés dans un WideIP."""
    pools = []
    bloc_pools = re.search(r"pools\s*\{", bloc_wideip)
    if not bloc_pools:
        return pools
    contenu = _bloc(bloc_wideip, bloc_pools.start() + len("pools") )
    for m in re.finditer(r"^\s*(/?\S+)\s*\{", contenu, re.MULTILINE):
        pools.append(m.group(1))
    return pools


def membres_du_pool(bloc_pool):
    """Renvoie la liste des membres (serveur:service) d'un pool."""
    membres = []
    bloc_members = re.search(r"members\s*\{", bloc_pool)
    if not bloc_members:
        return membres
    contenu = _bloc(bloc_pool, bloc_members.start() + len("members"))
    for m in re.finditer(r"^\s*(/?[^\s{}:]+:[^\s{}]+)\s*\{", contenu, re.MULTILINE):
        membres.append(m.group(1))
    return membres


def construire_arborescence(sortie_wideip, sortie_pool):
    """Construit le texte de l'arborescence WideIP -> Pool -> Pool member."""
    wideips = parser_objets(sortie_wideip, "wideip")
    pools = parser_objets(sortie_pool, "pool")

    lignes = []
    lignes.append("ARBORESCENCE GTM : WideIP -> Pool -> Pool member")
    lignes.append("=" * 60)

    if not wideips:
        lignes.append("(aucun WideIP trouvé)")
        return "\n".join(lignes) + "\n"

    for i, (nom_wip, bloc_wip) in enumerate(sorted(wideips.items())):
        dernier_wip = (i == len(wideips) - 1)
        branche_wip = "└── " if dernier_wip else "├── "
        lignes.append("{}WideIP : {}".format(branche_wip, nom_wip))
        prefixe_wip = "    " if dernier_wip else "│   "

        noms_pools = pools_du_wideip(bloc_wip)
        if not noms_pools:
            lignes.append("{}└── (aucun pool)".format(prefixe_wip))
            continue

        for j, nom_pool in enumerate(noms_pools):
            dernier_pool = (j == len(noms_pools) - 1)
            branche_pool = "└── " if dernier_pool else "├── "
            prefixe_pool = prefixe_wip + ("    " if dernier_pool else "│   ")

            bloc_pool = pools.get(nom_pool)
            if bloc_pool is None:
                lignes.append("{}{}Pool : {} (introuvable dans list gtm pool)".format(
                    prefixe_wip, branche_pool, nom_pool))
                continue

            lignes.append("{}{}Pool : {}".format(prefixe_wip, branche_pool, nom_pool))
            membres = membres_du_pool(bloc_pool)
            if not membres:
                lignes.append("{}└── (aucun pool member)".format(prefixe_pool))
                continue

            for k, membre in enumerate(membres):
                dernier_membre = (k == len(membres) - 1)
                branche_m = "└── " if dernier_membre else "├── "
                lignes.append("{}{}Pool member : {}".format(
                    prefixe_pool, branche_m, membre))

    return "\n".join(lignes) + "\n"


# ---------------------------------------------------------------------------
# Sauvegarde et orchestration
# ---------------------------------------------------------------------------

def sauvegarder(resultats, dossier):
    os.makedirs(dossier, exist_ok=True)
    print("    écriture dans : {}".format(os.path.abspath(dossier)))
    for nom, contenu in resultats.items():
        chemin = os.path.join(dossier, "{}.txt".format(nom))
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(contenu)
        print("    -> {}.txt".format(nom))


def capturer_equipement(hote, args, utilisateur, mdp, etat, horodatage):
    print("\n[*] {} : connexion".format(hote))
    client = connecter(hote, utilisateur, mdp, args.port)
    try:
        shell = args.shell if args.shell != "auto" else detecter_shell(client)
        print("[*] {} : shell = {}".format(hote, shell))
        resultats = recuperer_gtm(client, shell)
    finally:
        client.close()

    dossier = os.path.join(args.sortie, "{}_{}".format(etat, horodatage), hote)
    sauvegarder(resultats, dossier)

    # Arborescence générée à partir des sorties capturées
    arbre = construire_arborescence(
        resultats.get("gtm_wideip", ""),
        resultats.get("gtm_pool", ""),
    )
    chemin_arbre = os.path.join(dossier, "arborescence_gtm.txt")
    with open(chemin_arbre, "w", encoding="utf-8") as f:
        f.write(arbre)
    print("    -> arborescence_gtm.txt")

    print("[+] {} : capture terminée ({})".format(hote, etat))
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Capture GTM de plusieurs BIG-IP (lecture seule) + arborescence")
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
