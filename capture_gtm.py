#!/usr/bin/env python3
"""Capture en lecture seule la configuration GTM (DNS) de plusieurs BIG-IP.

Usage :
    python3 capture_gtm.py -f equipements.txt [-o sortie] [--shell auto|bash|tmsh]

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
import sys
from datetime import datetime

import paramiko


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
    except Exception:
        pass
    return "tmsh"


def _tmsh(client, shell, commande):
    """Exécute une commande tmsh en lecture seule et renvoie sa sortie."""
    if shell == "bash":
        cmd = "tmsh {}".format(commande)
    elif shell == "tmsh":
        cmd = commande
    else:
        raise ValueError("shell non pris en charge : {}".format(shell))

    out, err, rc = run(client, cmd, timeout=180)
    if rc != 0 or "Syntax Error" in out:
        raise RuntimeError("commande '{}' en échec : {}".format(
            commande, (err or out).strip() or "code {}".format(rc)))
    return out


COMMANDES_GTM = {
    "wideip": "list gtm wideip all-properties",
    "pool_a": "list gtm pool a all-properties",
    "server": "list gtm server all-properties",
    "monitor_http": "list gtm monitor http all-properties",
}


def recuperer_gtm(client, shell):
    """Récupère les objets GTM principaux en lecture seule."""
    resultats = {}
    for nom, cmd in COMMANDES_GTM.items():
        resultats[nom] = _tmsh(client, shell, cmd)
    return resultats


def sauvegarder(resultats, dossier):
    os.makedirs(dossier, exist_ok=True)
    for nom, contenu in resultats.items():
        chemin = os.path.join(dossier, "{}.txt".format(nom))
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(contenu)


def capturer_equipement(hote, args, utilisateur, mdp, etat, horodatage):
    """Capture un équipement dans <sortie>/<etat>_<horodatage>/<hote>/."""
    print("[*] {} : connexion".format(hote))
    client = connecter(hote, utilisateur, mdp, args.port)
    try:
        shell = args.shell if args.shell != "auto" else detecter_shell(client)
        print("[*] {} : shell détecté = {}".format(hote, shell))
        resultats = recuperer_gtm(client, shell)
        dossier = os.path.join(args.sortie, "{}_{}".format(etat, horodatage), hote)
        sauvegarder(resultats, dossier)
        print("[+] {} : capture terminée ({})".format(hote, etat))
        return True
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Capture GTM de plusieurs BIG-IP (lecture seule)")
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

    echecs = []
    for hote in hotes:
        try:
            capturer_equipement(hote, args, utilisateur, mdp, etat, horodatage)
        except Exception as e:
            print("[!] {} : erreur : {}".format(hote, e), file=sys.stderr)
            echecs.append(hote)

    print("\n[*] Terminé ({}) : {} réussi(s), {} échec(s)".format(
        etat, len(hotes) - len(echecs), len(echecs)))
    if echecs:
        print("[!] Échecs : {}".format(", ".join(echecs)))
        sys.exit(2)


if __name__ == "__main__":
    main()
