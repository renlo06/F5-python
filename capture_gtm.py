#!/usr/bin/env python3
"""Capture en lecture seule la configuration GTM (DNS) d'un BIG-IP.

Usage :
    python3 capture_gtm.py -H 10.0.0.10 -u admin -p 'motdepasse' [--shell auto|bash|tmsh]
"""

import argparse
import getpass
import sys

import paramiko


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
    """Renvoie 'bash' si on a un shell classique, 'tmsh' sinon.

    Certaines connexions SSH BIG-IP ouvrent directement le CLI tmsh.
    On teste en envoyant une commande shell simple.
    """
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


def recuperer_gtm(client, shell):
    """Récupère les objets GTM principaux en lecture seule."""
    commandes = {
        "wideip": "list gtm wideip all-properties",
        "pool_a": "list gtm pool a all-properties",
        "server": "list gtm server all-properties",
        "monitor_http": "list gtm monitor http all-properties",
    }
    resultats = {}
    for nom, cmd in commandes.items():
        print("[*] Récupération : {}".format(cmd))
        resultats[nom] = _tmsh(client, shell, cmd)
    return resultats


def sauvegarder(resultats, dossier):
    import os
    os.makedirs(dossier, exist_ok=True)
    for nom, contenu in resultats.items():
        chemin = os.path.join(dossier, "{}.txt".format(nom))
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(contenu)
        print("[+] Écrit : {}".format(chemin))


def main():
    parser = argparse.ArgumentParser(description="Capture GTM d'un BIG-IP (lecture seule)")
    parser.add_argument("-H", "--hote", required=True)
    parser.add_argument("-u", "--utilisateur", required=True)
    parser.add_argument("-p", "--mot-de-passe")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--shell", choices=["auto", "bash", "tmsh"], default="auto")
    parser.add_argument("-o", "--sortie", default="capture_gtm")
    args = parser.parse_args()

    mdp = args.mot_de_passe or getpass.getpass("Mot de passe : ")

    try:
        client = connecter(args.hote, args.utilisateur, mdp, args.port)
    except Exception as e:
        print("[!] Connexion impossible : {}".format(e), file=sys.stderr)
        sys.exit(1)

    try:
        shell = args.shell if args.shell != "auto" else detecter_shell(client)
        print("[*] Shell détecté : {}".format(shell))
        resultats = recuperer_gtm(client, shell)
        sauvegarder(resultats, args.sortie)
    except Exception as e:
        print("[!] Erreur : {}".format(e), file=sys.stderr)
        sys.exit(2)
    finally:
        client.close()


if __name__ == "__main__":
    main()
