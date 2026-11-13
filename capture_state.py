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

Le shell de connexion (bash ou tmsh) est détecté automatiquement et les
commandes sont adaptées en conséquence.

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
        reponse = input("Choix [1/2 ou before/after] : ").strip().lower()
        if reponse in ("1", "b", "before", "avant"):
            return "before"
        if reponse in ("2", "a", "after", "apres", "après"):
            return "after"
        print("  Réponse invalide, tape 1 (before) ou 2 (after).")


def demander_equipement() -> Equipement:
    """Demande interactivement un équipement unique."""
    host = input("Adresse IP / nom d'hôte du BIG-IP : ").strip()
    if not host:
        raise ValueError("Adresse vide.")
    label = input("Label [{}] : ".format(host)).strip() or host
    saisie_port = input("Port SSH [{}] : ".format(PORT_DEFAUT)).strip()
    port = int(saisie_port) if saisie_port else PORT_DEFAUT
    return label, host, None, port


# --------------------------------------------------- Lecture du fichier hosts

def lire_fichier_hosts(chemin: str) -> List[Equipement]:
    """Lit le fichier d'équipements.

    Formats acceptés par ligne :
        host
        label;host
        label;host;user
        label;host;user;port
    """
    equipements: List[Equipement] = []
    vus = set()

    with open(chemin, "r", encoding="utf-8") as fichier:
        for numero, ligne in enumerate(fichier, start=1):
            ligne = ligne.split("#", 1)[0].strip()
            if not ligne:
                continue

            champs = [c.strip() for c in ligne.split(";")]
            user: Optional[str] = None
            port = PORT_DEFAUT

            if len(champs) == 1:
                host = champs[0]
                label = host
            else:
                label, host = champs[0], champs[1]
                if len(champs) >= 3 and champs[2]:
                    user = champs[2]
                if len(champs) >= 4 and champs[3]:
                    try:
                        port = int(champs[3])
                    except ValueError:
                        print("  [AVERTISSEMENT] ligne {} : port invalide '{}', "
                              "ligne ignorée.".format(numero, champs[3]))
                        continue

            if not host:
                print("  [AVERTISSEMENT] ligne {} : hôte vide, ignorée."
                      .format(numero))
                continue

            cle = (host, port)
            if cle in vus:
                print("  [AVERTISSEMENT] ligne {} : doublon {}:{}, ignoré."
                      .format(numero, host, port))
                continue
            vus.add(cle)

            equipements.append((label or host, host, user, port))

    return equipements


# ------------------------------------------------------------------- SSH

def connecter(host: str, port: int, user: str,
              password: str) -> paramiko.SSHClient:
    """Ouvre une connexion SSH (clé d'hôte non vérifiée)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=TIMEOUT_SSH,
        banner_timeout=TIMEOUT_SSH,
        auth_timeout=TIMEOUT_SSH,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def detecter_shell(client: paramiko.SSHClient) -> str:
    """Détecte le shell de connexion du compte : 'bash' ou 'tmsh'.

    Sous bash, 'echo $0' renvoie le nom du shell. Sous tmsh, la commande
    provoque une erreur de syntaxe (ou un retour vide) : on en déduit tmsh."""
    try:
        _, stdout, stderr = client.exec_command("echo $0", timeout=TIMEOUT_SSH)
        sortie = stdout.read().decode("utf-8", errors="replace").strip().lower()
        erreur = stderr.read().decode("utf-8", errors="replace").strip().lower()
    except Exception:  # noqa: BLE001
        return "tmsh"

    if "syntax error" in sortie or "syntax error" in erreur:
        return "tmsh"
    if "bash" in sortie or sortie.endswith("sh"):
        return "bash"
    return "tmsh"


def executer_tmsh(client: paramiko.SSHClient, commande: str,
                  shell: str) -> str:
    """Exécute une commande tmsh en l'adaptant au shell de connexion."""
    if shell == "bash":
        cmd = "tmsh -c '{}'".format(commande.replace("'", "'\\''"))
    else:
        cmd = commande          # le shell est déjà tmsh

    _, stdout, stderr = client.exec_command(cmd, timeout=TIMEOUT_COMMANDE)
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace")

    if "syntax error" in sortie.lower() or "syntax error" in erreur.lower():
        raise RuntimeError("tmsh (shell {}) : {}".format(
            shell, (sortie or erreur).strip()))
    if not sortie.strip() and erreur.strip():
        raise RuntimeError("tmsh : {}".format(erreur.strip()))
    return sortie


# ---------------------------------------------------------------- Parsing

def decouper_blocs(texte: str, entete: str) -> List[List[str]]:
    """Découpe une sortie field-fmt en blocs commençant par 'entete'."""
    blocs: List[List[str]] = []
    courant: Optional[List[str]] = None
    for ligne in texte.splitlines():
        if ligne.startswith(entete + " "):
            if courant is not None:
                blocs.append(courant)
            courant = [ligne]
        elif courant is not None:
            courant.append(ligne)
    if courant is not None:
        blocs.append(courant)
    return blocs


def champ(lignes: List[str], nom: str) -> Optional[str]:
    """Retourne la valeur du premier champ 'nom valeur' trouvé."""
    motif = re.compile(r"^\s*" + re.escape(nom) + r"\s+(.+?)\s*$")
    for ligne in lignes:
        m = motif.match(ligne)
        if m:
            return m.group(1)
    return None


def parser_virtuals(texte: str) -> List[Dict[str, Optional[str]]]:
    resultat = []
    for bloc in decouper_blocs(texte, "ltm virtual"):
        nom = bloc[0].split()[2]
        resultat.append({
            "nom": nom,
            "destination": champ(bloc, "destination"),
            "disponibilite": champ(bloc, "status.availability-state"),
            "etat": champ(bloc, "status.enabled-state"),
            "raison": champ(bloc, "status.status-reason"),
        })
    return resultat


def parser_pools(texte: str) -> List[Dict[str, object]]:
    resultat = []
    for bloc in decouper_blocs(texte, "ltm pool"):
        nom = bloc[0].split()[2]
        membres = []
        courant: Optional[Dict[str, Optional[str]]] = None
        for ligne in bloc[1:]:
            m = re.match(r"^\s*ltm pool \S+ members \{", ligne)
            if m:
                continue
            m = re.match(r"^\s{4}(\S+)\s*\{\s*$", ligne)
            if m:
                courant = {"membre": m.group(1)}
                membres.append(courant)
                continue
            if courant is not None:
                for cle, nom_champ in (
                        ("disponibilite", "status.availability-state"),
                        ("etat", "status.enabled-state"),
                        ("raison", "status.status-reason")):
                    m = re.match(r"^\s+" + re.escape(nom_champ) + r"\s+(.+?)\s*$",
                                 ligne)
                    if m:
                        courant[cle] = m.group(1)
        resultat.append({
            "nom": nom,
            "disponibilite": champ(bloc, "status.availability-state"),
            "etat": champ(bloc, "status.enabled-state"),
            "membres": membres,
        })
    return resultat


def parser_nodes(texte: str) -> List[Dict[str, Optional[str]]]:
    resultat = []
    for bloc in decouper_blocs(texte, "ltm node"):
        nom = bloc[0].split()[2]
        resultat.append({
            "nom": nom,
            "adresse": champ(bloc, "addr"),
            "disponibilite": champ(bloc, "status.availability-state"),
            "etat": champ(bloc, "status.enabled-state"),
            "raison": champ(bloc, "status.status-reason"),
        })
    return resultat


# ---------------------------------------------------------------- Capture

def assainir(nom: str) -> str:
    """Rend un label utilisable comme nom de dossier."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", nom)


def capturer_equipement(label: str, host: str, port: int, user: str,
                        password: str, phase: str, racine: Path) -> Path:
    """Capture l'état d'un équipement et retourne le dossier créé."""
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier = racine / "{}_{}_{}".format(assainir(label), phase, horodatage)
    dossier.mkdir(parents=True, exist_ok=True)

    client = connecter(host, port, user, password)
    try:
        shell = detecter_shell(client)
        print("  Shell détecté : {}".format(shell))

        sorties: Dict[str, str] = {}
        for fichier, commande in COMMANDES_TMSH:
            texte = executer_tmsh(client, commande, shell)
            (dossier / fichier).write_text(texte, encoding="utf-8")
            sorties[fichier] = texte
            print("  [OK] {:<20} {} octets".format(fichier, len(texte)))
    finally:
        client.close()

    resume = {
        "label": label,
        "host": host,
        "phase": phase,
        "horodatage": horodatage,
        "shell": shell,
        "virtuals": parser_virtuals(sorties["state_virtual.txt"]),
        "pools": parser_pools(sorties["state_pool.txt"]),
        "nodes": parser_nodes(sorties["state_node.txt"]),
    }
    (dossier / "state_summary.json").write_text(
        json.dumps(resume, indent=2, ensure_ascii=False), encoding="utf-8")

    print("  Virtuals: {}  Pools: {}  Nodes: {}".format(
        len(resume["virtuals"]), len(resume["pools"]), len(resume["nodes"])))
    return dossier


# ------------------------------------------------------------------- Main

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture de l'état runtime de BIG-IP (before / after).")
    parser.add_argument("-f", "--fichier",
                        help="fichier d'équipements (label;host;user;port)")
    parser.add_argument("--host", help="équipement unique (IP ou nom)")
    parser.add_argument("--label", help="label de l'équipement unique")
    parser.add_argument("--port", type=int, default=PORT_DEFAUT,
                        help="port SSH par défaut (défaut : 22)")
    parser.add_argument("-u", "--user", help="utilisateur SSH")
    parser.add_argument("--phase", choices=("before", "after"),
                        help="état de la capture (demandé si absent)")
    parser.add_argument("--captures", default=REPERTOIRE_CAPTURES,
                        help="répertoire de sortie (défaut : captures)")
    args = parser.parse_args()

    # 1) Liste des équipements
    equipements: List[Equipement] = []
    if args.fichier:
        try:
            equipements = lire_fichier_hosts(args.fichier)
        except OSError as exc:
            print("Erreur de lecture du fichier : {}".format(exc))
            return 2
        if not equipements:
            print("Aucun équipement valide dans {}.".format(args.fichier))
            return 2
    elif args.host:
        equipements = [(args.label or args.host, args.host, None, args.port)]
    else:
        try:
            equipements = [demander_equipement()]
        except (ValueError, KeyboardInterrupt) as exc:
            print("Abandon : {}".format(exc))
            return 2

    # 2) Phase, utilisateur et mot de passe
    phase = args.phase or demander_phase()
    user_defaut = args.user or input("Utilisateur SSH : ").strip()
    if not user_defaut:
        print("Utilisateur obligatoire.")
        return 2

    print("\nPhase : {} | {} équipement(s)".format(phase.upper(),
                                                   len(equipements)))
    password = os.environ.get("BIGIP_PASSWORD") or getpass.getpass(
        "Mot de passe : ")

    racine = Path(args.captures)
    racine.mkdir(parents=True, exist_ok=True)

    # 3) Capture de chaque équipement (on continue en cas d'erreur)
    ok = 0
    erreurs: List[Tuple[str, str]] = []
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
