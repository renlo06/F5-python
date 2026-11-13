#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Relevé en lecture seule de l'état runtime BIG-IP : virtual servers, pools,
membres, nodes. Les pools sont relevés sur TOUTES les partitions.

Fichiers produits (captures/<label>_<phase>_<horodatage>/) :
    state_virtual.txt      show ltm virtual field-fmt
    state_pool.txt         show ltm pool members field-fmt (toutes partitions)
    state_node.txt         show ltm node field-fmt
    state_summary.json     synthèse parsée
    _meta_state.json       métadonnées (shell, durées, tailles, SHA256)

Usage:
    python capture_state.py --host 10.0.0.11 --label bigip-a [--phase before|after]
    python capture_state.py -f equipements.txt [--phase before|after]

Format de equipements.txt (une ligne par équipement, '#' = commentaire) :
    10.0.0.11  bigip-a
    10.0.0.12  bigip-b

Le mot de passe peut être fourni via la variable d'environnement BIGIP_PASSWORD.
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

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

TIMEOUT_CONNEXION = 15      # secondes
TIMEOUT_COMMANDE = 180      # secondes
REPERTOIRE_SORTIE = "captures"

PREFIXE_PARTITIONS = "modify cli admin-partitions update-partition All"

# (fichier de sortie, commande tmsh, toutes_partitions)
COMMANDES_TMSH = [
    ("state_virtual.txt", "show ltm virtual field-fmt", False),
    ("state_pool.txt", "show ltm pool members field-fmt", True),
    ("state_node.txt", "show ltm node field-fmt", False),
]


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #

def sha256_texte(texte: str) -> str:
    return hashlib.sha256(texte.encode("utf-8", errors="replace")).hexdigest()


def demander_phase() -> str:
    while True:
        rep = input("Phase de la capture (before/after) : ").strip().lower()
        if rep in ("before", "after"):
            return rep
        print("Réponse invalide : saisir 'before' ou 'after'.")


def lire_fichier_equipements(chemin: str) -> List[Tuple[str, str]]:
    equipements = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne or ligne.startswith("#"):
                continue
            parts = ligne.split()
            hote = parts[0]
            label = parts[1] if len(parts) > 1 else hote
            equipements.append((hote, label))
    return equipements


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #

def connecter(hote: str, port: int, utilisateur: str, mot_de_passe: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    # Pas de vérification de clé d'hôte
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=hote,
        port=port,
        username=utilisateur,
        password=mot_de_passe,
        timeout=TIMEOUT_CONNEXION,
        banner_timeout=TIMEOUT_CONNEXION,
        auth_timeout=TIMEOUT_CONNEXION,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def executer(client: paramiko.SSHClient, commande: str, timeout: int = TIMEOUT_COMMANDE) -> Tuple[str, str, int]:
    _stdin, stdout, stderr = client.exec_command(commande, timeout=timeout)
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return sortie, erreur, code


def detecter_shell(client: paramiko.SSHClient) -> str:
    """Retourne 'bash' si la session atterrit dans bash, 'tmsh' si elle atterrit dans tmsh."""
    sortie, _err, code = executer(client, "echo $0", timeout=TIMEOUT_CONNEXION)
    sortie = sortie.strip().lower()
    if code == 0 and ("bash" in sortie or sortie.endswith("sh")):
        return "bash"
    return "tmsh"


def construire_commande(shell: str, cmd_tmsh: str, toutes_partitions: bool = False) -> str:
    """Adapte la commande au shell ; active la vue sur toutes les partitions si demandé."""
    complete = "{}; {}".format(PREFIXE_PARTITIONS, cmd_tmsh) if toutes_partitions else cmd_tmsh
    if shell == "bash":
        return 'tmsh -c "{}"'.format(complete)
    return complete


# --------------------------------------------------------------------------- #
# Parsing field-fmt
# --------------------------------------------------------------------------- #

def decouper_blocs(texte: str, prefixe: str) -> List[List[str]]:
    """Découpe la sortie field-fmt en blocs d'objets (un bloc par 'ltm <type> <nom> {')."""
    blocs: List[List[str]] = []
    courant: Optional[List[str]] = None
    for ligne in texte.splitlines():
        if ligne.startswith(prefixe) and ligne.rstrip().endswith("{"):
            courant = [ligne]
            blocs.append(courant)
        elif courant is not None:
            courant.append(ligne)
    return blocs


def extraire_champ(bloc: List[str], champ: str) -> Optional[str]:
    motif = re.compile(r"^\s*{}\s+(.+?)\s*$".format(re.escape(champ)))
    for ligne in bloc:
        m = motif.match(ligne)
        if m:
            return m.group(1)
    return None


def parser_virtuals(texte: str) -> List[Dict[str, Optional[str]]]:
    resultat = []
    for bloc in decouper_blocs(texte, "ltm virtual "):
        nom = bloc[0].split()[2]
        resultat.append({
            "nom": nom,
            "destination": extraire_champ(bloc, "destination"),
            "etat": extraire_champ(bloc, "status.availability-state"),
            "etat_active": extraire_champ(bloc, "status.enabled-state"),
        })
    return resultat


def parser_pools(texte: str) -> List[Dict[str, object]]:
    """Parse 'show ltm pool members field-fmt' : un bloc pool contenant des blocs de membres."""
    pools: List[Dict[str, object]] = []
    pool_courant: Optional[Dict[str, object]] = None
    membre_courant: Optional[Dict[str, Optional[str]]] = None

    for ligne in texte.splitlines():
        brut = ligne.strip()
        if ligne.startswith("ltm pool ") and brut.endswith("{"):
            pool_courant = {
                "nom": ligne.split()[2],
                "etat": None,
                "etat_active": None,
                "membres": [],
            }
            pools.append(pool_courant)
            membre_courant = None
        elif pool_courant is None:
            continue
        elif brut.startswith("members {"):
            continue
        elif re.match(r"^\S+:\d+\s*\{$", brut) or re.match(r"^\S+\.\d+\s*\{$", brut):
            adresse = brut[:-1].strip()
            membre_courant = {"adresse": adresse, "etat": None, "etat_active": None}
            pool_courant["membres"].append(membre_courant)  # type: ignore[union-attr]
        elif brut.startswith("status.availability-state"):
            valeur = brut.split(None, 1)[1]
            (membre_courant if membre_courant is not None else pool_courant)["etat"] = valeur
        elif brut.startswith("status.enabled-state"):
            valeur = brut.split(None, 1)[1]
            (membre_courant if membre_courant is not None else pool_courant)["etat_active"] = valeur
    return pools


def parser_nodes(texte: str) -> List[Dict[str, Optional[str]]]:
    resultat = []
    for bloc in decouper_blocs(texte, "ltm node "):
        resultat.append({
            "nom": bloc[0].split()[2],
            "etat": extraire_champ(bloc, "status.availability-state"),
            "etat_active": extraire_champ(bloc, "status.enabled-state"),
        })
    return resultat


# --------------------------------------------------------------------------- #
# Capture d'un équipement
# --------------------------------------------------------------------------- #

def capturer_equipement(hote: str, label: str, phase: str, utilisateur: str,
                        mot_de_passe: str, port: int, racine: Path) -> bool:
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier = racine / "{}_{}_{}".format(label, phase, horodatage)
    dossier.mkdir(parents=True, exist_ok=True)

    print("\n[{}] Connexion à {} ...".format(label, hote))
    try:
        client = connecter(hote, port, utilisateur, mot_de_passe)
    except Exception as exc:
        print("[{}] ERREUR de connexion : {}".format(label, exc))
        return False

    meta: Dict[str, object] = {
        "hote": hote,
        "label": label,
        "phase": phase,
        "horodatage": horodatage,
        "fichiers": {},
    }
    succes = True
    contenus: Dict[str, str] = {}

    try:
        shell = detecter_shell(client)
        meta["shell"] = shell
        print("[{}] Shell détecté : {}".format(label, shell))

        for nom_fichier, cmd_tmsh, toutes_partitions in COMMANDES_TMSH:
            commande = construire_commande(shell, cmd_tmsh, toutes_partitions)
            debut = time.time()
            try:
                sortie, erreur, code = executer(client, commande)
            except Exception as exc:
                print("[{}] ERREUR sur '{}' : {}".format(label, cmd_tmsh, exc))
                meta["fichiers"][nom_fichier] = {"erreur": str(exc)}  # type: ignore[index]
                succes = False
                continue
            duree = time.time() - debut

            if code != 0 or (erreur.strip() and not sortie.strip()):
                print("[{}] ERREUR sur '{}' (code {}): {}".format(
                    label, cmd_tmsh, code, erreur.strip() or sortie.strip()))
                meta["fichiers"][nom_fichier] = {  # type: ignore[index]
                    "commande": commande, "code": code, "erreur": erreur.strip()}
                succes = False
                continue

            (dossier / nom_fichier).write_text(sortie, encoding="utf-8")
            contenus[nom_fichier] = sortie
            meta["fichiers"][nom_fichier] = {  # type: ignore[index]
                "commande": commande,
                "duree_s": round(duree, 2),
                "octets": len(sortie.encode("utf-8")),
                "sha256": sha256_texte(sortie),
            }
            print("[{}] OK  {:<20} {:>8} octets  {:.1f}s".format(
                label, nom_fichier, len(sortie.encode("utf-8")), duree))

        synthese = {
            "virtuals": parser_virtuals(contenus.get("state_virtual.txt", "")),
            "pools": parser_pools(contenus.get("state_pool.txt", "")),
            "nodes": parser_nodes(contenus.get("state_node.txt", "")),
        }
        (dossier / "state_summary.json").write_text(
            json.dumps(synthese, indent=2, ensure_ascii=False), encoding="utf-8")
        print("[{}] Synthèse : {} virtuals, {} pools, {} nodes".format(
            label, len(synthese["virtuals"]), len(synthese["pools"]), len(synthese["nodes"])))

    except Exception as exc:
        print("[{}] ERREUR inattendue : {}".format(label, exc))
        succes = False
    finally:
        client.close()

    (dossier / "_meta_state.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print("[{}] Résultats dans : {}".format(label, dossier))
    return succes


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(description="Relevé d'état BIG-IP (lecture seule)")
    parser.add_argument("--host", help="Adresse IP / nom de l'équipement")
    parser.add_argument("--label", help="Nom court utilisé pour nommer les fichiers")
    parser.add_argument("-f", "--file", help="Fichier listant les équipements")
    parser.add_argument("--phase", choices=["before", "after"], help="Phase de la capture")
    parser.add_argument("--user", help="Utilisateur SSH")
    parser.add_argument("--port", type=int, default=22, help="Port SSH (défaut : 22)")
    parser.add_argument("--output", default=REPERTOIRE_SORTIE, help="Répertoire de sortie")
    args = parser.parse_args()

    if args.file:
        equipements = lire_fichier_equipements(args.file)
    elif args.host:
        equipements = [(args.host, args.label or args.host)]
    else:
        parser.error("Indiquer --host ou -f")
        return 2

    if not equipements:
        print("[ERREUR] Aucun équipement à traiter.")
        return 2

    phase = args.phase or demander_phase()

    utilisateur = args.user or input("Utilisateur SSH : ").strip()
    mot_de_passe = os.environ.get("BIGIP_PASSWORD") or getpass.getpass("Mot de passe : ")

    racine = Path(args.output)
    racine.mkdir(parents=True, exist_ok=True)

    bilan: List[Tuple[str, bool]] = []
    for hote, label in equipements:
        ok = capturer_equipement(hote, label, phase, utilisateur, mot_de_passe, args.port, racine)
        bilan.append((label, ok))

    print("\n=== Bilan [{}] ===".format(phase))
    for label, ok in bilan:
        print("  {:<30} {}".format(label, "OK" if ok else "ERREUR"))
    return 0 if all(ok for _l, ok in bilan) else 1


if __name__ == "__main__":
    sys.exit(main())
