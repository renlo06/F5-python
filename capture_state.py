#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Relevé en lecture seule de l'état runtime BIG-IP (toutes partitions) :
virtual servers, pools, membres, nodes.

Fichiers produits (captures/<label>_<phase>_<horodatage>/) :
    state_virtual.txt      show ltm virtual recursive field-fmt
    state_pool.txt         show ltm pool members recursive field-fmt
    state_node.txt         show ltm node recursive field-fmt
    state_summary.json     synthèse parsée (états stables uniquement)
    _meta_state.json       métadonnées (shell, durées, tailles, SHA256)

Usage:
    python capture_state.py --host 10.0.0.11 --label bigip-a [--phase before|after]
    python capture_state.py -f equipements.txt [--phase before|after]

Format de equipements.txt (une ligne par équipement, '#' = commentaire) :
    10.0.0.11  bigip-a
    10.0.0.12  bigip-b
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
TIMEOUT_COMMANDE = 180      # secondes (recursive peut être long)
REPERTOIRE_SORTIE = "captures"

# (fichier de sortie, commande tmsh sans préfixe de contexte)
COMMANDES_TMSH = [
    ("state_virtual.txt", "show ltm virtual recursive field-fmt"),
    ("state_pool.txt", "show ltm pool members recursive field-fmt"),
    ("state_node.txt", "show ltm node recursive field-fmt"),
]

# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #


def sha256_texte(texte: str) -> str:
    return hashlib.sha256(texte.encode("utf-8", errors="replace")).hexdigest()


def demander_phase() -> str:
    while True:
        rep = input("Etat de la capture [before/after] (b/a) : ").strip().lower()
        if rep in ("b", "before"):
            return "before"
        if rep in ("a", "after"):
            return "after"
        print("Réponse invalide : tape 'b' (before) ou 'a' (after).")


def lire_equipements(chemin: str) -> List[Tuple[str, str]]:
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


def nettoyer_label(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", label)


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #


def connecter(hote: str, utilisateur: str, mot_de_passe: str, port: int) -> "paramiko.SSHClient":
    client = paramiko.SSHClient()
    # Pas de vérification de clé d'hôte (demandé pour ce script)
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


def executer(client: "paramiko.SSHClient", commande: str, timeout: int = TIMEOUT_COMMANDE) -> Tuple[str, str, int]:
    _stdin, stdout, stderr = client.exec_command(commande, timeout=timeout)
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return sortie, erreur, code


def detecter_shell(client: "paramiko.SSHClient") -> str:
    """Retourne 'bash' ou 'tmsh'.

    Sous bash, 'echo' fonctionne ; sous tmsh, 'echo' n'existe pas et renvoie une erreur.
    """
    try:
        sortie, _err, code = executer(client, "echo __SHELL_TEST__", timeout=20)
        if code == 0 and "__SHELL_TEST__" in sortie:
            return "bash"
    except Exception:
        pass
    return "tmsh"


def construire_commande(shell: str, cmd_tmsh: str) -> str:
    """Adapte la commande au shell et se place à la racine (/) pour couvrir toutes les partitions."""
    if shell == "bash":
        return 'tmsh -c "cd /; {}"'.format(cmd_tmsh)
    return "cd /; {}".format(cmd_tmsh)


# --------------------------------------------------------------------------- #
# Parsing field-fmt
# --------------------------------------------------------------------------- #

RE_DEBUT_OBJET = re.compile(r"^ltm\s+(virtual|pool|node)\s+(\S+)\s*\{\s*$")
RE_CLE_VALEUR = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s+(.+?)\s*$")


def extraire_blocs(texte: str, type_objet: str) -> Dict[str, List[str]]:
    """Découpe la sortie field-fmt en blocs {nom_complet: [lignes]} pour un type donné."""
    blocs: Dict[str, List[str]] = {}
    courant: Optional[str] = None
    profondeur = 0
    for ligne in texte.splitlines():
        if courant is None:
            m = RE_DEBUT_OBJET.match(ligne.strip())
            if m and m.group(1) == type_objet:
                courant = m.group(2)
                blocs[courant] = []
                profondeur = 1
            continue
        profondeur += ligne.count("{") - ligne.count("}")
        if profondeur <= 0:
            courant = None
            profondeur = 0
            continue
        blocs[courant].append(ligne)
    return blocs


def valeurs_simples(lignes: List[str]) -> Dict[str, str]:
    """Extrait les paires clé/valeur de niveau 1 (hors sous-blocs)."""
    res: Dict[str, str] = {}
    niveau = 0
    for ligne in lignes:
        ouvre = ligne.count("{")
        ferme = ligne.count("}")
        if niveau == 0 and ouvre == 0 and ferme == 0:
            m = RE_CLE_VALEUR.match(ligne)
            if m:
                res[m.group(1)] = m.group(2)
        niveau += ouvre - ferme
    return res


def extraire_membres(lignes: List[str]) -> Dict[str, Dict[str, str]]:
    """Extrait les membres d'un pool : {adresse:port: {clé: valeur}}."""
    membres: Dict[str, Dict[str, str]] = {}
    dans_members = False
    niveau_members = 0
    membre_courant: Optional[str] = None
    niveau_membre = 0
    niveau = 0
    for ligne in lignes:
        txt = ligne.strip()
        ouvre = ligne.count("{")
        ferme = ligne.count("}")
        if not dans_members:
            if re.match(r"^members\s*\{", txt):
                dans_members = True
                niveau_members = niveau + 1
            niveau += ouvre - ferme
            continue
        if membre_courant is None:
            m = re.match(r"^(\S+)\s*\{\s*$", txt)
            if m:
                membre_courant = m.group(1)
                membres[membre_courant] = {}
                niveau_membre = niveau + 1
        else:
            if ouvre == 0 and ferme == 0:
                m = RE_CLE_VALEUR.match(ligne)
                if m:
                    membres[membre_courant][m.group(1)] = m.group(2)
        niveau += ouvre - ferme
        if membre_courant is not None and niveau < niveau_membre:
            membre_courant = None
        if dans_members and niveau < niveau_members:
            dans_members = False
    return membres


# Champs d'état stables conservés dans la synthèse (pas de compteurs de trafic)
CHAMPS_VIRTUAL = [
    "status.availability-state",
    "status.enabled-state",
    "status.status-reason",
    "destination",
]
CHAMPS_POOL = [
    "status.availability-state",
    "status.enabled-state",
    "status.status-reason",
    "active-member-cnt",
]
CHAMPS_MEMBRE = [
    "status.availability-state",
    "status.enabled-state",
    "status.status-reason",
    "monitor-status",
    "session-status",
]
CHAMPS_NODE = [
    "status.availability-state",
    "status.enabled-state",
    "status.status-reason",
    "monitor-status",
    "session-status",
    "addr",
]


def filtrer(valeurs: Dict[str, str], champs: List[str]) -> Dict[str, str]:
    return {c: valeurs[c] for c in champs if c in valeurs}


def construire_synthese(txt_virtual: str, txt_pool: str, txt_node: str) -> Dict[str, dict]:
    synthese: Dict[str, dict] = {"virtual": {}, "pool": {}, "node": {}}

    for nom, lignes in extraire_blocs(txt_virtual, "virtual").items():
        synthese["virtual"][nom] = filtrer(valeurs_simples(lignes), CHAMPS_VIRTUAL)

    for nom, lignes in extraire_blocs(txt_pool, "pool").items():
        entree = filtrer(valeurs_simples(lignes), CHAMPS_POOL)
        entree["members"] = {
            adresse: filtrer(vals, CHAMPS_MEMBRE)
            for adresse, vals in extraire_membres(lignes).items()
        }
        synthese["pool"][nom] = entree

    for nom, lignes in extraire_blocs(txt_node, "node").items():
        synthese["node"][nom] = filtrer(valeurs_simples(lignes), CHAMPS_NODE)

    return synthese


# --------------------------------------------------------------------------- #
# Capture d'un équipement
# --------------------------------------------------------------------------- #


def capturer_equipement(hote: str, label: str, phase: str, utilisateur: str,
                        mot_de_passe: str, port: int, racine: Path) -> bool:
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier = racine / "{}_{}_{}".format(nettoyer_label(label), phase, horodatage)
    dossier.mkdir(parents=True, exist_ok=True)

    print("\n=== {} ({}) [{}] ===".format(label, hote, phase))
    debut = time.time()
    meta = {
        "hote": hote,
        "label": label,
        "phase": phase,
        "horodatage": horodatage,
        "shell": None,
        "fichiers": {},
        "erreurs": [],
    }

    try:
        client = connecter(hote, utilisateur, mot_de_passe, port)
    except Exception as exc:
        print("  [ERREUR] connexion : {}".format(exc))
        meta["erreurs"].append("connexion: {}".format(exc))
        (dossier / "_meta_state.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        return False

    succes = True
    contenus: Dict[str, str] = {}
    try:
        shell = detecter_shell(client)
        meta["shell"] = shell
        print("  Shell détecté : {}".format(shell))

        for fichier, cmd_tmsh in COMMANDES_TMSH:
            commande = construire_commande(shell, cmd_tmsh)
            t0 = time.time()
            try:
                sortie, erreur, code = executer(client, commande)
            except Exception as exc:
                print("  [ERREUR] {} : {}".format(fichier, exc))
                meta["erreurs"].append("{}: {}".format(fichier, exc))
                succes = False
                continue

            if code != 0 or (not sortie.strip() and erreur.strip()):
                print("  [ERREUR] {} (code {}) : {}".format(fichier, code, erreur.strip()[:200]))
                meta["erreurs"].append("{} (code {}): {}".format(fichier, code, erreur.strip()[:500]))
                succes = False
                continue

            (dossier / fichier).write_text(sortie, encoding="utf-8")
            contenus[fichier] = sortie
            meta["fichiers"][fichier] = {
                "octets": len(sortie.encode("utf-8", errors="replace")),
                "sha256": sha256_texte(sortie),
                "duree_s": round(time.time() - t0, 2),
                "commande": commande,
            }
            print("  [OK] {} ({} octets, {:.1f}s)".format(
                fichier, meta["fichiers"][fichier]["octets"], meta["fichiers"][fichier]["duree_s"]))
    finally:
        client.close()

    if all(f in contenus for f, _c in COMMANDES_TMSH):
        synthese = construire_synthese(
            contenus["state_virtual.txt"],
            contenus["state_pool.txt"],
            contenus["state_node.txt"],
        )
        (dossier / "state_summary.json").write_text(
            json.dumps(synthese, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        print("  [OK] state_summary.json (virtual: {}, pool: {}, node: {})".format(
            len(synthese["virtual"]), len(synthese["pool"]), len(synthese["node"])))
    else:
        print("  [ATTENTION] synthèse non générée (capture incomplète)")
        succes = False

    meta["duree_totale_s"] = round(time.time() - debut, 2)
    (dossier / "_meta_state.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print("  Dossier : {}".format(dossier))
    return succes


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser(description="Relevé d'état BIG-IP (lecture seule, toutes partitions)")
    parser.add_argument("--host", help="Adresse de l'équipement")
    parser.add_argument("--label", help="Nom logique de l'équipement (défaut : host)")
    parser.add_argument("-f", "--fichier", help="Fichier liste d'équipements (host [label])")
    parser.add_argument("--phase", choices=["before", "after"], help="Phase de la capture (sinon demandée)")
    parser.add_argument("--user", default=os.environ.get("BIGIP_USER"), help="Utilisateur SSH (ou BIGIP_USER)")
    parser.add_argument("--port", type=int, default=22, help="Port SSH (défaut 22)")
    parser.add_argument("--output", default=REPERTOIRE_SORTIE, help="Répertoire de sortie")
    args = parser.parse_args()

    if not args.host and not args.fichier:
        parser.error("indique --host ou -f <fichier>")

    equipements: List[Tuple[str, str]] = []
    if args.fichier:
        equipements.extend(lire_equipements(args.fichier))
    if args.host:
        equipements.append((args.host, args.label or args.host))
    if not equipements:
        print("[ERREUR] aucun équipement à traiter")
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
