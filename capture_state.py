#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capture de l'état (statut uniquement) des VS, pools et pool members BIG-IP.

Ne collecte QUE l'état, sans aucune statistique (connexions, octets, paquets) :
    - virtual servers : disponibilité, état activé/désactivé, raison
    - pools           : disponibilité, état activé/désactivé
    - pool members    : IP:port, disponibilité, état activé/désactivé, raison

Produit dans captures/<label>_<phase>_<horodatage>/ :
    state_virtual.txt   (statuts des virtual servers)
    state_pool.txt      (statuts des pools et de leurs membres)
    state_summary.json  (données structurées)

Aucune sortie brute n'est conservée : seuls les champs d'état sont écrits.

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

Le shell de connexion (bash ou tmsh) est détecté automatiquement.

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
CMD_VIRTUAL = "show ltm virtual /*/* field-fmt"
CMD_POOL = "show ltm pool /*/* field-fmt"
# Configuration des pools : contient la liste des membres (nom + adresse)
CMD_POOL_CONFIG = "list ltm pool /*/* members"

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
    """Détecte le shell de connexion du compte : 'bash' ou 'tmsh'."""
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

RE_VIRTUAL = re.compile(r"^ltm virtual (\S+)\s*\{")
RE_POOL = re.compile(r"^ltm pool (\S+)\s*\{")
# Membre dans la config : '/Common/10.0.0.11:80 {' ou '/Common/srv:80 {'
RE_MEMBRE_BLOC = re.compile(r"^(/\S+:\S+)\s*\{$")
RE_CHAMP = re.compile(r"^(\S+)\s+(.+)$")


def cle_etat(cle: str) -> Optional[str]:
    """Convertit un champ tmsh d'état en clé interne (None si ignoré)."""
    return {
        "status.availability-state": "disponibilite",
        "status.enabled-state": "etat",
        "status.status-reason": "raison",
    }.get(cle)


def parser_virtuals(texte: str) -> List[Dict[str, Optional[str]]]:
    """Extrait nom, destination et état de chaque virtual server."""
    resultat: List[Dict[str, Optional[str]]] = []
    courant: Optional[Dict[str, Optional[str]]] = None

    for ligne in texte.splitlines():
        brut = ligne.strip()
        m = RE_VIRTUAL.match(brut)
        if m:
            courant = {"nom": m.group(1), "destination": None,
                       "disponibilite": None, "etat": None, "raison": None}
            resultat.append(courant)
            continue
        if courant is None:
            continue
        m = RE_CHAMP.match(brut)
        if not m:
            continue
        cle, valeur = m.group(1), m.group(2).strip()
        if cle == "destination":
            courant["destination"] = valeur
        elif cle_etat(cle):
            courant[cle_etat(cle)] = valeur  # type: ignore[index]
    return resultat


def parser_pools(texte: str) -> Dict[str, Dict[str, Optional[str]]]:
    """Extrait l'état de chaque pool : {nom_pool: {disponibilite, etat}}."""
    pools: Dict[str, Dict[str, Optional[str]]] = {}
    courant: Optional[Dict[str, Optional[str]]] = None

    for ligne in texte.splitlines():
        brut = ligne.strip()
        m = RE_POOL.match(brut)
        if m:
            courant = {"disponibilite": None, "etat": None, "raison": None}
            pools[m.group(1)] = courant
            continue
        if courant is None:
            continue
        m = RE_CHAMP.match(brut)
        if not m:
            continue
        interne = cle_etat(m.group(1))
        if interne:
            courant[interne] = m.group(2).strip()
    return pools


def parser_config_membres(texte: str) -> Dict[str, List[str]]:
    """Extrait, depuis 'list ltm pool ... members', les noms des membres.

    Retourne {nom_pool: ['/Common/10.0.0.11:80', ...]}. Seuls les noms
    sont lus (aucune statistique dans une sortie 'list')."""
    resultat: Dict[str, List[str]] = {}
    pool_courant: Optional[str] = None

    for ligne in texte.splitlines():
        brut = ligne.strip()
        m = RE_POOL.match(brut)
        if m:
            pool_courant = m.group(1)
            resultat.setdefault(pool_courant, [])
            continue
        if pool_courant is None:
            continue
        m = RE_MEMBRE_BLOC.match(brut)
        if m:
            resultat[pool_courant].append(m.group(1))
    return resultat


def parser_etat_membre(texte: str) -> Dict[str, Optional[str]]:
    """Extrait l'état d'UN membre depuis la sortie de 'show ... members'."""
    etat: Dict[str, Optional[str]] = {"disponibilite": None, "etat": None,
                                      "raison": None}
    for ligne in texte.splitlines():
        m = RE_CHAMP.match(ligne.strip())
        if not m:
            continue
        interne = cle_etat(m.group(1))
        if interne and etat[interne] is None:
            etat[interne] = m.group(2).strip()
    return etat


def recuperer_etat_membres(client: paramiko.SSHClient, shell: str,
                           membres_par_pool: Dict[str, List[str]]
                           ) -> Dict[str, List[Dict[str, Optional[str]]]]:
    """Interroge l'état de chaque membre, pool par pool.

    Une requête 'show' par membre : c'est la seule façon d'obtenir l'état
    individuel quand 'show ltm pool ... field-fmt' ne détaille pas les
    membres. Seuls les champs d'état sont conservés."""
    resultat: Dict[str, List[Dict[str, Optional[str]]]] = {}
    for pool, noms in membres_par_pool.items():
        resultat[pool] = []
        for nom in noms:
            commande = "show ltm pool {} members {{ {} {{ }} }} field-fmt" \
                .format(pool, nom)
            try:
                brut = executer_tmsh(client, commande, shell)
                etat = parser_etat_membre(brut)
            except RuntimeError:
                etat = {"disponibilite": None, "etat": None, "raison": None}
            resultat[pool].append({"membre": nom, **etat})
    return resultat


def assembler_pools(etat_pools: Dict[str, Dict[str, Optional[str]]],
                    membres: Dict[str, List[Dict[str, Optional[str]]]]
                    ) -> List[Dict[str, object]]:
    """Fusionne l'état des pools et la liste de leurs membres."""
    noms = list(etat_pools.keys())
    for nom in membres:
        if nom not in etat_pools:
            noms.append(nom)

    resultat: List[Dict[str, object]] = []
    for nom in noms:
        etat = etat_pools.get(nom, {})
        resultat.append({
            "nom": nom,
            "disponibilite": etat.get("disponibilite"),
            "etat": etat.get("etat"),
            "raison": etat.get("raison"),
            "membres": membres.get(nom, []),
        })
    return resultat


def ecrire_etat_virtuals(virtuals: List[Dict[str, Optional[str]]],
                         chemin: Path) -> None:
    """Écrit les statuts des VS dans un fichier texte lisible."""
    lignes: List[str] = []
    for vs in virtuals:
        lignes.append("ltm virtual {} {{".format(vs["nom"]))
        lignes.append("    destination {}".format(vs["destination"]))
        lignes.append("    status.availability-state {}".format(
            vs["disponibilite"]))
        lignes.append("    status.enabled-state {}".format(vs["etat"]))
        lignes.append("    status.status-reason {}".format(vs["raison"]))
        lignes.append("}")
    chemin.write_text("\n".join(lignes) + "\n", encoding="utf-8")


def ecrire_etat_pools(pools: List[Dict[str, object]], chemin: Path) -> None:
    """Écrit les statuts des pools et membres dans un fichier texte."""
    lignes: List[str] = []
    for pool in pools:
        lignes.append("ltm pool {} {{".format(pool["nom"]))
        lignes.append("    status.availability-state {}".format(
            pool["disponibilite"]))
        lignes.append("    status.enabled-state {}".format(pool["etat"]))
        for membre in pool["membres"]:  # type: ignore[union-attr]
            lignes.append("    member {} {{".format(membre["membre"]))
            lignes.append("        status.availability-state {}".format(
                membre["disponibilite"]))
            lignes.append("        status.enabled-state {}".format(
                membre["etat"]))
            lignes.append("        status.status-reason {}".format(
                membre["raison"]))
            lignes.append("    }")
        lignes.append("}")
    chemin.write_text("\n".join(lignes) + "\n", encoding="utf-8")


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
        brut_virtual = executer_tmsh(client, CMD_VIRTUAL, shell)
        brut_pool = executer_tmsh(client, CMD_POOL, shell)
        brut_config = executer_tmsh(client, CMD_POOL_CONFIG, shell)

        # Liste des membres (noms), puis état de chacun
        membres_par_pool = parser_config_membres(brut_config)
        membres = recuperer_etat_membres(client, shell, membres_par_pool)
    finally:
        client.close()

    virtuals = parser_virtuals(brut_virtual)
    etat_pools = parser_pools(brut_pool)
    pools = assembler_pools(etat_pools, membres)
    nb_membres = sum(len(p["membres"]) for p in pools)  # type: ignore[arg-type]

    ecrire_etat_virtuals(virtuals, dossier / "state_virtual.txt")
    ecrire_etat_pools(pools, dossier / "state_pool.txt")

    resume = {
        "label": label,
        "host": host,
        "phase": phase,
        "horodatage": horodatage,
        "shell": shell,
        "virtuals": virtuals,
        "pools": pools,
    }
    (dossier / "state_summary.json").write_text(
        json.dumps(resume, indent=2, ensure_ascii=False), encoding="utf-8")

    print("  Virtuals: {}  Pools: {}  Membres: {}".format(
        len(virtuals), len(pools), nb_membres))

    if pools and nb_membres == 0:
        print("  [AVERTISSEMENT] {} pool(s) trouvé(s) mais 0 membre : "
              "vérifie que les pools ont des membres configurés."
              .format(len(pools)))
    return dossier


# ------------------------------------------------------------------- Main

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture de l'état (VS, pools, membres) de BIG-IP.")
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
