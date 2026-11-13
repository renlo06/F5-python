#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Relevé en lecture seule de l'état runtime BIG-IP : virtual servers, pools, membres.

Fichiers produits (dossier captures/<label>_<phase>_<horodatage>/) :
    state_virtual.txt      show ltm virtual field-fmt
    state_pool.txt         show ltm pool members field-fmt
    state_node.txt         show ltm node field-fmt
    state_summary.json     synthèse parsée (états stables uniquement)
    _meta_state.json       métadonnées (shell, durées, tailles, SHA256)

Usage:
    python capture_state.py --host 10.0.0.11 --label bigip-a [--phase before|after]
    python capture_state.py -f equipements.txt [--phase before|after]
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

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------
SORTIE_RACINE = Path("captures")
TIMEOUT_CONNEXION = 15
TIMEOUT_COMMANDE = 120

# Commandes tmsh en lecture seule uniquement.
COMMANDES = [
    ("state_virtual", "show ltm virtual field-fmt"),
    ("state_pool", "show ltm pool members field-fmt"),
    ("state_node", "show ltm node field-fmt"),
]

# Champs d'état stables conservés dans le résumé (les compteurs sont écartés).
CHAMPS_ETAT = {
    "status.availability-state": "disponibilite",
    "status.enabled-state": "active",
    "status.status-reason": "raison",
    "monitor-status": "monitor",
    "session-status": "session",
    "addr": "adresse",
    "destination": "destination",
}


# ----------------------------------------------------------------------
# SSH
# ----------------------------------------------------------------------
class Connexion:
    """Connexion SSH avec détection du shell (tmsh ou bash) et exécution tmsh."""

    def __init__(self, host: str, user: str, password: str, port: int = 22) -> None:
        self.host = host
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.client.load_system_host_keys()
        self.client.connect(
            host, port=port, username=user, password=password,
            timeout=TIMEOUT_CONNEXION, banner_timeout=TIMEOUT_CONNEXION,
            auth_timeout=TIMEOUT_CONNEXION, look_for_keys=False, allow_agent=False,
        )
        self.shell = self._detecter_shell()

    def _brut(self, commande: str) -> Tuple[str, str, int]:
        _in, out, err = self.client.exec_command(commande, timeout=TIMEOUT_COMMANDE)
        sortie = out.read().decode("utf-8", errors="replace")
        erreur = err.read().decode("utf-8", errors="replace")
        return sortie, erreur, out.channel.recv_exit_status()

    def _detecter_shell(self) -> str:
        sortie, _err, _rc = self._brut("echo $0")
        return "tmsh" if "tmsh" in sortie.lower() else "bash"

    def tmsh(self, commande: str) -> Tuple[str, str, int]:
        """Exécute une commande tmsh quel que soit le shell de connexion."""
        if self.shell == "tmsh":
            return self._brut(commande)
        return self._brut("tmsh -q {}".format(commande))

    def fermer(self) -> None:
        self.client.close()


# ----------------------------------------------------------------------
# Parsing du format field-fmt
# ----------------------------------------------------------------------
# Exemple (virtual) :
#   ltm virtual /Common/vs1 {
#       destination /Common/10.0.0.1:443
#       status.availability-state available
#       status.enabled-state enabled
#       status.status-reason The virtual server is available
#       ...
#   }
#
# Exemple (pool members) :
#   ltm pool /Common/pool1 {
#       members {
#           /Common/10.0.0.5:80 {
#               addr 10.0.0.5
#               status.availability-state offline
#               ...
#           }
#       }
#       status.availability-state ...
#   }

def _delta(ligne: str) -> int:
    return ligne.count("{") - ligne.count("}")


def parser_objets(texte: str, type_objet: str) -> Dict[str, Dict[str, object]]:
    """Retourne {nom: {champs d'état, 'membres': {nom_membre: {...}}}}."""
    entete = re.compile(r"^\s*ltm\s+{}\s+(\S+)\s*\{{\s*$".format(re.escape(type_objet)))
    objets: Dict[str, Dict[str, object]] = {}
    courant: Optional[str] = None
    profondeur = 0
    pile: List[str] = []
    membre: Optional[str] = None

    for ligne in texte.splitlines():
        brut = ligne.strip()
        if courant is None:
            m = entete.match(ligne)
            if m:
                courant = m.group(1)
                objets[courant] = {"membres": {}}
                profondeur = 1
                pile = []
                membre = None
            continue

        # Ouverture de sous-bloc : "members {" ou "/Common/x:80 {"
        m_bloc = re.match(r"^([^\s{}]+)\s*\{\s*$", brut)
        if m_bloc:
            nom = m_bloc.group(1)
            pile.append(nom)
            if len(pile) == 2 and pile[0] == "members":
                membre = nom
                objets[courant]["membres"].setdefault(membre, {})  # type: ignore[union-attr]
            profondeur += 1
            continue

        if brut == "}":
            profondeur -= 1
            if pile:
                pile.pop()
                if len(pile) < 2:
                    membre = None
            if profondeur <= 0:
                courant = None
            continue

        # Ligne "clé valeur"
        parts = brut.split(None, 1)
        if len(parts) != 2:
            continue
        cle, valeur = parts[0], parts[1].strip()
        if cle not in CHAMPS_ETAT:
            continue
        champ = CHAMPS_ETAT[cle]
        if membre is not None and len(pile) == 2:
            objets[courant]["membres"][membre][champ] = valeur  # type: ignore[index]
        elif not pile:
            objets[courant][champ] = valeur

    return objets


def parser_noeuds(texte: str) -> Dict[str, Dict[str, object]]:
    return parser_objets(texte, "node")


# ----------------------------------------------------------------------
# Capture d'un équipement
# ----------------------------------------------------------------------
def sha256_texte(texte: str) -> str:
    return hashlib.sha256(texte.encode("utf-8")).hexdigest()


def capturer(host: str, label: str, phase: str, user: str, password: str) -> bool:
    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    dossier = SORTIE_RACINE / "{}_{}_{}".format(label, phase, horodatage)
    dossier.mkdir(parents=True, exist_ok=True)

    print("\n=== {} ({}) [{}] ===".format(label, host, phase))
    debut = time.time()
    try:
        cnx = Connexion(host, user, password)
    except Exception as exc:
        print("[ERREUR] Connexion SSH impossible : {}".format(exc))
        return False

    meta: Dict[str, object] = {
        "host": host, "label": label, "phase": phase,
        "horodatage": horodatage, "shell": cnx.shell, "files": {},
    }
    ok_global = True
    bruts: Dict[str, str] = {}

    try:
        for nom, commande in COMMANDES:
            t0 = time.time()
            sortie, erreur, rc = cnx.tmsh(commande)
            duree = round(time.time() - t0, 2)
            fichier = dossier / "{}.txt".format(nom)

            if rc != 0 or not sortie.strip():
                message = (erreur.strip() or "sortie vide")[:200]
                # Sortie vide sans erreur : peut être légitime (aucun objet) mais à signaler.
                statut = "VIDE" if rc == 0 else "ERREUR"
                print("[{}] {:<14} {}".format(
                    "AVERT" if statut == "VIDE" else "ERREUR", nom, message))
                if statut == "ERREUR":
                    ok_global = False
                fichier.write_text(sortie, encoding="utf-8")
                meta["files"][nom] = {  # type: ignore[index]
                    "status": statut, "bytes": len(sortie.encode("utf-8")),
                    "seconds": duree, "message": message,
                }
                bruts[nom] = sortie
                continue

            fichier.write_text(sortie, encoding="utf-8")
            bruts[nom] = sortie
            meta["files"][nom] = {  # type: ignore[index]
                "status": "OK", "bytes": len(sortie.encode("utf-8")),
                "sha256": sha256_texte(sortie), "seconds": duree,
            }
            print("[OK    ] {:<14} {} octets ({} s)".format(
                nom, len(sortie.encode("utf-8")), duree))
    finally:
        cnx.fermer()

    # Résumé parsé : uniquement les états stables.
    resume = {
        "virtual": parser_objets(bruts.get("state_virtual", ""), "virtual"),
        "pool": parser_objets(bruts.get("state_pool", ""), "pool"),
        "node": parser_noeuds(bruts.get("state_node", "")),
    }
    nb_vs, nb_pool = len(resume["virtual"]), len(resume["pool"])
    nb_membres = sum(len(p.get("membres", {})) for p in resume["pool"].values())  # type: ignore[union-attr]

    if nb_vs == 0 and nb_pool == 0:
        print("[AVERT ] Aucun virtual server ni pool détecté "
              "(équipement sans objets, ou format de sortie inattendu).")
        meta["parsing"] = "AUCUN_OBJET"
    else:
        print("[OK    ] Résumé : {} VS, {} pool(s), {} membre(s)".format(
            nb_vs, nb_pool, nb_membres))
        meta["parsing"] = "OK"

    (dossier / "state_summary.json").write_text(
        json.dumps(resume, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8")
    meta["summary"] = {"virtual": nb_vs, "pool": nb_pool, "members": nb_membres}
    meta["duree_totale_s"] = round(time.time() - debut, 2)

    (dossier / "_meta_state.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Dossier : {}".format(dossier))
    return ok_global


# ----------------------------------------------------------------------
# Entrée
# ----------------------------------------------------------------------
def lire_equipements(chemin: Path) -> List[Tuple[str, str]]:
    """Lit un fichier 'hote;label' (une ligne par équipement, # = commentaire)."""
    equipements: List[Tuple[str, str]] = []
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#"):
            continue
        parts = [p.strip() for p in re.split(r"[;,\s]+", ligne) if p.strip()]
        hote = parts[0]
        label = parts[1] if len(parts) > 1 else hote
        equipements.append((hote, label))
    return equipements


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", help="adresse de l'équipement")
    parser.add_argument("--label", help="nom de l'équipement (dossier de sortie)")
    parser.add_argument("-f", "--file", help="fichier d'équipements (hote;label)")
    parser.add_argument("--phase", choices=("before", "after"), default="before")
    parser.add_argument("--user", default=os.environ.get("BIGIP_USER"))
    args = parser.parse_args()

    if args.file:
        equipements = lire_equipements(Path(args.file))
    elif args.host:
        equipements = [(args.host, args.label or args.host)]
    else:
        parser.print_help()
        return 2

    if not equipements:
        print("[ERREUR] Aucun équipement à traiter.")
        return 2

    utilisateur = args.user or input("Utilisateur SSH : ").strip()
    mot_de_passe = os.environ.get("BIGIP_PASSWORD") or getpass.getpass("Mot de passe : ")

    bilan: List[Tuple[str, bool]] = []
    for hote, label in equipements:
        try:
            ok = capturer(hote, label, args.phase, utilisateur, mot_de_passe)
        except Exception as exc:  # une erreur sur un équipement n'arrête pas les autres
            print("[ERREUR] {} : {}".format(label, exc))
            ok = False
        bilan.append((label, ok))

    if len(bilan) > 1:
        print("\n=== Récapitulatif ({}) ===".format(args.phase))
        for label, ok in bilan:
            print("[{}] {}".format("OK    " if ok else "ERREUR", label))

    return 0 if all(ok for _l, ok in bilan) else 1


if __name__ == "__main__":
    sys.exit(main())
