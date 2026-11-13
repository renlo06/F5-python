#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Menu de lancement des scripts BIG-IP.

Scripts regroupés :
    1) capture_inventory.py  - Capture de l'inventaire (virtuals, pools, membres)
    2) capture_state.py      - Capture de l'état / des fichiers de configuration
    3) compare_inventory.py  - Comparaison d'inventaires (avant/après)
    4) compare_state.py      - Comparaison d'états (avant/après)
    5) health.py             - Relevé de santé (CPU, mémoire, connexions)
    6) upload.py             - Upload d'une ISO vers /shared/images/

Un fichier d'équipements (un par ligne, # = commentaire) peut être donné
avec -f ; il est alors transmis automatiquement aux scripts qui l'utilisent
(capture_inventory, capture_state, health, upload).

Usage:
    python menu.py
    python menu.py -f equipements.txt
    python menu.py -f equipements.txt --etat 1
"""

import argparse
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

DOSSIER = Path(__file__).resolve().parent

# (touche, fichier, description, utilise_hosts_file, utilise_etat, option_etat)
SCRIPTS: List[Tuple[str, str, str, bool, bool, str]] = [
    ("1", "capture_inventory.py", "Capture de l'inventaire (virtuals, pools, membres)", True,  True,  "--phase"),
    ("2", "capture_state.py",     "Capture de l'état / de la configuration",            True,  True,  "--phase"),
    ("3", "compare_inventory.py", "Comparaison d'inventaires (avant/après)",            False, False, ""),
    ("4", "compare_state.py",     "Comparaison d'états (avant/après)",                  False, False, ""),
    ("5", "health.py",            "Relevé de santé (CPU, mémoire, connexions)",         True,  True,  "--etat"),
    ("6", "upload.py",            "Upload d'une ISO vers /shared/images/",              True,  False, ""),
]

ETATS = {"1": "1", "before": "1", "b": "1", "avant": "1",
         "2": "2", "after": "2", "a": "2", "apres": "2", "après": "2"}
LIBELLE_ETAT = {"1": "before", "2": "after"}


def lire_fichier_equipements(chemin: Path) -> List[str]:
    """Lit un fichier d'équipements (un par ligne, # = commentaire)."""
    lignes = []
    for brut in chemin.read_text(encoding="utf-8").splitlines():
        ligne = brut.strip()
        if ligne and not ligne.startswith("#"):
            lignes.append(ligne)
    return lignes


def verifier_fichier(chemin_txt: str) -> Optional[Path]:
    """Retourne le chemin absolu si le fichier est valide, sinon None."""
    chemin = Path(chemin_txt).expanduser()
    if not chemin.is_file():
        print("[ERREUR] Fichier d'équipements introuvable : {}".format(chemin),
              file=sys.stderr)
        return None
    try:
        equipements = lire_fichier_equipements(chemin)
    except (OSError, UnicodeDecodeError) as exc:
        print("[ERREUR] Lecture impossible : {}".format(exc), file=sys.stderr)
        return None
    if not equipements:
        print("[ERREUR] Aucun équipement dans {}".format(chemin), file=sys.stderr)
        return None
    return chemin.resolve()


def afficher_menu(hosts_file: Optional[Path], etat: Optional[str]) -> None:
    print()
    print("=" * 66)
    print("                    MENU SCRIPTS BIG-IP")
    print("=" * 66)
    if hosts_file:
        try:
            nombre = len(lire_fichier_equipements(hosts_file))
        except (OSError, UnicodeDecodeError):
            nombre = 0
        print("  Équipements : {} ({} entrée(s))".format(hosts_file, nombre))
    else:
        print("  Équipements : (aucun fichier, saisie par script)")
    print("  État        : {}".format(
        "{} ({})".format(etat, LIBELLE_ETAT[etat]) if etat else "(demandé par chaque script)"))
    print("-" * 66)
    for touche, fichier, description, utilise_hosts, _, _ in SCRIPTS:
        notes = []
        if not (DOSSIER / fichier).is_file():
            notes.append("introuvable")
        if utilise_hosts and hosts_file:
            notes.append("-f auto")
        suffixe = "  [{}]".format(", ".join(notes)) if notes else ""
        print("  {}) {:<22} {}{}".format(touche, fichier, description, suffixe))
    print("  f) Changer le fichier d'équipements")
    print("  e) Définir l'état (1 = before, 2 = after)")
    print("  q) Quitter")
    print("-" * 66)


def demander_arguments(fichier: str) -> List[str]:
    """Permet d'ajouter des arguments supplémentaires."""
    print("Arguments supplémentaires pour {} (Entrée = aucun)".format(fichier))
    try:
        saisie = input("Arguments > ").strip()
    except EOFError:
        return []
    if not saisie:
        return []
    try:
        return shlex.split(saisie)
    except ValueError as exc:
        print("Arguments invalides ({}), ignorés.".format(exc), file=sys.stderr)
        return []


def construire_commande(entree: Tuple[str, str, str, bool, bool, str],
                        hosts_file: Optional[Path], etat: Optional[str],
                        extra: List[str]) -> List[str]:
    _, fichier, _, utilise_hosts, utilise_etat, option_etat = entree
    commande = [sys.executable, str(DOSSIER / fichier)]
    # On n'injecte pas une option déjà fournie manuellement dans les extras.
    if utilise_hosts and hosts_file and not any(
            a in ("-f", "--hosts-file") for a in extra):
        commande += ["-f", str(hosts_file)]
    if utilise_etat and etat and option_etat and option_etat not in extra:
        commande += [option_etat, etat]
    return commande + extra


def lancer(entree: Tuple[str, str, str, bool, bool, str],
           hosts_file: Optional[Path], etat: Optional[str]) -> None:
    fichier = entree[1]
    chemin = DOSSIER / fichier
    if not chemin.is_file():
        print("[ERREUR] Script introuvable : {}".format(chemin), file=sys.stderr)
        return
    extra = demander_arguments(fichier)
    commande = construire_commande(entree, hosts_file, etat, extra)
    print()
    print(">>> {}".format(" ".join(shlex.quote(c) for c in commande)))
    print("-" * 66)
    try:
        code = subprocess.call(commande, cwd=str(DOSSIER))
    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur.", file=sys.stderr)
        return
    except OSError as exc:
        print("[ERREUR] Lancement impossible : {}".format(exc), file=sys.stderr)
        return
    print("-" * 66)
    if code == 0:
        print("[OK] {} terminé (code 0).".format(fichier))
    else:
        print("[ATTENTION] {} terminé avec le code {}.".format(fichier, code))


def choisir_etat() -> Optional[str]:
    reponse = input("État (1 = before, 2 = after, Entrée = redemander à chaque script) : ")
    reponse = reponse.strip().lower()
    if not reponse:
        return None
    if reponse in ETATS:
        return ETATS[reponse]
    print("Réponse invalide : {!r}".format(reponse), file=sys.stderr)
    return None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Menu de lancement des scripts BIG-IP.")
    parser.add_argument("-f", "--hosts-file", dest="hosts_file",
                        help="Fichier d'équipements transmis aux scripts concernés")
    parser.add_argument("--etat", choices=sorted(ETATS),
                        help="État partagé : 1/before ou 2/after")
    return parser


def main() -> int:
    args = _parser().parse_args()

    hosts_file: Optional[Path] = None
    if args.hosts_file:
        hosts_file = verifier_fichier(args.hosts_file)
        if hosts_file is None:
            return 2
    etat: Optional[str] = ETATS[args.etat] if args.etat else None

    par_touche = {e[0]: e for e in SCRIPTS}
    while True:
        afficher_menu(hosts_file, etat)
        try:
            choix = input("Votre choix : ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choix in ("q", "quit", "exit", "0"):
            print("Au revoir.")
            return 0
        if choix == "f":
            saisie = input("Chemin du fichier d'équipements (Entrée = aucun) : ").strip()
            if not saisie:
                hosts_file = None
            else:
                nouveau = verifier_fichier(saisie)
                if nouveau is not None:
                    hosts_file = nouveau
            continue
        if choix == "e":
            etat = choisir_etat()
            continue
        entree = par_touche.get(choix)
        if entree is None:
            print("Choix invalide : {!r}".format(choix), file=sys.stderr)
            continue
        lancer(entree, hosts_file, etat)
        try:
            input("\nAppuyer sur Entrée pour revenir au menu...")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0


if __name__ == "__main__":
    sys.exit(main())
