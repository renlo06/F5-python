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

Les scripts doivent se trouver dans le même dossier que menu.py.
Chaque script est lancé tel quel : il pose lui-même ses questions
(état before/after, login, mot de passe...).

Usage:
    python menu.py
"""

import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

DOSSIER = Path(__file__).resolve().parent

# (touche, fichier, description)
SCRIPTS: List[Tuple[str, str, str]] = [
    ("1", "capture_inventory.py", "Capture de l'inventaire (virtuals, pools, membres)"),
    ("2", "capture_state.py",     "Capture de l'état / de la configuration"),
    ("3", "compare_inventory.py", "Comparaison d'inventaires (avant/après)"),
    ("4", "compare_state.py",     "Comparaison d'états (avant/après)"),
    ("5", "health.py",            "Relevé de santé (CPU, mémoire, connexions)"),
    ("6", "upload.py",            "Upload d'une ISO vers /shared/images/"),
]


def afficher_menu() -> None:
    print()
    print("=" * 62)
    print("                 MENU SCRIPTS BIG-IP")
    print("=" * 62)
    for touche, fichier, description in SCRIPTS:
        present = (DOSSIER / fichier).is_file()
        marque = "" if present else "  [introuvable]"
        print("  {}) {:<22} {}{}".format(touche, fichier, description, marque))
    print("  q) Quitter")
    print("-" * 62)


def demander_arguments(fichier: str) -> List[str]:
    """Permet d'ajouter des arguments (ex: -f hosts.txt --etat 1)."""
    print("Arguments pour {} (Entrée = aucun ; ex : -f hosts.txt)".format(fichier))
    try:
        saisie = input("Arguments > ").strip()
    except EOFError:
        return []
    if not saisie:
        return []
    try:
        return shlex.split(saisie)
    except ValueError as exc:
        print("Arguments invalides ({}), lancement sans argument.".format(exc),
              file=sys.stderr)
        return []


def lancer(fichier: str) -> None:
    chemin = DOSSIER / fichier
    if not chemin.is_file():
        print("[ERREUR] Script introuvable : {}".format(chemin), file=sys.stderr)
        return
    arguments = demander_arguments(fichier)
    commande = [sys.executable, str(chemin)] + arguments
    print()
    print(">>> {}".format(" ".join(shlex.quote(c) for c in commande)))
    print("-" * 62)
    try:
        code = subprocess.call(commande, cwd=str(DOSSIER))
    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur.", file=sys.stderr)
        return
    except OSError as exc:
        print("[ERREUR] Lancement impossible : {}".format(exc), file=sys.stderr)
        return
    print("-" * 62)
    if code == 0:
        print("[OK] {} terminé (code 0).".format(fichier))
    else:
        print("[ATTENTION] {} terminé avec le code {}.".format(fichier, code))


def main() -> int:
    choix_valides = {touche: fichier for touche, fichier, _ in SCRIPTS}
    while True:
        afficher_menu()
        try:
            choix = input("Votre choix : ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choix in ("q", "quit", "exit", "0"):
            print("Au revoir.")
            return 0
        fichier = choix_valides.get(choix)
        if fichier is None:
            print("Choix invalide : {!r}".format(choix), file=sys.stderr)
            continue
        lancer(fichier)
        try:
            input("\nAppuyer sur Entrée pour revenir au menu...")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0


if __name__ == "__main__":
    sys.exit(main())
