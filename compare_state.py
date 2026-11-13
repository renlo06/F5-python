#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comparaison de deux relevés d'état runtime BIG-IP (before / after).

Compare state_summary.json produit par capture_state.py :
    - virtual servers (disponibilité, état, raison, destination)
    - pools (disponibilité, état)
    - membres de pool (apparition, disparition, disponibilité, état, raison)
    - nodes (disponibilité, état, raison, adresse)

Usage:
    python compare_state.py --label bigip-a [--captures captures]
    python compare_state.py --before captures/bigip-a_before_... --after captures/bigip-a_after_...
    python compare_state.py -f equipements.txt [--captures captures]

Options:
    --ignore-raison   ignore les changements du champ "raison" (souvent bavard)
    --rapport FICHIER écrit aussi le rapport dans un fichier texte
    --json FICHIER    écrit les différences au format JSON

Code retour : 0 = identique, 1 = différences, 2 = erreur d'utilisation.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPERTOIRE_CAPTURES = "captures"

# Champs comparés par catégorie
CHAMPS_VIRTUAL = ["destination", "disponibilite", "etat", "raison"]
CHAMPS_POOL = ["disponibilite", "etat"]
CHAMPS_MEMBRE = ["disponibilite", "etat", "raison"]
CHAMPS_NODE = ["adresse", "disponibilite", "etat", "raison"]

# Un "changement" : (objet, champ, avant, après)
Changement = Tuple[str, str, Optional[str], Optional[str]]


# --------------------------------------------------------------------------- #
# Chargement
# --------------------------------------------------------------------------- #

def trouver_dernier_dossier(racine: Path, label: str, phase: str) -> Optional[Path]:
    """Dernier dossier <label>_<phase>_<horodatage> (tri lexicographique = chronologique)."""
    candidats = sorted(p for p in racine.glob("{}_{}_*".format(label, phase)) if p.is_dir())
    return candidats[-1] if candidats else None


def charger_synthese(dossier: Path) -> Dict[str, list]:
    fichier = dossier / "state_summary.json"
    if not fichier.is_file():
        raise FileNotFoundError("state_summary.json introuvable dans {}".format(dossier))
    with open(fichier, "r", encoding="utf-8") as f:
        return json.load(f)


def lire_fichier_equipements(chemin: str) -> List[Tuple[str, str]]:
    equipements: List[Tuple[str, str]] = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            ligne = ligne.split("#", 1)[0].strip()
            if not ligne:
                continue
            parties = ligne.split()
            hote = parties[0]
            label = parties[1] if len(parties) > 1 else hote
            equipements.append((hote, label))
    return equipements


# --------------------------------------------------------------------------- #
# Comparaison
# --------------------------------------------------------------------------- #

def indexer(objets: List[dict]) -> Dict[str, dict]:
    return {o["nom"]: o for o in objets}


def comparer_champs(nom: str, avant: dict, apres: dict, champs: List[str],
                    ignorer_raison: bool, prefixe: str = "") -> List[Changement]:
    changements: List[Changement] = []
    for champ in champs:
        if ignorer_raison and champ == "raison":
            continue
        v_avant = avant.get(champ)
        v_apres = apres.get(champ)
        if v_avant != v_apres:
            changements.append((prefixe + nom, champ, v_avant, v_apres))
    return changements


def comparer_simple(avant: List[dict], apres: List[dict], champs: List[str],
                    ignorer_raison: bool) -> Tuple[List[str], List[str], List[Changement]]:
    """Compare des objets sans sous-objets (virtuals, nodes).
    Retourne (ajoutés, supprimés, changements)."""
    idx_avant, idx_apres = indexer(avant), indexer(apres)
    ajoutes = sorted(set(idx_apres) - set(idx_avant))
    supprimes = sorted(set(idx_avant) - set(idx_apres))
    changements: List[Changement] = []
    for nom in sorted(set(idx_avant) & set(idx_apres)):
        changements += comparer_champs(nom, idx_avant[nom], idx_apres[nom], champs, ignorer_raison)
    return ajoutes, supprimes, changements


def comparer_pools(avant: List[dict], apres: List[dict], ignorer_raison: bool):
    """Compare pools et membres.
    Retourne (pools ajoutés, pools supprimés, changements pools,
              membres ajoutés, membres supprimés, changements membres)."""
    idx_avant, idx_apres = indexer(avant), indexer(apres)
    pools_ajoutes = sorted(set(idx_apres) - set(idx_avant))
    pools_supprimes = sorted(set(idx_avant) - set(idx_apres))

    chg_pools: List[Changement] = []
    membres_ajoutes: List[str] = []
    membres_supprimes: List[str] = []
    chg_membres: List[Changement] = []

    for nom in sorted(set(idx_avant) & set(idx_apres)):
        p_avant, p_apres = idx_avant[nom], idx_apres[nom]
        chg_pools += comparer_champs(nom, p_avant, p_apres, CHAMPS_POOL, ignorer_raison)

        m_avant = {m["membre"]: m for m in p_avant.get("membres", [])}
        m_apres = {m["membre"]: m for m in p_apres.get("membres", [])}
        for m in sorted(set(m_apres) - set(m_avant)):
            membres_ajoutes.append("{} / {}".format(nom, m))
        for m in sorted(set(m_avant) - set(m_apres)):
            membres_supprimes.append("{} / {}".format(nom, m))
        for m in sorted(set(m_avant) & set(m_apres)):
            chg_membres += comparer_champs(
                m, m_avant[m], m_apres[m], CHAMPS_MEMBRE, ignorer_raison,
                prefixe="{} / ".format(nom))

    return pools_ajoutes, pools_supprimes, chg_pools, membres_ajoutes, membres_supprimes, chg_membres


# --------------------------------------------------------------------------- #
# Rapport
# --------------------------------------------------------------------------- #

def _valeur(v: Optional[str]) -> str:
    return "-" if v is None else v


def ecrire_categorie(lignes: List[str], nom: str, ajoutes: List[str],
                     supprimes: List[str], changements: List[Changement]) -> int:
    """Ajoute le bloc d'une catégorie au rapport. Retourne le nombre de différences."""
    total = len(ajoutes) + len(supprimes) + len(changements)
    if total == 0:
        lignes.append("[OK   ] {:<18} identique".format(nom))
        return 0
    lignes.append("[DIFF ] {:<18} {} changement(s) d'état".format(nom, total))
    for o in ajoutes:
        lignes.append("         + {} : apparu".format(o))
    for o in supprimes:
        lignes.append("         - {} : disparu".format(o))
    for objet, champ, avant, apres in changements:
        lignes.append("         ~ {} [{}] : {} -> {}".format(objet, champ, _valeur(avant), _valeur(apres)))
    return total


def comparer_equipement(label: str, dossier_avant: Path, dossier_apres: Path,
                        ignorer_raison: bool) -> Tuple[List[str], int, dict]:
    """Retourne (lignes du rapport, nombre total de différences, données JSON)."""
    avant = charger_synthese(dossier_avant)
    apres = charger_synthese(dossier_apres)

    lignes = [
        "=== {} ===".format(label),
        "  before : {}".format(dossier_avant.name),
        "  after  : {}".format(dossier_apres.name),
        "",
    ]
    total = 0
    detail: Dict[str, dict] = {}

    # Virtual servers
    aj, su, ch = comparer_simple(avant.get("virtuals", []), apres.get("virtuals", []),
                                 CHAMPS_VIRTUAL, ignorer_raison)
    total += ecrire_categorie(lignes, "ltm_virtual", aj, su, ch)
    detail["virtuals"] = {"ajoutes": aj, "supprimes": su, "changements": ch}

    # Pools et membres
    p_aj, p_su, p_ch, m_aj, m_su, m_ch = comparer_pools(
        avant.get("pools", []), apres.get("pools", []), ignorer_raison)
    total += ecrire_categorie(lignes, "ltm_pool", p_aj, p_su, p_ch)
    total += ecrire_categorie(lignes, "ltm_pool_member", m_aj, m_su, m_ch)
    detail["pools"] = {"ajoutes": p_aj, "supprimes": p_su, "changements": p_ch}
    detail["membres"] = {"ajoutes": m_aj, "supprimes": m_su, "changements": m_ch}

    # Nodes
    aj, su, ch = comparer_simple(avant.get("nodes", []), apres.get("nodes", []),
                                 CHAMPS_NODE, ignorer_raison)
    total += ecrire_categorie(lignes, "ltm_node", aj, su, ch)
    detail["nodes"] = {"ajoutes": aj, "supprimes": su, "changements": ch}

    lignes.append("")
    lignes.append("Total : {} différence(s)".format(total))
    return lignes, total, detail


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(description="Comparaison d'état runtime BIG-IP (before / after)")
    parser.add_argument("--label", help="Label de l'équipement (cherche les derniers dossiers before/after)")
    parser.add_argument("-f", "--file", help="Fichier listant les équipements")
    parser.add_argument("--before", help="Dossier de capture 'before' (mode manuel)")
    parser.add_argument("--after", help="Dossier de capture 'after' (mode manuel)")
    parser.add_argument("--captures", default=REPERTOIRE_CAPTURES, help="Répertoire des captures")
    parser.add_argument("--ignore-raison", action="store_true",
                        help="Ignorer les changements du champ 'raison'")
    parser.add_argument("--rapport", help="Écrire le rapport dans ce fichier texte")
    parser.add_argument("--json", dest="fichier_json", help="Écrire les différences dans ce fichier JSON")
    args = parser.parse_args()

    racine = Path(args.captures)

    # Liste des paires (label, dossier before, dossier after)
    paires: List[Tuple[str, Path, Path]] = []
    if args.before and args.after:
        paires.append((args.label or Path(args.before).name, Path(args.before), Path(args.after)))
    else:
        if args.file:
            labels = [label for _hote, label in lire_fichier_equipements(args.file)]
        elif args.label:
            labels = [args.label]
        else:
            parser.error("Indiquer --label, -f, ou --before et --after")
            return 2
        for label in labels:
            d_avant = trouver_dernier_dossier(racine, label, "before")
            d_apres = trouver_dernier_dossier(racine, label, "after")
            if d_avant is None or d_apres is None:
                print("[ERREUR] {} : capture before et/ou after introuvable dans {}".format(label, racine))
                return 2
            paires.append((label, d_avant, d_apres))

    toutes_lignes: List[str] = []
    resultats_json: Dict[str, dict] = {}
    total_global = 0

    for label, d_avant, d_apres in paires:
        try:
            lignes, total, detail = comparer_equipement(label, d_avant, d_apres, args.ignore_raison)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            print("[ERREUR] {} : {}".format(label, exc))
            return 2
        toutes_lignes += lignes + [""]
        resultats_json[label] = {"total": total, **detail}
        total_global += total

    rapport = "\n".join(toutes_lignes)
    print(rapport)

    if args.rapport:
        Path(args.rapport).write_text(rapport + "\n", encoding="utf-8")
        print("Rapport écrit : {}".format(args.rapport))
    if args.fichier_json:
        Path(args.fichier_json).write_text(
            json.dumps(resultats_json, indent=2, ensure_ascii=False), encoding="utf-8")
        print("JSON écrit    : {}".format(args.fichier_json))

    return 0 if total_global == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
