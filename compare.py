#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compare_conf.py - Compare deux captures de configuration BIG-IP (before / after).

Compatible avec capture_conf.py : bigip.conf, bigip_base.conf,
partition_<nom>_bigip.conf et _meta.json.

Usage:
    python compare_conf.py <dossier_before> <dossier_after> [--show-secrets-hash]

Produit :
  - un affichage console coloré
  - un rapport Markdown : <dossier_after>/report_conf.md
Code retour : 0 = OK, 1 = au moins un DIFF/ALERT, 2 = erreur d'usage.

Niveaux :
  OK     identique
  INFO   modification attendue (upgrade, version, licence...)
  WARN   à vérifier (fichier absent d'un côté, capture incomplète...)
  DIFF   différence de configuration
  SKIP   ignoré
"""

import difflib
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------

# Types d'objets (deux premiers mots de l'en-tête) classés INFO :
# modifications attendues lors d'un upgrade.
EXPECTED_TYPES = {
    "sys software", "sys version", "sys license", "sys provision",
    "sys management-ovsdb", "sys folder", "sys db",
}

# Types ignorés (bruit, objets générés par le système).
IGNORED_TYPES = {
    "sys ucs", "sys log-config", "sys diags", "sys state-mirroring",
}

# Propriétés ignorées dans les blocs (horodatages, valeurs volatiles).
IGNORED_KEYS = {
    "creation-time", "last-modified-time", "updated-time",
    "last-modified", "mcpd-last-modified-time",
}

# Propriétés dont la valeur est masquée (comparaison par hash).
SECRET_KEYS = re.compile(
    r"(passphrase|secret|password|passwd|encrypted|private-key|"
    r"community|auth-password|priv-password|shared-secret|"
    r"bind-pw|admin-password|sso)",
    re.IGNORECASE,
)
SECRET_VALUE = re.compile(r"\$M\$\S+|\$1\$\S+|\$6\$\S+")

CONSOLE_MAX_DETAIL = 15

# ----------------------------------------------------------------------
# Couleurs console
# ----------------------------------------------------------------------
USE_COLOR = sys.stdout.isatty()
COLORS = {"OK": "32", "INFO": "36", "WARN": "33", "DIFF": "31",
          "ALERT": "1;31", "SKIP": "90"}


def color(level: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return "\033[{}m{}\033[0m".format(COLORS.get(level, "0"), text)


# ----------------------------------------------------------------------
# Résultats
# ----------------------------------------------------------------------
class Result:
    def __init__(self, name: str, level: str, summary: str,
                 details: Optional[List[str]] = None) -> None:
        self.name = name
        self.level = level
        self.summary = summary
        self.details = details or []


# ----------------------------------------------------------------------
# Secrets
# ----------------------------------------------------------------------
def _hash_court(valeur: str) -> str:
    return hashlib.sha256(valeur.encode("utf-8")).hexdigest()[:10]


def masquer(cle: str, valeur: str) -> str:
    """Remplace une valeur sensible par un hash court (comparable, non lisible)."""
    if SECRET_KEYS.search(cle) or SECRET_VALUE.search(valeur):
        return "[SECRET:{}]".format(_hash_court(valeur))
    return valeur


# ----------------------------------------------------------------------
# Parseur de fichiers .conf tmsh
# ----------------------------------------------------------------------
# Un objet de premier niveau : "ltm virtual /Common/vs1 {" ... "}"
# Le fichier est traité caractère par caractère pour gérer correctement :
#   - les accolades imbriquées,
#   - les chaînes entre guillemets (qui peuvent contenir { ou }),
#   - les commentaires (# ... jusqu'à fin de ligne, hors chaîne),
#   - les blocs multi-lignes (iRules : traités comme texte brut).

def _decouper_objets(texte: str) -> List[Tuple[str, str]]:
    """Retourne [(en-tête, corps)] pour chaque objet de premier niveau."""
    objets: List[Tuple[str, str]] = []
    i, n = 0, len(texte)
    debut_entete = 0
    while i < n:
        c = texte[i]
        if c == "{":
            entete = texte[debut_entete:i].strip()
            corps, fin = _lire_bloc(texte, i)
            if entete:
                objets.append((entete, corps))
            i = fin
            debut_entete = i
            continue
        if c == "\n":
            # Une ligne complète sans accolade (ex: "cm device-group x" isolé)
            # n'est pas un objet : on repart de la ligne suivante.
            ligne = texte[debut_entete:i].strip()
            if ligne and "{" not in ligne:
                debut_entete = i + 1
        i += 1
    return objets


def _lire_bloc(texte: str, pos_ouvrante: int) -> Tuple[str, int]:
    """Lit un bloc à partir de l'accolade ouvrante. Retourne (corps, index après la fermante)."""
    profondeur = 0
    i, n = pos_ouvrante, len(texte)
    en_chaine = False
    echappe = False
    while i < n:
        c = texte[i]
        if en_chaine:
            if echappe:
                echappe = False
            elif c == "\\":
                echappe = True
            elif c == '"':
                en_chaine = False
        else:
            if c == '"':
                en_chaine = True
            elif c == "{":
                profondeur += 1
            elif c == "}":
                profondeur -= 1
                if profondeur == 0:
                    return texte[pos_ouvrante + 1:i], i + 1
        i += 1
    # Bloc non fermé : on rend tout le reste (capture tronquée).
    return texte[pos_ouvrante + 1:], n


def _aplatir(corps: str, prefixe: str = "") -> Dict[str, str]:
    """Aplatit un corps de bloc en {chemin: valeur}. Les sous-blocs deviennent 'a/b/clé'."""
    resultat: Dict[str, str] = {}
    lignes = corps.splitlines()
    i = 0
    compteurs: Dict[str, int] = {}
    while i < len(lignes):
        brut = lignes[i]
        ligne = brut.strip()
        i += 1
        if not ligne or ligne.startswith("#"):
            continue

        # Sous-bloc : "nom {" (éventuellement "nom { }" sur une ligne)
        m_bloc = re.match(r"^(.+?)\s*\{\s*(\}?)\s*$", ligne)
        if m_bloc and not ligne.endswith("\\"):
            nom = m_bloc.group(1).strip()
            cle = prefixe + nom
            if m_bloc.group(2) == "}":
                resultat[cle] = "(vide)"
                continue
            # Rassemble les lignes jusqu'à l'accolade fermante correspondante.
            profondeur = 1
            sous: List[str] = []
            while i < len(lignes) and profondeur > 0:
                interne = lignes[i]
                i += 1
                profondeur += _delta_accolades(interne)
                if profondeur > 0:
                    sous.append(interne)
            texte_sous = "\n".join(sous)
            # Blocs de texte brut (iRules, définitions) : comparés tels quels.
            if nom in ("definition", "api-anonymous", "apply-to", "script"):
                resultat[cle] = _normaliser_texte(texte_sous)
            else:
                resultat.update(_aplatir(texte_sous, cle + "/"))
                if not texte_sous.strip():
                    resultat[cle] = "(vide)"
            continue

        # Propriété simple : "clé valeur..."
        parts = ligne.split(None, 1)
        cle_simple = parts[0]
        valeur = parts[1].strip() if len(parts) > 1 else "(défini)"
        if cle_simple in IGNORED_KEYS:
            continue
        cle_complete = prefixe + cle_simple
        # Clés répétées (rare) : on les numérote pour ne rien perdre.
        if cle_complete in resultat:
            compteurs[cle_complete] = compteurs.get(cle_complete, 1) + 1
            cle_complete = "{}#{}".format(cle_complete, compteurs[cle_complete])
        resultat[cle_complete] = masquer(cle_simple, valeur)
    return resultat


def _delta_accolades(ligne: str) -> int:
    """Variation de profondeur d'une ligne, en ignorant les accolades dans les chaînes."""
    delta = 0
    en_chaine = False
    echappe = False
    for c in ligne:
        if en_chaine:
            if echappe:
                echappe = False
            elif c == "\\":
                echappe = True
            elif c == '"':
                en_chaine = False
        else:
            if c == '"':
                en_chaine = True
            elif c == "{":
                delta += 1
            elif c == "}":
                delta -= 1
    return delta


def _normaliser_texte(texte: str) -> str:
    """Texte brut normalisé : retire les espaces de fin et les lignes vides extrêmes."""
    lignes = [ln.rstrip() for ln in texte.splitlines()]
    while lignes and not lignes[0]:
        lignes.pop(0)
    while lignes and not lignes[-1]:
        lignes.pop()
    return "\n".join(lignes)


def parser_conf(texte: str) -> Dict[str, Dict[str, str]]:
    """Retourne {identifiant objet: {propriété: valeur}}."""
    objets: Dict[str, Dict[str, str]] = {}
    for entete, corps in _decouper_objets(texte):
        mots = entete.split()
        if len(mots) < 2:
            continue
        # "ltm virtual /Common/vs1" -> type "ltm virtual", nom "/Common/vs1"
        # "sys ntp" (singleton) -> type "sys ntp", nom ""
        # Types à trois mots (ex: "ltm profile http X", "net route-domain X") :
        # on détecte le nom comme le dernier mot s'il commence par "/" ou s'il y a 3+ mots.
        if len(mots) >= 3:
            type_obj = " ".join(mots[:-1])
            nom = mots[-1]
        else:
            type_obj = " ".join(mots)
            nom = ""
        identifiant = "{} {}".format(type_obj, nom).strip()
        objets[identifiant] = _aplatir(corps)
    return objets


def type_de(identifiant: str) -> str:
    """Extrait le type d'objet ('ltm virtual', 'net vlan'...) d'un identifiant."""
    mots = identifiant.split()
    for i, mot in enumerate(mots):
        if mot.startswith("/"):
            return " ".join(mots[:i])
    return " ".join(mots[:2]) if len(mots) >= 2 else identifiant


# ----------------------------------------------------------------------
# Comparaison
# ----------------------------------------------------------------------
def _fmt(valeur: str, limite: int = 120) -> str:
    v = valeur.replace("\n", "\\n")
    return v if len(v) <= limite else v[:limite - 3] + "..."


def comparer_objets(avant: Dict[str, Dict[str, str]],
                    apres: Dict[str, Dict[str, str]]) -> Tuple[List[str], List[str], List[str]]:
    """Retourne (détails DIFF, détails INFO, types ignorés comptés)."""
    diff: List[str] = []
    info: List[str] = []
    for ident in sorted(set(avant) | set(apres)):
        type_obj = type_de(ident)
        if type_obj in IGNORED_TYPES:
            continue
        cible = info if type_obj in EXPECTED_TYPES else diff
        if ident not in avant:
            cible.append("+ objet nouveau : {}".format(ident))
            continue
        if ident not in apres:
            cible.append("- objet disparu : {}".format(ident))
            continue
        old, new = avant[ident], apres[ident]
        for cle in sorted(set(old) | set(new)):
            ov = old.get(cle)
            nv = new.get(cle)
            if ov == nv:
                continue
            if ov is None:
                cible.append("+ {} [{}] : {}".format(ident, cle, _fmt(nv or "")))
            elif nv is None:
                cible.append("- {} [{}] : {}".format(ident, cle, _fmt(ov)))
            else:
                cible.append("~ {} [{}] : {} -> {}".format(ident, cle, _fmt(ov), _fmt(nv)))
    return diff, info, []


def comparer_fichier(nom: str, avant_txt: str, apres_txt: str) -> List[Result]:
    avant = parser_conf(avant_txt)
    apres = parser_conf(apres_txt)

    if not avant and not apres:
        return [Result(nom, "WARN", "aucun objet détecté (fichier vide ou format inattendu)")]

    diff, info, _ = comparer_objets(avant, apres)
    resultats: List[Result] = []

    if not diff and not info:
        resultats.append(Result(nom, "OK", "{} objet(s), identiques".format(len(avant))))
        return resultats

    if diff:
        resultats.append(Result(nom, "DIFF", "{} changement(s)".format(len(diff)), diff))
    else:
        resultats.append(Result(nom, "OK", "{} objet(s), config applicative identique".format(len(avant))))
    if info:
        resultats.append(Result(nom + " (attendu)", "INFO",
                                "{} changement(s) attendu(s)".format(len(info)), info))
    return resultats


# ----------------------------------------------------------------------
# Intégrité des captures
# ----------------------------------------------------------------------
def lire_meta(dossier: Path) -> Optional[dict]:
    chemin = dossier / "_meta.json"
    if not chemin.exists():
        return None
    try:
        return json.loads(chemin.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def verifier_meta(avant: Path, apres: Path) -> List[Result]:
    resultats: List[Result] = []
    metas = {}
    for etiquette, dossier in (("before", avant), ("after", apres)):
        meta = lire_meta(dossier)
        metas[etiquette] = meta
        if meta is None:
            resultats.append(Result("_meta ({})".format(etiquette), "WARN",
                                    "_meta.json absent ou illisible : intégrité non vérifiable"))
            continue
        # Les clés exactes dépendent de capture_conf.py : on cherche tout résultat en erreur.
        fichiers = meta.get("files") or meta.get("results") or {}
        erreurs = [n for n, r in fichiers.items()
                   if isinstance(r, dict) and str(r.get("status", "OK")).upper() not in ("OK", "VIDE")]
        if erreurs:
            resultats.append(Result("_meta ({})".format(etiquette), "WARN",
                                    "capture incomplète : {}".format(", ".join(sorted(erreurs)))))

    if metas.get("before") and metas.get("after"):
        h_avant = metas["before"].get("host")
        h_apres = metas["after"].get("host")
        if h_avant and h_apres and h_avant != h_apres:
            resultats.append(Result("_meta (hôte)", "WARN",
                                    "hôtes différents : {} vs {}".format(h_avant, h_apres)))
    return resultats


# ----------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------
def lister_confs(dossier: Path) -> Dict[str, Path]:
    return {p.name: p for p in sorted(dossier.glob("*.conf"))}


def lire_texte(chemin: Path) -> str:
    return chemin.read_text(encoding="utf-8", errors="replace")


def run(avant: Path, apres: Path) -> List[Result]:
    confs_avant = lister_confs(avant)
    confs_apres = lister_confs(apres)
    resultats: List[Result] = []

    resultats.extend(verifier_meta(avant, apres))

    for nom in sorted(set(confs_avant) | set(confs_apres)):
        if nom not in confs_avant:
            resultats.append(Result(nom, "WARN", "absent dans before (partition nouvelle ?)"))
            continue
        if nom not in confs_apres:
            resultats.append(Result(nom, "DIFF", "absent dans after (partition supprimée ?)"))
            continue
        resultats.extend(comparer_fichier(nom, lire_texte(confs_avant[nom]),
                                          lire_texte(confs_apres[nom])))
    return resultats


# ----------------------------------------------------------------------
# Sorties
# ----------------------------------------------------------------------
def afficher_console(resultats: List[Result]) -> None:
    for r in resultats:
        print("{} {:<40} {}".format(color(r.level, "[{:<5}]".format(r.level)), r.name, r.summary))
        if r.details and r.level in ("DIFF", "WARN", "ALERT"):
            for d in r.details[:CONSOLE_MAX_DETAIL]:
                print("         {}".format(d))
            extra = len(r.details) - CONSOLE_MAX_DETAIL
            if extra > 0:
                print("         ... ({} de plus, voir le rapport)".format(extra))


def ecrire_rapport(resultats: List[Result], avant: Path, apres: Path, sortie: Path) -> None:
    compte = Counter(r.level for r in resultats)
    lignes = [
        "# Rapport de comparaison de configuration BIG-IP",
        "",
        "- **Before** : `{}`".format(avant),
        "- **After** : `{}`".format(apres),
        "",
        "> Comparaison de la configuration sauvegardée uniquement. "
        "L'état runtime (membres up/down, failover, statistiques) n'est pas couvert.",
        "> Les valeurs secrètes sont masquées (hash court) : un changement est détecté sans être affiché.",
        "",
        "## Synthèse",
        "",
        "| Niveau | Nombre |",
        "|---|---|",
    ]
    for niveau in ("ALERT", "DIFF", "WARN", "INFO", "OK", "SKIP"):
        lignes.append("| {} | {} |".format(niveau, compte.get(niveau, 0)))

    lignes += ["", "## Détail", "", "| Niveau | Élément | Résumé |", "|---|---|---|"]
    for r in resultats:
        lignes.append("| {} | {} | {} |".format(r.level, r.name, r.summary))

    for r in resultats:
        if r.details and r.level in ("ALERT", "DIFF", "WARN", "INFO"):
            lignes += ["", "### {} ({})".format(r.name, r.level), "", "```diff"]
            lignes += r.details
            lignes += ["```"]

    sortie.write_text("\n".join(lignes) + "\n", encoding="utf-8")


def main() -> int:
    args = sys.argv[1:]
    if len(args) != 2:
        print(__doc__)
        return 2

    avant, apres = Path(args[0]), Path(args[1])
    for dossier in (avant, apres):
        if not dossier.is_dir():
            print("Dossier introuvable : {}".format(dossier))
            return 2

    if not lister_confs(avant) or not lister_confs(apres):
        print("[ERREUR] Aucun fichier .conf trouvé dans l'un des dossiers "
              "(captures issues de capture_conf.py attendues).")
        return 2

    resultats = run(avant, apres)
    afficher_console(resultats)

    rapport = apres / "report_conf.md"
    ecrire_rapport(resultats, avant, apres, rapport)
    print("\nRapport : {}".format(rapport))

    return 1 if any(r.level in ("DIFF", "ALERT") for r in resultats) else 0


if __name__ == "__main__":
    sys.exit(main())
