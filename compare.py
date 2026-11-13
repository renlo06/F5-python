#!/usr/bin/env python3
"""
compare.py - Compare deux captures BIG-IP (before / after).

Usage:
    python compare.py <dossier_before> <dossier_after> [--ltm-strict]

Options:
    --ltm-strict   un changement d'inventaire LTM (VS / pools / membres)
                   est traité comme DIFF (code retour 1) au lieu d'INFO.

Produit :
  - un affichage console coloré
  - un rapport Markdown : <dossier_after>/report.md
Code retour : 0 = OK, 1 = au moins un DIFF/ALERT, 2 = erreur d'usage.

Niveaux :
  OK     identique
  INFO   modification attendue (upgrade), stats expliquées par la config,
         ou changement d'inventaire LTM (hors --ltm-strict)
  WARN   à vérifier (fichier absent, non classé, inchangé alors qu'attendu...)
  DIFF   différence de configuration
  ALERT  changement d'état INEXPLIQUÉ par la config (signal à investiguer)
  SKIP   ignoré
"""

import difflib
import re
import sys
from collections import Counter
from pathlib import Path

from inventory import diff_inventory_dirs

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------

# Fichiers ignorés (bruit ou obsolètes)
IGNORE = {"failover", "ucs_list", "disk", "ltm_all_properties", "_ucs_creation"}

# Attendus différents après upgrade : affichés en INFO
EXPECTED_DIFF = {"version", "software"}

# Diff brut : toute différence est une alerte
RAW_DIFF = {
    "ltm_rule", "ltm_profile", "ltm_monitor", "vlan", "self_ip",
    "route", "trunk", "dns", "ntp", "snmp", "syslog", "device",
    "hardware", "license", "provision", "certs", "ha_status",
    "keys",
}

# Préfixes traités en diff brut (fichiers modulaires)
RAW_DIFF_PREFIXES = ("ltm_monitor_", "ltm_profile_", "ltm_persistence_")

# Comparaison sémantique (état, pas compteurs)
SEMANTIC = {
    "ltm_virtual_stats", "ltm_pool_stats", "ltm_node",
    "ltm_pool", "ltm_virtual",
}

# Lignes ignorées (horodatages, compteurs volatils)
NOISE_PATTERNS = [
    re.compile(r"^\s*$"),
    re.compile(r"^###"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ T:]\d{2}:\d{2}"),
    re.compile(r"\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b.*\d{2}:\d{2}:\d{2}"),
    re.compile(r"\b(creation|last-modified)-time\b"),
    re.compile(r"uptime", re.I),
]

CONSOLE_MAX_DETAIL = 12

# Sections *_stats corrélées à la configuration
STATS_TO_CONFIG = {
    "ltm_pool_stats": "ltm_pool",
    "ltm_virtual_stats": "ltm_virtual",
}

# Sections dont le détail est affiché en console même en INFO
INFO_SHOWN_IN_CONSOLE = EXPECTED_DIFF | {"ltm_inventory"}

# ----------------------------------------------------------------------
# Couleurs console
# ----------------------------------------------------------------------
USE_COLOR = sys.stdout.isatty()
COLORS = {
    "OK": "32", "INFO": "36", "WARN": "33", "DIFF": "31",
    "ALERT": "1;31", "SKIP": "90",
}

def color(level, text):
    if not USE_COLOR:
        return text
    return f"\033[{COLORS.get(level, '0')}m{text}\033[0m"

# ----------------------------------------------------------------------
# Résultats
# ----------------------------------------------------------------------
class Result:
    def __init__(self, name, level, summary, details=None, changes=None):
        self.name = name
        self.level = level      # OK / INFO / WARN / DIFF / ALERT / SKIP
        self.summary = summary
        self.details = details or []
        # Liste de (objet, clé, avant, après) pour la corrélation
        self.changes = changes or []

# ----------------------------------------------------------------------
# Utilitaires
# ----------------------------------------------------------------------
def is_noise(line):
    return any(p.search(line) for p in NOISE_PATTERNS)

def read_lines(path):
    """Lit un fichier et retourne ses lignes sans bruit (None si absent)."""
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [ln for ln in lines if not is_noise(ln)]

def unified_diff(before, after, name):
    return list(difflib.unified_diff(
        before, after,
        fromfile=f"before/{name}", tofile=f"after/{name}",
        lineterm="", n=2,
    ))

def count_changed(diff_lines):
    return sum(
        1 for ln in diff_lines
        if (ln.startswith("+") or ln.startswith("-"))
        and not ln.startswith(("+++", "---"))
    )

# ----------------------------------------------------------------------
# Comparaisons texte (diff brut / attendu)
# ----------------------------------------------------------------------
def compare_raw(name, before, after):
    diff = unified_diff(before, after, name)
    if not diff:
        return Result(name, "OK", "identique")
    n = count_changed(diff)
    return Result(name, "DIFF", f"{n} ligne(s) modifiée(s)", diff)

def compare_expected(name, before, after):
    diff = unified_diff(before, after, name)
    if not diff:
        return Result(name, "WARN", "inchangé (upgrade effectif ?)")
    return Result(name, "INFO", "modifié (attendu après upgrade)", diff)

# ----------------------------------------------------------------------
# Parseur sémantique (nodes, stats)
# ----------------------------------------------------------------------
# Extrait, pour chaque objet, un dictionnaire d'états stables
# (session, state, availability...) en ignorant les compteurs.
# Gère les membres de pool imbriqués (clé "membre:session" / "membre:state").

STATE_KEYS = (
    "availability", "state", "enabled", "reason",
    "session", "status.availability-state", "status.enabled-state",
    "monitor-status",
)

# Format "show" : "Ltm::Virtual Server: nom" / "Ltm::Pool: nom" / ...
HEADER_RE = re.compile(
    r"^(Ltm::(?:Virtual Server|Pool|Node|Pool Member)[^:]*):\s*(\S+)"
)
# Format "list" : "ltm node 1.1.1.1 {" / "ltm pool nom {" / "ltm virtual nom {"
TMSH_OBJ_RE = re.compile(r"^ltm\s+(node|pool|virtual)\s+(\S+)\s*\{")
# Membre de pool (8 espaces) : "        1.0.0.1:http {"
TMSH_MEMBER_RE = re.compile(r"^\s{8}(\S+:\S+)\s*\{")
# Clés d'état tmsh list, quelle que soit l'indentation
TMSH_KV_RE = re.compile(r"^\s+(session|state)\s+(\S+)\s*$")
# Lignes "Clé   valeur" du show
KV_RE = re.compile(r"^\s*([A-Za-z][\w\- .]*?)\s{2,}(\S.*)$")

def parse_objects(lines):
    """Retourne {objet: {clé: valeur}} pour les états stables."""
    objects = {}
    current = None
    member = None

    for ln in lines:
        m = HEADER_RE.match(ln)
        if m:
            current = m.group(2)
            member = None
            objects.setdefault(current, {})
            continue

        m = TMSH_OBJ_RE.match(ln)
        if m:
            current = m.group(2)
            member = None
            objects.setdefault(current, {})
            continue

        if current is None:
            continue

        m = TMSH_MEMBER_RE.match(ln)
        if m:
            member = m.group(1)
            continue

        m = TMSH_KV_RE.match(ln)
        if m:
            key = f"{member}:{m.group(1)}" if member else m.group(1)
            objects[current][key] = m.group(2).strip()
            continue

        m = KV_RE.match(ln)
        if m:
            key = m.group(1).strip().lower()
            if any(k in key for k in STATE_KEYS):
                objects[current][key] = m.group(2).strip()

    return objects

def diff_objects(b_objs, a_objs):
    """
    Compare deux dictionnaires {objet: {clé: valeur}}.
    Retourne (details texte, changes structurés).
    """
    details, changes = [], []
    for obj in sorted(set(b_objs) | set(a_objs)):
        if obj not in b_objs:
            details.append(f"+ objet nouveau : {obj}")
            changes.append((obj, "(objet)", "(absent)", "(présent)"))
            continue
        if obj not in a_objs:
            details.append(f"- objet disparu : {obj}")
            changes.append((obj, "(objet)", "(présent)", "(absent)"))
            continue
        old, new = b_objs[obj], a_objs[obj]
        for key in sorted(set(old) | set(new)):
            ov = old.get(key, "(absent)")
            nv = new.get(key, "(absent)")
            if ov != nv:
                details.append(f"~ {obj} [{key}] : {ov} -> {nv}")
                changes.append((obj, key, ov, nv))
    return details, changes

def compare_semantic(name, before, after):
    if name == "ltm_pool":
        return compare_config_objects(
            name, before, after, parse_pool_list, "pool")
    if name == "ltm_virtual":
        return compare_config_objects(
            name, before, after, parse_virtual_list, "virtual")

    b_objs = parse_objects(before)
    a_objs = parse_objects(after)

    if not b_objs and not a_objs:
        return Result(
            name, "WARN",
            "aucun objet détecté (format à vérifier dans le parseur)",
        )

    details, changes = diff_objects(b_objs, a_objs)
    if not details:
        return Result(name, "OK", f"{len(b_objs)} objet(s), états identiques")
    return Result(
        name, "DIFF", f"{len(details)} changement(s) d'état", details, changes
    )

# ----------------------------------------------------------------------
# Parseurs de configuration (pools, virtuals)
# ----------------------------------------------------------------------
# Format tmsh list : les blocs sont délimités par des accolades.
# On suit la structure avec une pile de blocs ouverts.

_TIMESTAMP_KEYS = {"creation-time", "last-modified-time"}
_OBJ_HEADER = re.compile(r"^\s*ltm\s+(pool|virtual)\s+(\S+)\s*\{\s*$")
_BLOCK_OPEN = re.compile(r"^([^\s{}]+)\s*\{\s*$")
_BLOCK_EMPTY = re.compile(r"^([^\s{}]+)\s*\{\s*\}\s*$")

# Collections d'un virtual comparées comme des ensembles
_VIRTUAL_COLLECTIONS = {
    "profiles": "profil",
    "rules": "rule",
    "policies": "policy",
    "persist": "persistance",
    "security-log-profiles": "log-profile",
    "vlans": "vlan",
}

def _short(name):
    """Retire un éventuel préfixe de partition (/Common/...)."""
    return name.rsplit("/", 1)[-1]

def _split_kv(line):
    """'clé valeur multi-mots' -> (clé, valeur) ou None."""
    m = re.match(r"^([^\s{}]+)(?:\s+(.*))?$", line)
    if not m:
        return None
    return m.group(1), (m.group(2) or "").strip()

def _tokenize(lines, kind):
    """Découpe en objets : {nom: [lignes internes]} pour kind pool/virtual."""
    objs = {}
    cur = None
    depth = 0
    for raw in lines:
        m = _OBJ_HEADER.match(raw)
        if m and m.group(1) == kind:
            cur = m.group(2)
            objs[cur] = []
            depth = 1
            continue
        if cur is None:
            continue
        opens = raw.count("{")
        closes = raw.count("}")
        depth += opens - closes
        if depth <= 0:
            cur = None
            continue
        objs[cur].append(raw.strip())
    return objs

def parse_pool_list(lines):
    """Retourne {pool: {propriété: valeur, 'member X:propriété': valeur}}."""
    pools = {}
    for name, body in _tokenize(lines, "pool").items():
        props = {}
        stack = []          # blocs ouverts relatifs au pool
        member = None
        for ln in body:
            m_empty = _BLOCK_EMPTY.match(ln)
            if m_empty:
                key = m_empty.group(1)
                if stack == ["members"]:
                    props[f"member {_short(key)}:présent"] = "oui"
                continue
            m = _BLOCK_OPEN.match(ln)
            if m:
                key = m.group(1)
                stack.append(key)
                if len(stack) == 2 and stack[0] == "members":
                    member = _short(key)
                    props[f"member {member}:présent"] = "oui"
                continue
            if ln == "}":
                if stack:
                    stack.pop()
                    if len(stack) == 1 and stack[0] == "members":
                        member = None
                continue
            kv = _split_kv(ln)
            if not kv or kv[0] in _TIMESTAMP_KEYS:
                continue
            if len(stack) == 2 and stack[0] == "members" and member:
                props[f"member {member}:{kv[0]}"] = kv[1]
            elif not stack:
                props[kv[0]] = kv[1]
        pools[name] = props
    return pools

def parse_virtual_list(lines):
    """Retourne {virtual: {propriété: valeur, 'profil X': détail, ...}}."""
    virtuals = {}
    for name, body in _tokenize(lines, "virtual").items():
        props = {}
        stack = []
        entry = None
        for ln in body:
            top = stack[0] if stack else None
            m_empty = _BLOCK_EMPTY.match(ln)
            if m_empty:
                key = m_empty.group(1)
                if len(stack) == 1 and top in _VIRTUAL_COLLECTIONS:
                    props[f"{_VIRTUAL_COLLECTIONS[top]} {_short(key)}"] = "(défaut)"
                continue
            m = _BLOCK_OPEN.match(ln)
            if m:
                key = m.group(1)
                stack.append(key)
                if len(stack) == 2 and stack[0] in _VIRTUAL_COLLECTIONS:
                    entry = f"{_VIRTUAL_COLLECTIONS[stack[0]]} {_short(key)}"
                    props.setdefault(entry, "(défaut)")
                continue
            if ln == "}":
                if stack:
                    stack.pop()
                    if len(stack) < 2:
                        entry = None
                continue
            kv = _split_kv(ln)
            if not kv or kv[0] in _TIMESTAMP_KEYS:
                continue
            if not stack:
                props[kv[0]] = kv[1]
            elif (len(stack) == 1 and stack[0] in _VIRTUAL_COLLECTIONS
                  and not ln.endswith("{")):
                # Entrée simple sans accolades (ex: "persist" ou "rules")
                props[f"{_VIRTUAL_COLLECTIONS[stack[0]]} {_short(kv[0])}"] = (
                    kv[1] or "(défaut)")
            elif len(stack) == 2 and entry:
                prev = props.get(entry, "(défaut)")
                detail = f"{kv[0]} {kv[1]}".strip()
                props[entry] = detail if prev == "(défaut)" else f"{prev}, {detail}"
        virtuals[name] = props
    return virtuals

def compare_config_objects(name, before, after, parser, label):
    b_objs = parser(before)
    a_objs = parser(after)

    if not b_objs and not a_objs:
        return Result(
            name, "WARN",
            f"aucun {label} détecté (format à vérifier dans le parseur)",
        )

    details, changes = diff_objects(b_objs, a_objs)
    if not details:
        return Result(name, "OK", f"{len(b_objs)} objet(s), états identiques")
    return Result(
        name, "DIFF", f"{len(details)} changement(s) d'état", details, changes
    )

# ----------------------------------------------------------------------
# Corrélation config -> stats
# ----------------------------------------------------------------------
# Une section *_stats est "expliquée" si l'objet concerné (ou l'un de ses
# parents dans la chaîne node -> pool -> virtual) a un diff de configuration.
# Un changement d'état sans diff de config dans la chaîne = ALERT.

_MEMBER_KEY = re.compile(r"^member (\S+?):[^:]+:")

def _node_of(member_id):
    """'192.168.60.11:ssh' -> '192.168.60.11'."""
    return member_id.rsplit(":", 1)[0]

def build_dependencies(config_dirs):
    """
    Construit {objet: {parents}} sur les deux captures (before + after,
    car un lien peut avoir été ajouté ou retiré).
      - pool    dépend de ses nodes (via les membres)
      - virtual dépend de son pool
    """
    deps = {}
    for d in config_dirs:
        pool_lines = read_lines(d / "ltm_pool.txt") or []
        for pool, props in parse_pool_list(pool_lines).items():
            for key in props:
                m = _MEMBER_KEY.match(key)
                if m:
                    deps.setdefault(pool, set()).add(_node_of(m.group(1)))

        vs_lines = read_lines(d / "ltm_virtual.txt") or []
        for vs, props in parse_virtual_list(vs_lines).items():
            pool = props.get("pool")
            if pool and pool != "none":
                deps.setdefault(vs, set()).add(_short(pool))
    return deps

def explained_objects(results_by_name, deps):
    """Objets ayant un diff de config, étendus à leurs dépendants."""
    explained = set()
    for cfg in ("ltm_node", "ltm_pool", "ltm_virtual"):
        r = results_by_name.get(cfg)
        if r:
            explained |= {obj for obj, *_ in r.changes}

    changed = True
    while changed:
        changed = False
        for obj, parents in deps.items():
            if obj not in explained and parents & explained:
                explained.add(obj)
                changed = True
    return explained

def correlate_stats(results, before_dir, after_dir):
    """Sépare les diffs *_stats en attendus (INFO) / inexpliqués (ALERT)."""
    by_name = {r.name: r for r in results}
    deps = build_dependencies((before_dir, after_dir))
    explained = explained_objects(by_name, deps)

    for stats_name in STATS_TO_CONFIG:
        r = by_name.get(stats_name)
        if not r or r.level != "DIFF":
            continue

        unexplained = [c for c in r.changes if c[0] not in explained]
        n_total = len(r.changes)

        if not unexplained:
            r.level = "INFO"
            r.summary = (f"{n_total} changement(s), "
                         f"tous expliqués par la config")
            r.details = [
                f"(expliqué) {c[0]} [{c[1]}] : {c[2]} -> {c[3]}"
                for c in r.changes
            ]
        else:
            r.level = "ALERT"
            r.summary = (f"{len(unexplained)} changement(s) INEXPLIQUÉ(S) "
                         f"sur {n_total}")
            ordered = sorted(r.changes, key=lambda c: c in unexplained,
                             reverse=True)
            r.details = [
                f"{'!' if c in unexplained else '(expliqué)'} "
                f"{c[0]} [{c[1]}] : {c[2]} -> {c[3]}"
                for c in ordered
            ]

# ----------------------------------------------------------------------
# Inventaire LTM consolidé (VS / pools / membres)
# ----------------------------------------------------------------------
def compare_inventory(before_dir, after_dir):
    """Vue de synthèse : statuts VS / pools / membres + associations."""
    try:
        lines, n = diff_inventory_dirs(before_dir, after_dir)
    except Exception as exc:
        return Result("ltm_inventory", "WARN",
                      f"inventaire non comparable ({exc})")
    if not lines:
        return Result("ltm_inventory", "OK", "identique")
    return Result("ltm_inventory", "INFO",
                  f"{n} changement(s) d'inventaire", lines)

# ----------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------
def classify(name):
    if name in IGNORE:
        return "ignore"
    if name in EXPECTED_DIFF:
        return "expected"
    if name in SEMANTIC:
        return "semantic"
    if name in RAW_DIFF or name.startswith(RAW_DIFF_PREFIXES):
        return "raw"
    return "unknown"

def run(before_dir, after_dir):
    names = sorted(
        {p.stem for p in before_dir.glob("*.txt")}
        | {p.stem for p in after_dir.glob("*.txt")}
    )

    results = []
    for name in names:
        kind = classify(name)

        if kind == "ignore":
            results.append(Result(name, "SKIP", "ignoré (bruit)"))
            continue

        before = read_lines(before_dir / f"{name}.txt")
        after = read_lines(after_dir / f"{name}.txt")

        if before is None:
            results.append(Result(name, "WARN", "absent dans before"))
            continue
        if after is None:
            results.append(Result(name, "DIFF", "absent dans after"))
            continue

        if kind == "expected":
            results.append(compare_expected(name, before, after))
        elif kind == "semantic":
            results.append(compare_semantic(name, before, after))
        elif kind == "raw":
            results.append(compare_raw(name, before, after))
        else:
            r = compare_raw(name, before, after)
            if r.level == "DIFF":
                r.level = "WARN"
                r.summary += " (fichier non classé)"
            results.append(r)

    correlate_stats(results, before_dir, after_dir)
    results.append(compare_inventory(before_dir, after_dir))
    return results

# ----------------------------------------------------------------------
# Sorties
# ----------------------------------------------------------------------
def print_console(results):
    for r in results:
        tag = color(r.level, f"[{r.level:<5}]")
        print(f"{tag} {r.name:<32} {r.summary}")
        # Console : détail pour DIFF/WARN/ALERT, et INFO uniquement
        # pour les fichiers attendus (version/software) et l'inventaire LTM.
        # Les stats expliquées restent dans report.md.
        show = r.level in ("DIFF", "WARN", "ALERT") or (
            r.level == "INFO" and r.name in INFO_SHOWN_IN_CONSOLE)
        if r.details and show:
            for d in r.details[:CONSOLE_MAX_DETAIL]:
                print(f"         {d}")
            extra = len(r.details) - CONSOLE_MAX_DETAIL
            if extra > 0:
                print(f"         ... ({extra} de plus, voir report.md)")

def write_report(results, before_dir, after_dir, out_path):
    counts = Counter(r.level for r in results)

    lines = [
        "# Rapport de comparaison BIG-IP",
        "",
        f"- **Before** : `{before_dir}`",
        f"- **After** : `{after_dir}`",
        "",
        "## Synthèse",
        "",
        "| Niveau | Nombre |",
        "|---|---|",
    ]
    for lvl in ("ALERT", "DIFF", "WARN", "INFO", "OK", "SKIP"):
        lines.append(f"| {lvl} | {counts.get(lvl, 0)} |")

    lines += [
        "", "## Détail", "",
        "| Niveau | Élément | Résumé |", "|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r.level} | {r.name} | {r.summary} |")

    for r in results:
        if r.details and r.level in ("ALERT", "DIFF", "WARN", "INFO"):
            lines += ["", f"### {r.name} ({r.level})", "", "```diff"]
            lines += r.details
            lines += ["```"]

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def main():
    argv = [a for a in sys.argv[1:] if a != "--ltm-strict"]
    strict_ltm = "--ltm-strict" in sys.argv[1:]

    if len(argv) != 2:
        print(__doc__)
        return 2

    before_dir, after_dir = Path(argv[0]), Path(argv[1])
    for d in (before_dir, after_dir):
        if not d.is_dir():
            print(f"Dossier introuvable : {d}")
            return 2

    results = run(before_dir, after_dir)

    if strict_ltm:
        for r in results:
            if r.name == "ltm_inventory" and r.level == "INFO":
                r.level = "DIFF"

    print_console(results)

    report = after_dir / "report.md"
    write_report(results, before_dir, after_dir, report)
    print(f"\nRapport : {report}")

    return 1 if any(r.level in ("DIFF", "ALERT") for r in results) else 0

if __name__ == "__main__":
    sys.exit(main())
