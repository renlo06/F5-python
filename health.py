#!/usr/bin/env python3
"""Relevé BIG-IP (lecture seule) via SSH/Paramiko, en parallèle.

Sans -u/--user, demande l'utilisateur SSH (Entrée = admin).
Sans --etat, demande l'état du relevé : 1 = before, 2 = after.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import getpass
import json
import re
import shlex
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

COMMANDS = ("show sys cpu", "show sys memory", "show sys performance connections", "show sys version")
_METRICS = ("cpu_pct", "mem_tmm_pct", "mem_host_pct", "connexions_actives",
            "nouvelles_connexions_client_s", "nouvelles_connexions_server_s")
_STOP_EVENT = threading.Event()
_PRINT_LOCK = threading.Lock()
_UNIT = re.compile(r"^([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*([KMGTP]?)$", re.I)


def _octets(value: str) -> int:
    """Convertit un nombre tmsh en octets (base 1024)."""
    m = _UNIT.match(value.strip())
    if not m:
        raise ValueError("unité mémoire non reconnue: {!r}".format(value))
    powers = {"K": 1, "M": 2, "G": 3, "T": 4, "P": 5}
    number, suffix = m.groups()
    return int(round(float(number) * (1024 ** powers[suffix.upper()] if suffix else 1)))


def parser_cpu(sortie: str) -> Dict[str, Any]:
    coeurs: Dict[str, float] = {}
    for bloc_match in re.finditer(
        r"^CPU:\s*(\d+)\s*\(clock ticks\)(.*?)(?=^CPU:\s*\d+\s*\(clock ticks\)|\Z)",
        sortie, re.M | re.S,
    ):
        numero, bloc = bloc_match.groups()
        idle = re.search(r"^\s*Idle\s+(\d+)\s+(\d+)\s+(\d+)", bloc, re.M)
        if idle:
            coeurs[numero] = float(100 - int(idle.group(2)))
    moyenne = round(sum(coeurs.values()) / len(coeurs), 2) if coeurs else None
    return {"coeurs": coeurs, "moyenne_1min": moyenne}


def parser_memoire(sortie: str) -> Dict[str, Optional[float]]:
    resultat: Dict[str, Optional[float]] = {
        "tmm_total": None, "tmm_utilisee": None, "tmm_pct": None,
        "host_total": None, "host_utilisee": None, "host_pct": None,
    }
    section = sortie.split("Sys::Host Memory (bytes)", 1)[-1].split("Sys::SubSystem Memory", 1)[0]
    motif = r"^{}:\s*\d+\s*\n\s*Total\s+([\d.]+\s*[KMGTP]?)\s*\n\s*Used\s+([\d.]+\s*[KMGTP]?)"
    for etiquette, prefixe in (("TMM", "tmm"), ("Total", "host")):
        match = re.search(motif.format(etiquette), section, re.M | re.I)
        if match:
            total, utilisee = (_octets(value) for value in match.groups())
            resultat[prefixe + "_total"] = total
            resultat[prefixe + "_utilisee"] = utilisee
            resultat[prefixe + "_pct"] = round(100 * utilisee / total, 1) if total else None
    return resultat


def parser_connexions(sortie: str) -> Dict[str, Any]:
    def valeur(texte: str, etiquette: str) -> Optional[Dict[str, int]]:
        match = re.search(r"^\s*" + re.escape(etiquette) + r"\s+(\d+)\s+(\d+)", texte, re.M)
        return {"actuel": int(match.group(1)), "moy": int(match.group(2))} if match else None

    try:
        active = sortie.split("Active Connections", 1)[1].split("Total New Connections(/sec)", 1)[0]
        nouveaux = sortie.split("Total New Connections(/sec)", 1)[1].split("HTTP Requests(/sec)", 1)[0]
    except IndexError:
        return {}
    resultat = {
        "total": valeur(active, "Connections"),
        "client": valeur(nouveaux, "Client Connections"),
        "server": valeur(nouveaux, "Server Connections"),
    }
    return {cle: val for cle, val in resultat.items() if val is not None}


def extraire_version(sortie: str) -> Optional[str]:
    version = re.search(r"^\s*Version\s+(.+?)\s*$", sortie, re.M | re.I)
    build = re.search(r"^\s*Build\s+(.+?)\s*$", sortie, re.M | re.I)
    if version:
        value = version.group(1).strip()
        if build:
            value += " (build {})".format(build.group(1).strip())
        return value
    # Repli si le format de version est une ligne produit synthétique.
    product = re.search(r"\bBIG-IP\s+(\S+)", sortie, re.I)
    return product.group(1) if product else None


def analyser_hoteport(value: str) -> Tuple[str, int]:
    """Accepte host, host:port et [IPv6]:port."""
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", value)
        if not match:
            raise argparse.ArgumentTypeError("adresse IPv6 invalide: {}".format(value))
        host, port = match.group(1), int(match.group(2) or 22)
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        if port_text.isdigit():
            port = int(port_text)
        else:
            host, port = value, 22
    else:
        host, port = value, 22
    if not host or not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("hôte/port invalide: {}".format(value))
    return host, port


def _est_commande_tmsh(commande: str) -> bool:
    """Reconnaît les verbes tmsh usuels; les autres commandes sont Linux."""
    premier = commande.strip().split(None, 1)[0].lower() if commande.strip() else ""
    if premier == "tmsh":
        return True
    return premier in {"show", "list", "create", "modify", "delete", "install", "load",
                       "save", "reset", "run", "help", "exit", "quit"}


def _lancer(client: Any, remote: str, timeout: float) -> Tuple[str, str, int]:
    """Exécute une commande distante, retourne (stdout, stderr, code)."""
    _stdin, stdout, stderr = client.exec_command(remote, timeout=timeout)
    sortie = stdout.read().decode("utf-8", errors="replace")
    erreur = stderr.read().decode("utf-8", errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    return sortie, erreur, code


def _erreur_shell(sortie: str, erreur: str) -> bool:
    """Détecte l'erreur typique d'un mauvais choix de shell (tmsh vs bash)."""
    texte = (sortie + " " + erreur).lower()
    return ("syntax error" in texte and "unexpected argument" in texte) \
        or "command not found" in texte


def executer_commande(client: Any, commande: str, shell: str, timeout: float) -> str:
    """Exécute une commande tmsh ou Linux selon le shell d'ouverture BIG-IP.

    Si la forme choisie échoue à cause d'une mauvaise détection du shell,
    la commande est rejouée automatiquement sous l'autre forme."""
    est_tmsh = _est_commande_tmsh(commande)
    # Forme "bash" : on préfixe 'tmsh -q'. Forme "tmsh" : commande telle quelle.
    forme_bash = "tmsh -q {}".format(commande) if est_tmsh else commande
    forme_tmsh = commande if est_tmsh else "run /util bash -c {}".format(shlex.quote(commande))

    ordre = (forme_bash, forme_tmsh) if shell == "bash" else (forme_tmsh, forme_bash)

    derniere: Tuple[str, str, int] = ("", "", 1)
    for remote in ordre:
        sortie, erreur, code = _lancer(client, remote, timeout)
        derniere = (sortie, erreur, code)
        if code == 0 and not _erreur_shell(sortie, erreur):
            return sortie
        if not _erreur_shell(sortie, erreur):
            break  # vraie erreur de commande : inutile de changer de forme
    sortie, erreur, code = derniere
    raise RuntimeError("commande {!r} en échec (code {}): {}".format(
        commande, code, erreur or sortie.strip()))


def ouvrir_client(host: str, port: int, user: str, password: str, timeout: float) -> Any:
    """Connexion SSH sans contrôle des clés d'hôte; essaie password puis keyboard-interactive."""
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("dépendance manquante: installer paramiko") from exc
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=port, username=user, password=password,
                       timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                       look_for_keys=False, allow_agent=False)
        return client
    except (paramiko.BadAuthenticationType, paramiko.AuthenticationException) as initial_error:
        try:
            client.close()
        except Exception:
            pass
        transport = paramiko.Transport((host, port))
        auth_errors = [initial_error]
        try:
            transport.start_client(timeout=timeout)
            try:
                transport.auth_password(username=user, password=password)
            except (paramiko.BadAuthenticationType, paramiko.AuthenticationException) as exc:
                auth_errors.append(exc)
            if not transport.is_authenticated():
                def handler(_title: str, _instructions: str, prompts: List[Tuple[str, bool]]) -> List[str]:
                    return [password] * len(prompts)
                try:
                    transport.auth_interactive(user, handler)
                except (paramiko.BadAuthenticationType, paramiko.AuthenticationException) as exc:
                    auth_errors.append(exc)
            if not transport.is_authenticated():
                allowed = []
                for exc in auth_errors:
                    allowed.extend(getattr(exc, "allowed_types", None) or [])
                methods = ", ".join(dict.fromkeys(str(method) for method in allowed))
                detail = "Authentification SSH refusée"
                if methods:
                    detail += "; méthodes autorisées: {}".format(methods)
                if auth_errors:
                    detail += " ({})".format(auth_errors[-1])
                raise paramiko.AuthenticationException(detail)
            client._transport = transport
            return client
        except Exception:
            transport.close()
            raise


def _masquer_secret(value: Any, secret: str) -> Any:
    """Retire le secret de toute donnée susceptible d'être affichée ou exportée."""
    if isinstance(value, str):
        return value.replace(secret, "[MASQUÉ]") if secret else value
    if isinstance(value, list):
        return [_masquer_secret(item, secret) for item in value]
    if isinstance(value, tuple):
        return tuple(_masquer_secret(item, secret) for item in value)
    if isinstance(value, dict):
        return {key: _masquer_secret(item, secret) for key, item in value.items()}
    return value


def _detecter_shell(client: Any, timeout: float) -> str:
    """Détecte le shell de connexion : 'bash' ou 'tmsh'.

    Sous tmsh, 'echo' est une commande inconnue (syntax error) ; c'est ce
    signal qui est utilisé, plutôt que la seule lecture de $0."""
    try:
        sortie, erreur, _code = _lancer(client, "echo BASHOK", timeout)
        if "BASHOK" in sortie and not _erreur_shell(sortie, erreur):
            return "bash"
        if _erreur_shell(sortie, erreur):
            return "tmsh"
    except Exception:
        pass

    # Confirmation par une commande tmsh native
    try:
        sortie, erreur, code = _lancer(client, "show sys version", timeout)
        if code == 0 and "version" in sortie.lower():
            return "tmsh"
    except Exception:
        pass

    # Dernier essai : tmsh préfixé (compte bash)
    try:
        sortie, erreur, code = _lancer(client, "tmsh -q show sys version", timeout)
        if code == 0 and "version" in sortie.lower():
            return "bash"
    except Exception:
        pass

    raise RuntimeError("shell distant non reconnu (ni bash ni tmsh)")


def _champ_incomplet(cpu: Dict[str, Any], mem: Dict[str, Any], con: Dict[str, Any], version: Optional[str]) -> List[str]:
    champs = []
    if cpu.get("moyenne_1min") is None:
        champs.append("CPU")
    for key in ("tmm_total", "tmm_utilisee", "tmm_pct", "host_total", "host_utilisee", "host_pct"):
        if mem.get(key) is None:
            champs.append("mémoire " + key)
    for key in ("total", "client", "server"):
        if con.get(key) is None:
            champs.append("connexions " + key)
    if version is None:
        champs.append("version")
    return champs


def _echantillon(client: Any, shell: str, timeout: float) -> Tuple[Dict[str, Any], Dict[str, str]]:
    brut = {"cpu": "", "memoire": "", "connexions": "", "version": ""}
    erreurs = []
    for key, command in zip(("cpu", "memoire", "connexions", "version"), COMMANDS):
        try:
            brut[key] = executer_commande(client, command, shell, timeout)
        except Exception as exc:
            erreurs.append("{}: {}".format(key, exc))
    if erreurs:
        raise RuntimeError("; ".join(erreurs))
    parsed = {
        "cpu": parser_cpu(brut["cpu"]),
        "memoire": parser_memoire(brut["memoire"]),
        "connexions": parser_connexions(brut["connexions"]),
        "version": extraire_version(brut["version"]),
    }
    return parsed, brut


def _valeurs_metriques(parsed: Dict[str, Any]) -> Dict[str, Optional[float]]:
    con = parsed["connexions"]
    return {
        "cpu_pct": parsed["cpu"].get("moyenne_1min"),
        "mem_tmm_pct": parsed["memoire"].get("tmm_pct"),
        "mem_host_pct": parsed["memoire"].get("host_pct"),
        "connexions_actives": (con.get("total") or {}).get("actuel"),
        "nouvelles_connexions_client_s": (con.get("client") or {}).get("actuel"),
        "nouvelles_connexions_server_s": (con.get("server") or {}).get("actuel"),
    }


def _statistiques(echantillons: List[Dict[str, Any]]) -> Dict[str, Any]:
    resultat = {}
    for metric in _METRICS:
        vals = [s["metriques"].get(metric) for s in echantillons
                if s.get("statut") == "OK" and s.get("metriques", {}).get(metric) is not None]
        resultat[metric] = {
            "moyenne": round(sum(vals) / len(vals), 2) if vals else None,
            "min": min(vals) if vals else None,
            "max": max(vals) if vals else None,
            "echantillons_valides": len(vals),
        }
    return resultat


def _statut_erreur(exc: Exception) -> str:
    message = str(exc)
    typ = type(exc).__name__.lower()
    msg = message.lower()
    if "authentication" in typ or "auth" in msg or "authentication failed" in msg:
        return "AUTH_REFUSEE"
    if "timeout" in typ or "timed out" in msg or "timeout" in msg:
        return "TIMEOUT"
    if "paramiko" in msg and "manquant" in msg:
        return "DEPENDANCE_MANQUANTE"
    if isinstance(exc, argparse.ArgumentTypeError):
        return "HOTE_INVALIDE"
    return "ERREUR_SSH"


def collecter(equipement: str, user: str, password: str, timeout: float,
              duree: float = 0, intervalle: float = 10, etat: str = "before") -> Dict[str, Any]:
    host, port = analyser_hoteport(equipement)
    maintenant = datetime.now().astimezone().isoformat(timespec="seconds")
    resultat: Dict[str, Any] = {
        "equipement": equipement, "etat": etat, "horodatage": maintenant, "statut": "ERREUR",
        "user": user, "shell": None, "version": None,
        "cpu": {"coeurs": {}, "moyenne_1min": None},
        "memoire": {"tmm_total": None, "tmm_utilisee": None, "tmm_pct": None,
                    "host_total": None, "host_utilisee": None, "host_pct": None},
        "connexions": {}, "echantillons": [],
        "statistiques": {m: {"moyenne": None, "min": None, "max": None, "echantillons_valides": 0} for m in _METRICS},
        "duree_demandee_s": duree,
    }
    client = None
    try:
        client = ouvrir_client(host, port, user, password, timeout)
        shell = _detecter_shell(client, timeout)
        resultat["shell"] = shell
        debut = time.monotonic()
        cible_index = 0
        numero = 0
        while True:
            if _STOP_EVENT.is_set():
                break
            numero += 1
            cible = min(cible_index * intervalle, duree)
            if cible_index and time.monotonic() - debut < cible:
                if _STOP_EVENT.wait(max(0, debut + cible - time.monotonic())):
                    break
            horodatage = datetime.now().astimezone().isoformat(timespec="seconds")
            rec = {"horodatage": horodatage, "statut": "ERREUR", "metriques": {m: None for m in _METRICS}}
            try:
                parsed, brut = _echantillon(client, shell, timeout)
                rec["metriques"] = _valeurs_metriques(parsed)
                rec["statut"] = "OK" if any(v is not None for v in rec["metriques"].values()) else "PARSING_INCOMPLET"
                if duree == 0 and rec["statut"] == "OK":
                    missing = _champ_incomplet(parsed["cpu"], parsed["memoire"], parsed["connexions"], parsed["version"])
                    if missing:
                        rec["statut"] = "PARSING_INCOMPLET"
                        rec["erreur"] = "parsing incomplet : " + ", ".join(missing)
                rec["version"] = parsed["version"]
                if rec["statut"] == "OK":
                    # Valeurs structurées conservées au niveau racine pour compatibilité.
                    resultat["cpu"] = parsed["cpu"]
                    resultat["memoire"] = parsed["memoire"]
                    resultat["connexions"] = parsed["connexions"]
                    if parsed["version"]:
                        resultat["version"] = parsed["version"]
                else:
                    rec["erreur"] = rec.get("erreur") or "aucune métrique numérique analysable"
                if getattr(collecter, "inclure_brut", False) and numero == 1:
                    rec["brut"] = brut
            except Exception as exc:
                rec["erreur"] = str(exc)
                rec["statut"] = _statut_erreur(exc)
            resultat["echantillons"].append(rec)
            with _PRINT_LOCK:
                print("{}: échantillon {}/{} — {}".format(
                    equipement, numero, (int(duree // intervalle) + 1 if duree else 1), rec["statut"]), flush=True)
            if duree <= 0 or _STOP_EVENT.is_set():
                break
            cible_index += 1
            prochaine = cible_index * intervalle
            if prochaine > duree:
                break
        stats = _statistiques(resultat["echantillons"])
        resultat["statistiques"] = stats
        resultat["duree_reelle_s"] = round(time.monotonic() - debut, 3)
        # Utiliser les moyennes comme valeurs principales affichées/exportées.
        resultat["cpu"]["moyenne_1min"] = stats["cpu_pct"]["moyenne"]
        resultat["memoire"]["tmm_pct"] = stats["mem_tmm_pct"]["moyenne"]
        resultat["memoire"]["host_pct"] = stats["mem_host_pct"]["moyenne"]
        for key, metric in (("total", "connexions_actives"), ("client", "nouvelles_connexions_client_s"),
                            ("server", "nouvelles_connexions_server_s")):
            if resultat["connexions"].get(key) is None:
                resultat["connexions"][key] = {}
            if stats[metric]["moyenne"] is not None:
                resultat["connexions"][key]["actuel"] = stats[metric]["moyenne"]
        valid_sample = any(s["statut"] == "OK" for s in resultat["echantillons"])
        if duree == 0:
            # Compatibilité du relevé unique historique : les champs manquants restent une erreur de parsing.
            last = resultat["echantillons"][-1] if resultat["echantillons"] else None
            if last and last["statut"] in ("OK", "PARSING_INCOMPLET"):
                missing = _champ_incomplet(resultat["cpu"], resultat["memoire"], resultat["connexions"], resultat["version"])
                resultat["statut"] = "OK" if not missing else "PARSING_INCOMPLET"
                if missing:
                    resultat["avertissements"] = ["parsing incomplet : " + ", ".join(missing)]
            else:
                resultat["statut"] = last["statut"] if last else "ERREUR"
        else:
            resultat["statut"] = "OK" if valid_sample else "ERREUR"
        failures = [s for s in resultat["echantillons"] if s["statut"] != "OK"]
        if failures:
            resultat.setdefault("avertissements", []).extend(
                "échantillon {} en échec : {}".format(i + 1, s.get("erreur", s["statut"]))
                for i, s in enumerate(resultat["echantillons"]) if s["statut"] != "OK")
        if not valid_sample:
            resultat["erreur"] = "; ".join(s.get("erreur", s["statut"]) for s in failures) or "aucun échantillon valide"
        if getattr(collecter, "inclure_brut", False):
            resultat["brut"] = next((s.get("brut") for s in resultat["echantillons"] if s.get("brut")), {})
        return _masquer_secret(resultat, password)
    except Exception as exc:
        resultat["statut"] = _statut_erreur(exc)
        resultat["erreur"] = _masquer_secret(str(exc), password)
        if "méthodes autorisées" in resultat["erreur"].lower():
            with _PRINT_LOCK:
                print("{}: {}".format(equipement, resultat["erreur"]), file=sys.stderr)
        return _masquer_secret(resultat, password)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def lire_hotes(positionnels: Iterable[str], fichier: Optional[str]) -> List[str]:
    hotes = list(positionnels)
    if fichier:
        with open(fichier, "r", encoding="utf-8") as stream:
            for ligne in stream:
                hote = ligne.split("#", 1)[0].strip()
                if hote:
                    hotes.append(hote)
    return hotes


def format_bytes(value: Optional[int]) -> str:
    if value is None:
        return "—"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return "{} {}".format(round(value, 1) if unit != "B" else value, unit)
        value /= 1024
    return str(value)


def afficher_tableau(resultats: List[Dict[str, Any]], duree: float = 0, intervalle: float = 10,
                     etat: str = "before") -> None:
    print("=== ÉTAT : {} ===".format(etat.upper()))
    counts = sorted(set(len(r.get("echantillons", [])) for r in resultats))
    count_text = str(counts[0]) if len(counts) == 1 and counts else ("/".join(map(str, counts)) if counts else "0")
    print("Fenêtre: {} s | intervalle: {} s | échantillons/équipement: {} (valides par métrique)".format(
        duree, intervalle, count_text))

    def cellule(r: Dict[str, Any], metric: str, suffix: str = "") -> str:
        st = r.get("statistiques", {}).get(metric, {})
        avg, lo, hi = st.get("moyenne"), st.get("min"), st.get("max")
        if avg is None:
            return "n/d (0)"

        def compact(v: Any) -> str:
            return "{:.1f}".format(v).rstrip("0").rstrip(".")
        return (compact(avg) + suffix + " (" + compact(lo) + "–" + compact(hi) + suffix + ";" +
                str(st.get("echantillons_valides", 0)) + ")")

    lignes = []
    for r in resultats:
        lignes.append([
            str(r.get("equipement", "")), str(r.get("user", "")), str(r.get("statut", "")),
            cellule(r, "cpu_pct", "%"), cellule(r, "mem_tmm_pct", "%"),
            cellule(r, "mem_host_pct", "%"), cellule(r, "connexions_actives"),
            cellule(r, "nouvelles_connexions_client_s"), cellule(r, "nouvelles_connexions_server_s"),
        ])
    headers = ["ÉQUIPEMENT", "USER", "STATUT", "CPU%", "TMM%", "HOST%", "ACT", "CLI/s", "SRV/s"]
    widths = [max(len(headers[i]), *(len(line[i]) for line in lignes)) if lignes else len(headers[i])
              for i in range(len(headers))]
    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("─" * widths[i] for i in range(len(headers))))
    for line in lignes:
        print("  ".join(line[i].ljust(widths[i]) for i in range(len(headers))))
    for r in resultats:
        for warning in r.get("avertissements", []):
            print("{}: {}".format(r.get("equipement"), warning), file=sys.stderr)


def normaliser_etat(value: str) -> str:
    """Accepte 1/2, before/after, b/a, avant/apres."""
    value = value.strip().lower()
    aliases = {"1": "before", "b": "before", "avant": "before",
               "2": "after", "a": "after", "apres": "after", "après": "after"}
    value = aliases.get(value, value)
    if value not in ("before", "after"):
        raise argparse.ArgumentTypeError("l'état doit être 1/before ou 2/after")
    return value


def demander_etat() -> str:
    print("Quel est l'état de ce relevé ?")
    print("  1) before (avant l'intervention)")
    print("  2) after  (après l'intervention)")
    while True:
        try:
            value = input("Choix [1/2] : ")
        except EOFError as exc:
            raise RuntimeError("aucun état fourni") from exc
        try:
            return normaliser_etat(value)
        except argparse.ArgumentTypeError:
            print("Valeur invalide. Saisir 1 (before) ou 2 (after).", file=sys.stderr)


def construire_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Relevé CPU, mémoire et connexions BIG-IP en lecture seule via SSH.")
    parser.add_argument("hotes", nargs="*", help="hôte(s) BIG-IP, au format host ou host:port")
    parser.add_argument("-f", "--fichier", help="fichier de liste d'hôtes (un par ligne, # commentaires)")
    parser.add_argument("-u", "--user", default=None, help="utilisateur SSH (sans cette option : prompt interactif, défaut admin)")
    parser.add_argument("-w", "--workers", type=int, default=4, help="nombre de connexions parallèles (défaut: 4)")
    parser.add_argument("--etat", type=normaliser_etat,
                        help="état du relevé : 1/before ou 2/after (sans cette option : prompt interactif)")
    parser.add_argument("-j", "--json", dest="json_path", nargs="?", const="",
                        help="chemin de sortie JSON (sans valeur : sante_bigip_<état>.json)")
    parser.add_argument("--raw", action="store_true", help="inclure les sorties tmsh brutes dans le JSON")
    parser.add_argument("--timeout", type=float, default=10.0, help="timeout SSH/commande en secondes (défaut: 10)")
    parser.add_argument("--duree", type=float, default=60, help="fenêtre d'échantillonnage en secondes (défaut: 60; 0 = relevé unique)")
    parser.add_argument("--intervalle", type=float, default=10, help="secondes entre échantillons (défaut: 10)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = construire_parser()
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers doit être au moins 1")
    if args.timeout <= 0:
        parser.error("--timeout doit être positif")
    if args.intervalle <= 0:
        parser.error("--intervalle doit être positif")
    if args.duree < 0:
        parser.error("--duree doit être supérieure ou égale à zéro")
    try:
        hotes = lire_hotes(args.hotes, args.fichier)
    except OSError as exc:
        parser.error("impossible de lire --fichier: {}".format(exc))
    if not hotes:
        parser.error("fournir au moins un hôte ou --fichier")
    etat = args.etat if args.etat is not None else demander_etat()
    user = args.user
    if user is None:
        user = input("Login [admin] : ").strip() or "admin"
    password = getpass.getpass("Mot de passe SSH pour {}: ".format(user))
    collecter.inclure_brut = args.raw
    _STOP_EVENT.clear()
    resultats: List[Optional[Dict[str, Any]]] = [None] * len(hotes)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futurs = {pool.submit(collecter, hote, user, password, args.timeout, args.duree,
                              args.intervalle, etat): index for index, hote in enumerate(hotes)}
        try:
            for futur in concurrent.futures.as_completed(futurs):
                index = futurs[futur]
                try:
                    resultats[index] = futur.result()
                except Exception as exc:  # garde-fou; une panne isolée ne bloque pas le lot
                    resultats[index] = {
                        "equipement": hotes[index], "statut": _statut_erreur(exc), "erreur": str(exc),
                        "horodatage": datetime.now().astimezone().isoformat(timespec="seconds"),
                        "user": user, "etat": etat, "version": None,
                        "cpu": {"coeurs": {}, "moyenne_1min": None},
                        "memoire": {"tmm_total": None, "tmm_utilisee": None, "tmm_pct": None,
                                    "host_total": None, "host_utilisee": None, "host_pct": None},
                        "connexions": {}}
        except KeyboardInterrupt:
            _STOP_EVENT.set()
            print("Interruption demandée: arrêt des échantillonnages en cours…", file=sys.stderr)
            for futur, index in futurs.items():
                try:
                    resultats[index] = futur.result()
                except Exception:
                    pass
    final = [r for r in resultats if r is not None]
    afficher_tableau(final, args.duree, args.intervalle, etat)
    json_path = args.json_path
    if json_path == "":
        json_path = "sante_bigip_{}.json".format(etat)
    if json_path:
        try:
            document = {
                "etat": etat,
                "horodatage": datetime.now().astimezone().isoformat(timespec="seconds"),
                "equipements": final,
            }
            for resultat in final:
                resultat["etat"] = etat
                resultat.setdefault("horodatage", datetime.now().astimezone().isoformat(timespec="seconds"))
            with open(json_path, "w", encoding="utf-8") as stream:
                json.dump(document, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
        except OSError as exc:
            print("Erreur d'écriture JSON: {}".format(exc), file=sys.stderr)
            return 1
    return 0 if all(r.get("statut") == "OK" for r in final) else 1


if __name__ == "__main__":
    sys.exit(main())
