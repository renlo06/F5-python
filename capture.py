#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capture en lecture seule de la configuration BIG-IP via SSH.

Usage:
    python capture.py --host 10.0.0.11 --label bigip-a [--phase before|after]
    python capture.py -f equipements.txt [--phase before|after] [--shell tmsh]

Format du fichier d'équipements (une ligne par équipement) :
    hote[:port][;label]
Les lignes vides et celles commençant par # sont ignorées.
"""

import argparse
import getpass
import json
import re
import shlex
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Liste des commandes conservée dans sa forme tmsh d'origine.
COMMANDS: List[Tuple[str, str]] = [
    ("version", "tmsh show sys version"),
    ("hardware", "tmsh show sys hardware"),
    ("license", "tmsh show sys license"),
    ("provision", "tmsh list sys provision"),
    ("disk", "tmsh show sys disk directory; echo; echo '--- df -h ---'; df -h; echo; echo '--- raid ---'; tmsh show sys raid"),
    ("software", "tmsh show sys software"),
    ("ucs_list", "tmsh list sys ucs"),
    ("ntp", "tmsh list sys ntp"),
    ("dns", "tmsh list sys dns"),
    ("snmp", "tmsh list sys snmp"),
    ("syslog", "tmsh list sys syslog"),
    ("ha_status", "tmsh show cm sync-status"),
    ("failover", "tmsh show sys failover"),
    ("device", "tmsh list cm device"),
    ("vlan", "tmsh list net vlan"),
    ("self_ip", "tmsh list net self"),
    ("route", "tmsh list net route"),
    ("trunk", "tmsh list net trunk"),
    ("ltm_virtual", "tmsh list ltm virtual all-properties"),
    ("ltm_virtual_stats", "tmsh show ltm virtual"),
    ("ltm_pool", "tmsh list ltm pool all-properties"),
    ("ltm_pool_stats", "tmsh show ltm pool"),
    ("ltm_node", "tmsh list ltm node all-properties"),
]

for _monitor in ("tcp", "http", "https", "icmp", "gateway-icmp", "udp", "tcp-half-open", "external", "dns", "ldap", "mysql", "radius", "sip", "smtp"):
    _name = "ltm_monitor_" + _monitor.replace("-", "_")
    COMMANDS.append((_name, "tmsh list ltm monitor " + _monitor))

for _profile, _name in (
    ("client-ssl", "ltm_profile_client_ssl"),
    ("server-ssl", "ltm_profile_server_ssl"),
    ("http", "ltm_profile_http"),
    ("tcp", "ltm_profile_tcp"),
    ("udp", "ltm_profile_udp"),
    ("fastl4", "ltm_profile_fastl4"),
    ("one-connect", "ltm_profile_oneconnect"),
    ("http-compression", "ltm_profile_http_compression"),
    ("web-acceleration", "ltm_profile_web_acceleration"),
    ("stream", "ltm_profile_stream"),
):
    COMMANDS.append((_name, "tmsh list ltm profile " + _profile))

for _persistence, _name in (
    ("cookie", "ltm_persistence_cookie"),
    ("source-addr", "ltm_persistence_source_addr"),
    ("ssl", "ltm_persistence_ssl"),
    ("universal", "ltm_persistence_universal"),
):
    COMMANDS.append((_name, "tmsh list ltm persistence " + _persistence))

COMMANDS.extend([
    ("certs", "tmsh list sys file ssl-cert"),
    ("keys", "tmsh list sys file ssl-key"),
    ("ltm_rule", "tmsh list ltm rule"),
])

FILTER_SYS_RULES = re.compile(r"(?m)^\s*ltm rule\s+(?:/Common/)?_sys_[^\s{]+\s*\{")


def filter_sys_rules(text: str) -> str:
    """Retire les blocs de règles _sys_ en comptant les accolades imbriquées."""
    lines = text.splitlines(keepends=True)
    output: List[str] = []
    skipping = False
    depth = 0
    for line in lines:
        if not skipping:
            match = FILTER_SYS_RULES.search(line)
            if not match:
                output.append(line)
                continue
            skipping = True
            depth = 0
        # Le comptage est volontairement simple et suit la structure tmsh.
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            skipping = False
            depth = 0
    return "".join(output)


def adapter_commande(cmd: str, shell: str) -> str:
    """Adapte la commande selon le shell SSH distant détecté."""
    if shell == "bash":
        return cmd
    if shell != "tmsh":
        raise ValueError("shell non pris en charge : {}".format(shell))

    # En tmsh, les commandes composées sont déléguées à bash via run /util.
    # Cela évite les interprétations tmsh des points-virgules, echo et df.
    lower = cmd.lower()
    if ";" in cmd or re.search(r"(?:^|\s)(?:df|echo)(?:\s|$)", lower):
        if cmd.startswith("tmsh "):
            wrapped = cmd
        else:
            wrapped = "tmsh " + cmd
        return "run /util bash -c {}".format(shlex.quote(wrapped))

    if cmd.startswith("tmsh "):
        return cmd[len("tmsh "):]
    return cmd


def _sortie(chaine: Any) -> str:
    """Normalise les sorties Paramiko et les faux clients de test."""
    value = chaine.read()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def run(client: Any, cmd: str, timeout: int = 180) -> Tuple[str, str, int]:
    """Exécute une commande et renvoie stdout, stderr et code de retour."""
    _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = _sortie(stdout)
    err = _sortie(stderr)
    rc = stdout.channel.recv_exit_status()
    return out, err, rc


def _methodes_autorisees(erreurs: List[BaseException]) -> List[str]:
    methodes: List[str] = []
    for erreur in erreurs:
        for methode in getattr(erreur, "allowed_types", None) or []:
            if str(methode) not in methodes:
                methodes.append(str(methode))
    return methodes


def ouvrir_client(host: str, port: int, user: str, password: str, timeout: int = 30) -> Any:
    """Connexion mot de passe puis repli keyboard-interactive, sans clé connue."""
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("Dépendance manquante : installer paramiko") from exc

    client = paramiko.SSHClient()
    # AutoAddPolicy évite toute vérification/lecture du fichier known_hosts.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=user, password=password,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=False, allow_agent=False,
        )
        return client
    except (paramiko.BadAuthenticationType, paramiko.AuthenticationException) as first_error:
        try:
            client.close()
        except Exception:
            pass
        erreurs: List[BaseException] = [first_error]
        transport = paramiko.Transport((host, port))
        try:
            transport.start_client(timeout=timeout)
            try:
                transport.auth_password(username=user, password=password)
            except (paramiko.BadAuthenticationType, paramiko.AuthenticationException) as exc:
                erreurs.append(exc)
            if not transport.is_authenticated():
                def handler(_titre: str, _instructions: str, prompts: List[Tuple[str, bool]]) -> List[str]:
                    return [password for _prompt, _echo in prompts]
                try:
                    # auth_interactive effectue le dispatch Paramiko vers le serveur.
                    transport.auth_interactive(user, handler)
                except (paramiko.BadAuthenticationType, paramiko.AuthenticationException) as exc:
                    erreurs.append(exc)
            if not transport.is_authenticated():
                methodes = _methodes_autorisees(erreurs)
                detail = "Authentification refusée"
                if methodes:
                    detail += "; méthodes autorisées par le serveur : " + ", ".join(methodes)
                raise paramiko.AuthenticationException(detail)
            client._transport = transport
            return client
        except Exception:
            transport.close()
            raise


def _detecter_shell(client: Any, timeout: int = 30) -> str:
    """Détecte le shell de connexion (tmsh ou bash) par des sondes discriminantes.

    - Sonde tmsh : 'show sys version' n'a de sens qu'en tmsh ; en bash, la
      commande est introuvable (code retour 127).
    - Sonde bash : 'echo $((6*7))' vaut 42 en bash ; en tmsh, c'est une erreur.
    """
    # 1) Sonde tmsh : sortie typique de "show sys version" et code retour 0.
    try:
        out, _err, rc = run(client, "show sys version", timeout=timeout)
        if rc == 0 and re.search(r"Sys::Version|Product\s+BIG-IP", out):
            return "tmsh"
    except Exception:
        pass

    # 2) Sonde bash : l'arithmétique shell renvoie exactement 42.
    try:
        out, _err, rc = run(client, "echo $((6*7))", timeout=timeout)
        if rc == 0 and out.strip() == "42":
            return "bash"
    except Exception:
        pass

    raise RuntimeError("Shell distant non reconnu (sondes tmsh et bash échouées)")


def _nettoyer_secret(texte: str, secret: str) -> str:
    """Empêche la propagation accidentelle du mot de passe dans les sorties."""
    return texte.replace(secret, "[MASQUÉ]") if secret else texte


def _nom_fichier(name: str) -> str:
    """Les identifiants de commandes sont des noms de fichier sûrs et stables."""
    return name + ".txt"


def _resume(results: Dict[str, Dict[str, Any]]) -> None:
    print("\nRésumé de la capture :")
    for name, result in results.items():
        status = result.get("status", "ERREUR")
        n = result.get("bytes", 0)
        print("[{:6}] {:32} ({} octets)".format(status, name, n))


def lire_fichier_equipements(path: Path) -> List[Tuple[str, int, str]]:
    """Lit un fichier d'équipements : hote[:port][;label] par ligne."""
    equipements: List[Tuple[str, int, str]] = []
    for numero, brut in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        ligne = brut.strip()
        if not ligne or ligne.startswith("#"):
            continue
        adresse, _sep, label = ligne.partition(";")
        adresse = adresse.strip()
        label = label.strip()
        host, port = adresse, 22
        if ":" in adresse:
            host, _sep2, port_txt = adresse.rpartition(":")
            host = host.strip()
            try:
                port = int(port_txt)
            except ValueError:
                raise ValueError("{}:{} port invalide : {!r}".format(path, numero, port_txt))
        if not host:
            raise ValueError("{}:{} hôte vide".format(path, numero))
        equipements.append((host, port, label or host))
    if not equipements:
        raise ValueError("Aucun équipement trouvé dans {}".format(path))
    return equipements


def demander_phase() -> str:
    """Demande interactivement la phase de capture."""
    while True:
        reponse = input("Phase de capture (before/after) : ").strip().lower()
        if reponse in ("before", "after"):
            return reponse
        print("Réponse invalide, saisir 'before' ou 'after'.")


def capturer_equipement(host: str, port: int, label: str, phase: str,
                        user: str, password: str, outdir: str,
                        shell_force: str = "auto") -> bool:
    """Capture un équipement. Renvoie True si la capture a pu être réalisée."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    capture_dir = Path(outdir) / "{}_{}_{}".format(label, phase, timestamp)
    capture_dir.mkdir(parents=True, exist_ok=True)

    try:
        client = ouvrir_client(host, port, user, password)
    except Exception as exc:
        message = _nettoyer_secret(str(exc), password)
        print("[ERREUR] Connexion SSH impossible : {}".format(message), file=sys.stderr)
        return False

    try:
        if shell_force != "auto":
            shell = shell_force
        else:
            try:
                shell = _detecter_shell(client)
            except Exception as exc:
                print("[ERREUR] Détection du shell impossible : {}".format(
                    _nettoyer_secret(str(exc), password)), file=sys.stderr)
                return False
        print("[*] Shell détecté : {}".format(shell))
        results: Dict[str, Dict[str, Any]] = {}

        for name, cmd in COMMANDS:
            try:
                remote_cmd = adapter_commande(cmd, shell)
                out, err, rc = run(client, remote_cmd, timeout=180)
                out = _nettoyer_secret(out, password)
                err = _nettoyer_secret(err, password)
                if name == "ltm_rule":
                    out = filter_sys_rules(out)
                content = out
                if err.strip():
                    content += "\n### STDERR ###\n" + err
                (capture_dir / _nom_fichier(name)).write_text(content, encoding="utf-8")
                status = "ERREUR" if rc else ("OK" if out.strip() else "VIDE")
                results[name] = {"status": status, "bytes": len(out.encode("utf-8")), "return_code": rc}
            except Exception as exc:
                message = _nettoyer_secret(str(exc), password)
                (capture_dir / _nom_fichier(name)).write_text("\n### STDERR ###\n" + message, encoding="utf-8")
                results[name] = {"status": "ERREUR", "bytes": 0, "error": message}
            print("[{:6}] {:32} ({} octets)".format(
                results[name]["status"], name, results[name]["bytes"]))

        metadata = {
            "host": host,
            "port": port,
            "label": label,
            "phase": phase,
            "timestamp": timestamp,
            "shell": shell,
            "results": results,
        }
        (capture_dir / "_meta.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _resume(results)
        print("\nCapture enregistrée dans : {}".format(capture_dir))
        return True
    finally:
        try:
            client.close()
        except Exception:
            pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture de configuration BIG-IP par SSH.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--host", help="Nom ou adresse IP d'un BIG-IP")
    source.add_argument("-f", "--hosts-file", dest="hosts_file",
                        help="Fichier d'équipements : hote[:port][;label] par ligne")
    parser.add_argument("--port", type=int, default=22, help="Port SSH avec --host (défaut : 22)")
    parser.add_argument("--user", help="Login SSH (demandé si absent)")
    parser.add_argument("--label", help="Étiquette d'équipement avec --host (défaut : l'hôte)")
    parser.add_argument("--phase", choices=("before", "after"),
                        help="Phase de capture (demandée si absente)")
    parser.add_argument("--shell", choices=("auto", "tmsh", "bash"), default="auto",
                        help="Forcer le shell distant (défaut : détection automatique)")
    parser.add_argument("--outdir", default="captures", help="Répertoire de sortie")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)

    if args.hosts_file:
        try:
            equipements = lire_fichier_equipements(Path(args.hosts_file))
        except (OSError, ValueError) as exc:
            print("[ERREUR] Fichier d'équipements : {}".format(exc), file=sys.stderr)
            return 2
    else:
        equipements = [(args.host, args.port, args.label or args.host)]

    phase = args.phase or demander_phase()
    user = args.user
    if user is None:
        user = input("Login [admin] : ").strip() or "admin"
    password = getpass.getpass("Mot de passe SSH : ")

    bilan: List[Tuple[str, bool]] = []
    total = len(equipements)
    for index, (host, port, label) in enumerate(equipements, start=1):
        print("\n=== [{}/{}] {} ({}:{}) - phase {} ===".format(
            index, total, label, host, port, phase))
        try:
            ok = capturer_equipement(host, port, label, phase, user, password,
                                     args.outdir, args.shell)
        except Exception as exc:
            print("[ERREUR] {} : {}".format(label, _nettoyer_secret(str(exc), password)), file=sys.stderr)
            ok = False
        bilan.append((label, ok))

    if total > 1:
        print("\n=== Récapitulatif ({}) ===".format(phase))
        for label, ok in bilan:
            print("[{}] {}".format("OK    " if ok else "ERREUR", label))

    return 0 if all(ok for _label, ok in bilan) else 1


if __name__ == "__main__":
    sys.exit(main())
