#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Récupération en lecture seule des fichiers de configuration BIG-IP via SSH.

Fichiers récupérés :
    /config/bigip.conf
    /config/bigip_base.conf
    /config/partitions/<partition>/bigip.conf   (une par partition)

Sans --phase, demande la phase de capture : 1 = before, 2 = after.

Usage:
    python capture_conf.py --host 10.0.0.11 --label bigip-a [--phase 1|2]
    python capture_conf.py -f equipements.txt [--phase before|after] [--shell tmsh]

Format du fichier d'équipements (une ligne par équipement) :
    hote[:port][;label]
Les lignes vides et celles commençant par # sont ignorées.
"""

import argparse
import getpass
import hashlib
import json
import re
import shlex
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CONFIG_DIR = "/config"
FICHIERS_FIXES: List[Tuple[str, str, str]] = [
    # (identifiant, chemin distant, nom local)
    ("bigip_conf", CONFIG_DIR + "/bigip.conf", "bigip.conf"),
    ("bigip_base_conf", CONFIG_DIR + "/bigip_base.conf", "bigip_base.conf"),
]
# Nom de partition valide : lettres, chiffres, tiret, underscore, point.
PARTITION_VALIDE = re.compile(r"^[A-Za-z0-9._-]+$")


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


def run_brut(client: Any, cmd: str, timeout: int = 180) -> Tuple[bytes, str, int]:
    """Comme run(), mais conserve stdout en octets bruts (pas de décodage)."""
    _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read()
    if not isinstance(out, bytes):
        out = str(out).encode("utf-8")
    err = _sortie(stderr)
    rc = stdout.channel.recv_exit_status()
    return out, err, rc


def adapter_commande_bash(cmd_bash: str, shell: str) -> str:
    """Enveloppe une commande bash selon le shell de connexion distant."""
    if shell == "bash":
        return cmd_bash
    if shell == "tmsh":
        return "run /util bash -c {}".format(shlex.quote(cmd_bash))
    raise ValueError("shell non pris en charge : {}".format(shell))


def _erreur_shell(sortie: str, erreur: str) -> bool:
    """Détecte l'erreur typique d'un mauvais choix de shell (tmsh vs bash)."""
    texte = (sortie + " " + erreur).lower()
    return (
        ("syntax error" in texte and "unexpected argument" in texte)
        or "command not found" in texte
        or "unexpected argument" in texte
    )


def autre_shell(shell: str) -> str:
    return "bash" if shell == "tmsh" else "tmsh"


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
    try:
        out, _err, rc = run(client, "show sys version", timeout=timeout)
        if rc == 0 and re.search(r"Sys::Version|Product\s+BIG-IP", out):
            return "tmsh"
    except Exception:
        pass

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


def run_bash_adaptatif(client: Any, cmd_bash: str, shell: str, timeout: int = 180,
                       brut: bool = False) -> Tuple[Any, str, int, str]:
    """Exécute une commande bash avec repli automatique sur l'autre shell.

    Renvoie (stdout, stderr, code, shell_effectif). Le repli n'a lieu que si
    l'échec ressemble à une mauvaise détection de shell, jamais pour une
    vraie erreur de commande (fichier absent, etc.)."""
    executeur = run_brut if brut else run
    dernier: Tuple[Any, str, int, str] = ("", "", 1, shell)
    for candidat in (shell, autre_shell(shell)):
        out, err, rc = executeur(client, adapter_commande_bash(cmd_bash, candidat), timeout=timeout)
        out_txt = out.decode("utf-8", errors="replace") if isinstance(out, bytes) else out
        dernier = (out, err, rc, candidat)
        if rc == 0 and not _erreur_shell(out_txt if not brut else "", err):
            return dernier
        if not _erreur_shell(out_txt if not brut else "", err):
            break  # vraie erreur de commande : inutile de changer de shell
    return dernier


def lister_partitions(client: Any, shell: str) -> List[str]:
    """Liste les partitions ayant un bigip.conf dédié (hors Common)."""
    out, _err, _rc, _sh = run_bash_adaptatif(
        client, "ls -1 {}/partitions 2>/dev/null".format(CONFIG_DIR), shell, timeout=60)
    partitions: List[str] = []
    for ligne in out.splitlines():
        nom = ligne.strip()
        if not nom:
            continue
        if not PARTITION_VALIDE.match(nom):
            print("[ATTENTION] Partition ignorée (nom inattendu) : {!r}".format(nom),
                  file=sys.stderr)
            continue
        partitions.append(nom)
    return partitions


def recuperer_fichier(client: Any, shell: str, chemin_distant: str,
                      chemin_local: Path, password: str) -> Dict[str, Any]:
    """Lit un fichier distant par cat, vérifie la taille et écrit en local."""
    # shlex.quote protège le chemin ; les noms de partition sont déjà validés.
    cmd_cat = "cat {}".format(shlex.quote(chemin_distant))
    cmd_wc = "wc -c < {}".format(shlex.quote(chemin_distant))

    try:
        contenu, err, rc, shell_effectif = run_bash_adaptatif(
            client, cmd_cat, shell, timeout=180, brut=True)
    except Exception as exc:
        return {"status": "ERREUR", "bytes": 0,
                "error": _nettoyer_secret(str(exc), password)}

    if rc != 0:
        message = _nettoyer_secret(err.strip() or "code retour {}".format(rc), password)
        return {"status": "ERREUR", "bytes": 0, "return_code": rc, "error": message}
    if not contenu.strip():
        return {"status": "VIDE", "bytes": 0, "return_code": rc}

    # Contrôle d'intégrité : taille annoncée par le BIG-IP = octets reçus.
    taille_distante: Optional[int] = None
    try:
        out_wc, _e, rc_wc, _sh = run_bash_adaptatif(
            client, cmd_wc, shell_effectif, timeout=60)
        if rc_wc == 0 and out_wc.strip().isdigit():
            taille_distante = int(out_wc.strip())
    except Exception:
        pass

    chemin_local.write_bytes(contenu)
    resultat: Dict[str, Any] = {
        "status": "OK",
        "bytes": len(contenu),
        "return_code": rc,
        "sha256": hashlib.sha256(contenu).hexdigest(),
        "remote_path": chemin_distant,
    }
    if taille_distante is not None:
        resultat["remote_bytes"] = taille_distante
        if taille_distante != len(contenu):
            resultat["status"] = "ERREUR"
            resultat["error"] = "taille différente : {} reçus, {} attendus".format(
                len(contenu), taille_distante)
    return resultat


def _resume(results: Dict[str, Dict[str, Any]]) -> None:
    print("\nRésumé de la capture :")
    for name, result in results.items():
        status = result.get("status", "ERREUR")
        n = result.get("bytes", 0)
        print("[{:6}] {:40} ({} octets)".format(status, name, n))


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


def normaliser_phase(value: str) -> str:
    """Accepte 1/2, before/after, b/a, avant/apres."""
    value = value.strip().lower()
    aliases = {"1": "before", "b": "before", "avant": "before",
               "2": "after", "a": "after", "apres": "after", "après": "after"}
    value = aliases.get(value, value)
    if value not in ("before", "after"):
        raise argparse.ArgumentTypeError("la phase doit être 1/before ou 2/after")
    return value


def demander_phase() -> str:
    """Demande interactivement la phase de capture (1 = before, 2 = after)."""
    print("Quelle est la phase de cette capture ?")
    print("  1) before (avant l'intervention)")
    print("  2) after  (après l'intervention)")
    while True:
        try:
            reponse = input("Choix [1/2] : ")
        except EOFError as exc:
            raise RuntimeError("aucune phase fournie") from exc
        try:
            return normaliser_phase(reponse)
        except argparse.ArgumentTypeError:
            print("Valeur invalide. Saisir 1 (before) ou 2 (after).", file=sys.stderr)


def capturer_equipement(host: str, port: int, label: str, phase: str,
                        user: str, password: str, outdir: str,
                        shell_force: str = "auto") -> bool:
    """Récupère les fichiers de configuration. True si tout a été récupéré."""
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

        # Liste des fichiers : fixes + un bigip.conf par partition.
        fichiers: List[Tuple[str, str, str]] = list(FICHIERS_FIXES)
        try:
            partitions = lister_partitions(client, shell)
        except Exception as exc:
            print("[ATTENTION] Liste des partitions impossible : {}".format(
                _nettoyer_secret(str(exc), password)), file=sys.stderr)
            partitions = []
        for partition in partitions:
            fichiers.append((
                "partition_{}_bigip_conf".format(partition),
                "{}/partitions/{}/bigip.conf".format(CONFIG_DIR, partition),
                "partition_{}_bigip.conf".format(partition),
            ))
        print("[*] Partitions détectées : {}".format(", ".join(partitions) or "aucune (Common seule)"))

        results: Dict[str, Dict[str, Any]] = {}
        for identifiant, chemin_distant, nom_local in fichiers:
            res = recuperer_fichier(client, shell, chemin_distant,
                                    capture_dir / nom_local, password)
            res["local_file"] = nom_local
            results[identifiant] = res
            print("[{:6}] {:40} ({} octets)".format(res["status"], nom_local, res["bytes"]))
            if res.get("error"):
                print("         -> {}".format(res["error"]), file=sys.stderr)

        metadata = {
            "host": host,
            "port": port,
            "label": label,
            "phase": phase,
            "timestamp": timestamp,
            "shell": shell,
            "partitions": partitions,
            "results": results,
        }
        (capture_dir / "_meta.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _resume(results)
        print("\nCapture enregistrée dans : {}".format(capture_dir))
        return all(r["status"] == "OK" for r in results.values())
    finally:
        try:
            client.close()
        except Exception:
            pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Récupération des fichiers de configuration BIG-IP par SSH.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--host", help="Nom ou adresse IP d'un BIG-IP")
    source.add_argument("-f", "--hosts-file", dest="hosts_file",
                        help="Fichier d'équipements : hote[:port][;label] par ligne")
    parser.add_argument("--port", type=int, default=22, help="Port SSH avec --host (défaut : 22)")
    parser.add_argument("--user", help="Login SSH (demandé si absent)")
    parser.add_argument("--label", help="Étiquette d'équipement avec --host (défaut : l'hôte)")
    parser.add_argument("--phase", type=normaliser_phase,
                        help="Phase de capture : 1/before ou 2/after (demandée si absente)")
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
            print("[ERREUR] {} : {}".format(label, _nettoyer_secret(str(exc), password)),
                  file=sys.stderr)
            ok = False
        bilan.append((label, ok))

    if total > 1:
        print("\n=== Récapitulatif ({}) ===".format(phase))
        for label, ok in bilan:
            print("[{}] {}".format("OK    " if ok else "ERREUR", label))

    return 0 if all(ok for _label, ok in bilan) else 1


if __name__ == "__main__":
    sys.exit(main())
