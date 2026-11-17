#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inventaire GTM (DNS) des BIG-IP en lecture seule : WideIP -> Pool -> Members.

Récupère via tmsh :
    gtm wideip         (Wide IPs et leurs pools, avec ordre et ratio)
    gtm pool a         (pools A, avec leurs membres)
    gtm pool aaaa      (pools AAAA, avec leurs membres)
    gtm pool cname / mx / naptr / srv  (autres types de pools)

Sorties :
    <outdir>/<label>_<phase>_<horodatage>/
        gtm_tree.txt      arborescence lisible
        gtm_inventory.json  données brutes structurées
        _meta.json        métadonnées de la capture

Usage:
    python capture_gtm.py --host 10.0.0.11 --label gtm-a [--phase 1|2]
    python capture_gtm.py -f equipements.txt [--phase before|after]
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

ETATS = {"1": "before", "before": "before", "b": "before", "avant": "before",
         "2": "after", "after": "after", "a": "after", "apres": "after", "après": "after"}

# Types de pools GTM à interroger.
TYPES_POOL = ["a", "aaaa", "cname", "mx", "naptr", "srv"]


# ---------------------------------------------------------------------------
# Connexion SSH (identique aux autres scripts)
# ---------------------------------------------------------------------------

def _sortie(flux: Any) -> str:
    valeur = flux.read()
    if isinstance(valeur, bytes):
        return valeur.decode("utf-8", errors="replace")
    return str(valeur)


def run(client: Any, cmd: str, timeout: int = 120) -> Tuple[str, str, int]:
    _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = _sortie(stdout)
    err = _sortie(stderr)
    rc = stdout.channel.recv_exit_status()
    return out, err, rc


def adapter_commande_bash(cmd_bash: str, shell: str) -> str:
    if shell == "bash":
        return cmd_bash
    if shell == "tmsh":
        return "run /util bash -c {}".format(shlex.quote(cmd_bash))
    raise ValueError("shell non pris en charge : {}".format(shell))


def _methodes_autorisees(erreurs: List[BaseException]) -> List[str]:
    methodes: List[str] = []
    for erreur in erreurs:
        for methode in getattr(erreur, "allowed_types", None) or []:
            if str(methode) not in methodes:
                methodes.append(str(methode))
    return methodes


def ouvrir_client(host: str, port: int, user: str, password: str, timeout: int = 30) -> Any:
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("Dépendance manquante : installer paramiko") from exc

    client = paramiko.SSHClient()
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
                    detail += "; méthodes autorisées : " + ", ".join(methodes)
                raise paramiko.AuthenticationException(detail)
            client._transport = transport
            return client
        except Exception:
            transport.close()
            raise


def _detecter_shell(client: Any) -> str:
    try:
        out, _err, rc = run(client, "show sys version", timeout=30)
        if rc == 0 and re.search(r"Sys::Version|Product\s+BIG-IP", out):
            return "tmsh"
    except Exception:
        pass
    try:
        out, _err, rc = run(client, "echo $((6*7))", timeout=30)
        if rc == 0 and out.strip() == "42":
            return "bash"
    except Exception:
        pass
    raise RuntimeError("Shell distant non reconnu (sondes tmsh et bash échouées)")


def _nettoyer_secret(texte: str, secret: str) -> str:
    return texte.replace(secret, "[MASQUÉ]") if secret else texte


# ---------------------------------------------------------------------------
# Lecture de la configuration GTM
# ---------------------------------------------------------------------------

def _tmsh(client: Any, shell: str, commande: str) -> str:
    """Exécute une commande tmsh en lecture seule et renvoie sa sortie.

    - Shell 'tmsh' : la commande est envoyée directement (pas de préfixe 'tmsh').
    - Shell 'bash' : on appelle le binaire tmsh explicitement.
    """
    if shell == "bash":
        cmd = "tmsh -q {}".format(commande)
    elif shell == "tmsh":
        cmd = "-q {}".format(commande)
    else:
        raise ValueError("shell non pris en charge : {}".format(shell))

    out, err, rc = run(client, cmd, timeout=180)
    if rc != 0:
        raise RuntimeError("commande '{}' en échec : {}".format(
            commande, err.strip() or "code {}".format(rc)))
    return out


def _lignes_config(texte: str) -> List[str]:
    """Nettoie la sortie tmsh et renvoie les lignes utiles."""
    return [l.rstrip() for l in texte.splitlines() if l.strip()]


def _extraire_blocs(texte: str) -> Dict[str, List[str]]:
    """Découpe la sortie `tmsh list` en blocs : nom complet -> lignes du bloc.

    Les blocs commencent par une ligne du type `gtm wideip ... {`.
    """
    blocs: Dict[str, List[str]] = {}
    courant: Optional[str] = None
    profondeur = 0
    for ligne in texte.splitlines():
        strip = ligne.strip()
        if courant is None:
            m = re.match(r"^(gtm\s+\S+\s+\S+)\s*\{", strip)
            if m:
                courant = m.group(1)
                blocs[courant] = []
                profondeur = 1
            continue
        profondeur += strip.count("{") - strip.count("}")
        if profondeur <= 0:
            courant = None
            continue
        blocs[courant].append(strip)
    return blocs


def _nom_court(nom_complet: str) -> str:
    """'/Common/www.example.com' -> '/Common/www.example.com' (on garde le nom)."""
    return nom_complet.split()[-1] if nom_complet else nom_complet


def _attribut(lignes: List[str], cle: str) -> Optional[str]:
    for ligne in lignes:
        if ligne.startswith(cle + " "):
            return ligne[len(cle):].strip().rstrip(";").strip()
    return None


def _pool_members(lignes: List[str]) -> List[Dict[str, Any]]:
    """Extrait les membres d'un pool GTM depuis son bloc."""
    membres: List[Dict[str, Any]] = []
    dans_members = False
    profondeur = 0
    courant: Optional[Dict[str, Any]] = None
    for ligne in lignes:
        if not dans_members:
            if ligne.startswith("members {"):
                dans_members = True
                profondeur = 1
            continue
        profondeur += ligne.count("{") - ligne.count("}")
        if profondeur <= 0:
            break
        m = re.match(r"^(\S+)\s*\{", ligne)
        if m and profondeur == 2:
            courant = {"name": m.group(1)}
            membres.append(courant)
            continue
        if courant is not None:
            m2 = re.match(r"^(\S+)\s+(.+?);?$", ligne)
            if m2 and m2.group(1) not in ("{", "}"):
                courant[m2.group(1)] = m2.group(2).rstrip(";")
    return membres


def _wideip_pools(lignes: List[str]) -> List[Dict[str, Any]]:
    """Extrait les pools référencés par une WideIP."""
    pools: List[Dict[str, Any]] = []
    dans_pools = False
    profondeur = 0
    courant: Optional[Dict[str, Any]] = None
    for ligne in lignes:
        if not dans_pools:
            if ligne.startswith("pools {"):
                dans_pools = True
                profondeur = 1
            continue
        profondeur += ligne.count("{") - ligne.count("}")
        if profondeur <= 0:
            break
        m = re.match(r"^(\S+)\s*\{", ligne)
        if m and profondeur == 2:
            courant = {"name": m.group(1)}
            pools.append(courant)
            continue
        if courant is not None:
            m2 = re.match(r"^(\S+)\s+(.+?);?$", ligne)
            if m2:
                courant[m2.group(1)] = m2.group(2).rstrip(";")
    return pools


def recuperer_gtm(client: Any, shell: str) -> Dict[str, Any]:
    """Récupère WideIPs, pools et membres GTM et les relie entre eux."""
    # WideIPs
    texte_wideip = _tmsh(client, shell, "list gtm wideip all")
    blocs_wideip = _extraire_blocs(texte_wideip)

    wideips: Dict[str, Dict[str, Any]] = {}
    for nom_complet, lignes in blocs_wideip.items():
        # nom_complet = 'gtm wideip a /Common/www.example.com'
        nom = nom_complet.split()[-1]
        type_wip = nom_complet.split()[2]
        wideips[nom] = {
            "name": nom,
            "type": type_wip,
            "pool_lb_mode": _attribut(lignes, "pool-lb-mode"),
            "pools": _wideip_pools(lignes),
        }

    # Pools (tous types)
    pools: Dict[str, Dict[str, Any]] = {}
    for type_pool in TYPES_POOL:
        try:
            texte_pool = _tmsh(client, shell, "list gtm pool {} all".format(type_pool))
        except RuntimeError:
            continue  # type de pool absent ou non supporté sur cette version
        for nom_complet, lignes in _extraire_blocs(texte_pool).items():
            nom = nom_complet.split()[-1]
            pools[nom] = {
                "name": nom,
                "type": type_pool,
                "lb_mode": _attribut(lignes, "load-balancing-mode"),
                "members": _pool_members(lignes),
            }

    return {"wideips": wideips, "pools": pools}


# ---------------------------------------------------------------------------
# Arborescence
# ---------------------------------------------------------------------------

def construire_arbre(donnees: Dict[str, Any]) -> str:
    """Produit l'arborescence WideIP -> Pool -> Members."""
    wideips = donnees["wideips"]
    pools = donnees["pools"]
    lignes: List[str] = []

    lignes.append("GTM : {} WideIP(s), {} pool(s)".format(len(wideips), len(pools)))
    lignes.append("")

    if not wideips:
        lignes.append("(aucune WideIP configurée)")
    for index, (nom_wip, wip) in enumerate(sorted(wideips.items())):
        est_dernier_wip = index == len(wideips) - 1
        branche = "└── " if est_dernier_wip else "├── "
        prefixe_wip = "    " if est_dernier_wip else "│   "
        lignes.append("{}WideIP [{}] {}  (lb: {})".format(
            branche, wip["type"].upper(), nom_wip, wip.get("pool_lb_mode") or "-"))

        pools_wip = wip["pools"]
        if not pools_wip:
            lignes.append("{}└── (aucun pool rattaché)".format(prefixe_wip))
            continue

        for j, ref in enumerate(pools_wip):
            dernier_pool = j == len(pools_wip) - 1
            b_pool = "└── " if dernier_pool else "├── "
            p_pool = "    " if dernier_pool else "│   "
            nom_pool = ref["name"]
            details = []
            if ref.get("order"):
                details.append("ordre {}".format(ref["order"]))
            if ref.get("ratio"):
                details.append("ratio {}".format(ref["ratio"]))
            entete = "{}Pool {}".format(b_pool, nom_pool)
            if details:
                entete += "  ({})".format(", ".join(details))
            lignes.append(prefixe_wip + entete)

            pool = pools.get(nom_pool)
            if pool is None:
                lignes.append("{}{}└── (pool introuvable dans l'inventaire)".format(
                    prefixe_wip, p_pool))
                continue
            lignes.append("{}{}  type {} | lb {}".format(
                prefixe_wip, p_pool, pool["type"].upper(), pool.get("lb_mode") or "-"))

            membres = pool["members"]
            if not membres:
                lignes.append("{}{}└── (aucun membre)".format(prefixe_wip, p_pool))
                continue
            for k, membre in enumerate(membres):
                dernier_m = k == len(membres) - 1
                b_m = "└── " if dernier_m else "├── "
                details_m = []
                if membre.get("ratio"):
                    details_m.append("ratio {}".format(membre["ratio"]))
                if membre.get("member-order"):
                    details_m.append("ordre {}".format(membre["member-order"]))
                texte = "{}{}{}Member {}".format(prefixe_wip, p_pool, b_m, membre["name"])
                if details_m:
                    texte += "  ({})".format(", ".join(details_m))
                lignes.append(texte)

    return "\n".join(lignes) + "\n"


# ---------------------------------------------------------------------------
# Capture par équipement
# ---------------------------------------------------------------------------

def capturer_equipement(host: str, port: int, label: str, phase: str,
                        user: str, password: str, outdir: str,
                        shell_force: str = "auto") -> bool:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    capture_dir = Path(outdir) / "{}_{}_{}".format(label, phase, timestamp)
    capture_dir.mkdir(parents=True, exist_ok=True)

    try:
        client = ouvrir_client(host, port, user, password)
    except Exception as exc:
        print("[ERREUR] Connexion SSH impossible : {}".format(
            _nettoyer_secret(str(exc), password)), file=sys.stderr)
        return False

    try:
        if shell_force != "auto":
            shell = shell_force
        else:
            shell = _detecter_shell(client)
        print("[*] Shell détecté : {}".format(shell))

        donnees = recuperer_gtm(client, shell)
        nb_wip = len(donnees["wideips"])
        nb_pool = len(donnees["pools"])
        nb_mbr = sum(len(p["members"]) for p in donnees["pools"].values())
        print("[*] {} WideIP, {} pool(s), {} membre(s) GTM".format(nb_wip, nb_pool, nb_mbr))

        arbre = construire_arbre(donnees)
        (capture_dir / "gtm_tree.txt").write_text(arbre, encoding="utf-8")
        (capture_dir / "gtm_inventory.json").write_text(
            json.dumps(donnees, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (capture_dir / "_meta.json").write_text(json.dumps({
            "host": host, "port": port, "label": label, "phase": phase,
            "timestamp": timestamp, "shell": shell,
            "wideips": nb_wip, "pools": nb_pool, "members": nb_mbr,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        print("\n" + arbre)
        print("Capture enregistrée dans : {}".format(capture_dir))
        return True
    except Exception as exc:
        print("[ERREUR] Capture GTM impossible : {}".format(
            _nettoyer_secret(str(exc), password)), file=sys.stderr)
        return False
    finally:
        try:
            client.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Entrée
# ---------------------------------------------------------------------------

def lire_fichier_equipements(path: Path) -> List[Tuple[str, int, str]]:
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
            try:
                port = int(port_txt)
            except ValueError:
                raise ValueError("{}:{} port invalide : {!r}".format(path, numero, port_txt))
        if not host:
            raise ValueError("{}:{} hôte vide".format(path, numero))
        equipements.append((host.strip(), port, label or host.strip()))
    if not equipements:
        raise ValueError("Aucun équipement trouvé dans {}".format(path))
    return equipements


def normaliser_etat(valeur: str) -> Optional[str]:
    return ETATS.get(valeur.strip().lower())


def demander_phase() -> str:
    print("Phase de capture :")
    print("  1) before")
    print("  2) after")
    while True:
        etat = normaliser_etat(input("Choix (1/2) : "))
        if etat:
            return etat
        print("Réponse invalide, saisir 1 ou 2.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inventaire GTM en arborescence WideIP -> Pool -> Members.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--host", help="Nom ou adresse IP d'un BIG-IP")
    source.add_argument("-f", "--hosts-file", dest="hosts_file",
                        help="Fichier d'équipements : hote[:port][;label] par ligne")
    parser.add_argument("--port", type=int, default=22, help="Port SSH avec --host")
    parser.add_argument("--user", help="Login SSH (demandé si absent)")
    parser.add_argument("--label", help="Étiquette avec --host (défaut : l'hôte)")
    parser.add_argument("--phase", "--etat", dest="phase",
                        help="Phase : 1/before ou 2/after (demandée si absente)")
    parser.add_argument("--shell", choices=("auto", "tmsh", "bash"), default="auto")
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

    if args.phase:
        phase = normaliser_etat(args.phase)
        if phase is None:
            print("[ERREUR] Phase invalide : {!r}".format(args.phase), file=sys.stderr)
            return 2
    else:
        phase = demander_phase()

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
