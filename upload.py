#!/usr/bin/env python3
"""Transfère un ISO BIG-IP vers /shared/images par SFTP (sans installation)."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import re
import shlex
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import paramiko

DOSSIER_DISTANT = "/shared/images"
PORT_SSH = 22
_log_lock = threading.Lock()


def log(message: str, niveau: str = "INFO") -> None:
    """Affiche des messages sérialisés, sans inclure de secrets."""
    with _log_lock:
        print(f"[{niveau}] {message}", flush=True)


def fmt_taille(octets: Optional[int]) -> str:
    if octets is None:
        return "inconnue"
    valeur = float(octets)
    for unite in ("o", "Kio", "Mio", "Gio", "Tio"):
        if valeur < 1024 or unite == "Tio":
            return f"{valeur:.1f} {unite}"
        valeur /= 1024
    return f"{valeur:.1f} Tio"


def _hash_fichier(chemin: Path, algorithme: str) -> str:
    h = hashlib.new(algorithme)
    with chemin.open("rb") as fichier:
        for bloc in iter(lambda: fichier.read(1024 * 1024), b""):
            h.update(bloc)
    return h.hexdigest()


def sha256_local(chemin: Path) -> str:
    return _hash_fichier(chemin, "sha256")


def md5_local(chemin: Path) -> str:
    return _hash_fichier(chemin, "md5")


def verifier_md5_fournisseur(chemin: Path, md5: str) -> tuple[bool, str]:
    """Compare le MD5 local au checksum fournisseur dans un fichier compagnon.

    Cherche d'abord <iso>.md5, puis <nom sans extension>.md5. Accepte les
    formats usuels « hash fichier », « hash » et « MD5 (fichier) = hash ».
    En l'absence de checksum fournisseur, indique qu'aucune comparaison n'a
    été faite; le calcul MD5 local est néanmoins conservé dans le récapitulatif.
    """
    candidats = (Path(str(chemin) + ".md5"), chemin.with_suffix(".md5"))
    fichier_md5 = next((p for p in candidats if p.is_file()), None)
    if fichier_md5 is None:
        return True, "checksum fournisseur absent (comparaison ignorée)"
    try:
        texte = fichier_md5.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"lecture du checksum fournisseur impossible: {exc}"
    trouve = re.search(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", texte)
    if not trouve:
        return False, f"aucun MD5 valide trouvé dans {fichier_md5.name}"
    attendu = trouve.group(0).lower()
    if md5.lower() != attendu:
        return False, f"MD5 différent du checksum fournisseur ({fichier_md5.name})"
    return True, f"MD5 conforme au checksum fournisseur ({fichier_md5.name})"


def parse_hote(valeur: str) -> tuple[str, int]:
    """Parse host, host:port ou [IPv6]:port."""
    valeur = valeur.strip()
    if not valeur:
        raise ValueError("nom d'équipement vide")
    if valeur.startswith("["):
        fin = valeur.find("]")
        if fin < 0:
            raise ValueError(f"adresse IPv6 invalide: {valeur}")
        hote = valeur[1:fin]
        reste = valeur[fin + 1:]
        port = int(reste[1:]) if reste.startswith(":") else PORT_SSH
    elif valeur.count(":") == 1:
        hote, port_txt = valeur.rsplit(":", 1)
        port = int(port_txt)
    else:
        hote, port = valeur, PORT_SSH
    if not hote or not 1 <= port <= 65535:
        raise ValueError(f"équipement ou port invalide: {valeur}")
    return hote, port


def charger_hotes(arguments: list[str], fichier: Optional[str]) -> list[tuple[str, int]]:
    valeurs = list(arguments)
    if fichier:
        with open(fichier, encoding="utf-8") as entree:
            for ligne in entree:
                ligne = ligne.split("#", 1)[0].strip()
                if ligne:
                    valeurs.append(ligne)
    resultats: list[tuple[str, int]] = []
    vus: set[tuple[str, int]] = set()
    for valeur in valeurs:
        hote = parse_hote(valeur)
        if hote not in vus:
            resultats.append(hote)
            vus.add(hote)
    return resultats


class Bigip:
    def __init__(self, hote: str, port: int, utilisateur: str, mot_de_passe: str,
                 timeout: float = 20.0):
        self.hote, self.port = hote, port
        self.utilisateur = utilisateur
        self.client = paramiko.SSHClient()
        # Politique explicitement demandée: accepter automatiquement les clés inconnues.
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.shell: Optional[str] = None
        try:
            self.client.connect(
                hostname=hote, port=port, username=utilisateur,
                password=mot_de_passe, timeout=timeout,
                look_for_keys=False, allow_agent=False,
            )
        except (paramiko.BadAuthenticationType, paramiko.AuthenticationException) as erreur:
            transport = self.client.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError(self._message_auth(erreur)) from erreur
            try:
                # Certains BIG-IP exposent uniquement keyboard-interactive.
                transport.auth_interactive(utilisateur, self._handler_interactif(mot_de_passe))
            except (paramiko.BadAuthenticationType, paramiko.AuthenticationException) as fallback:
                if not getattr(fallback, "allowed_types", None) and getattr(erreur, "allowed_types", None):
                    fallback.allowed_types = erreur.allowed_types
                raise RuntimeError(self._message_auth(fallback)) from fallback
        self._detecter_shell()

    @staticmethod
    def _message_auth(erreur: Exception) -> str:
        methodes = getattr(erreur, "allowed_types", None)
        if methodes:
            return "Authentification refusée; méthodes autorisées: " + ", ".join(methodes)
        return "Authentification refusée (password et keyboard-interactive)"

    @staticmethod
    def _handler_interactif(mot_de_passe: str):
        def repondre(titre: str, instructions: str, prompts: list[tuple[str, bool]]) -> list[str]:
            return [mot_de_passe for _ in prompts]
        return repondre

    def _exec_brut(self, commande: str) -> tuple[str, str, int]:
        stdin, stdout, stderr = self.client.exec_command(commande)
        sortie = stdout.read().decode("utf-8", errors="replace")
        erreur = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        return sortie, erreur, code

    def _detecter_shell(self) -> None:
        """Détecte bash par echo __SH__$0; sinon confirme tmsh par sys version.

        $0 n'est pas fiable quand exec_command est lancé sous tmsh: une erreur,
        une sortie vide, un code non nul ou une réponse sans bash/sh entraîne
        donc une vérification explicite avec « show sys version » puis
        « list sys version ». Un shell inconnu fait échouer la connexion.
        """
        sortie, erreur, code = self._exec_brut("echo __SH__$0")
        contenu = (sortie + "\n" + erreur).lower()
        if code == 0 and not erreur.strip() and "__sh__" in contenu and ("bash" in contenu or re.search(r"\bsh\b", contenu)):
            self.shell = "bash"
            log(f"{self.hote}: shell bash détecté")
            return
        for commande in ("show sys version", "list sys version"):
            sortie, erreur, code = self._exec_brut(commande)
            texte = (sortie + "\n" + erreur).lower()
            if code == 0 and sortie.strip() and "syntax error" not in texte and "unknown" not in texte and ("version" in texte or "product" in texte):
                self.shell = "tmsh"
                log(f"{self.hote}: shell tmsh détecté")
                return
        raise RuntimeError(f"{self.hote}: shell non reconnu (bash ou tmsh attendu)")

    def _adapter_commande(self, commande: str) -> str:
        if self.shell == "bash":
            return commande
        if self.shell == "tmsh":
            # shlex.quote protège toute la commande en tant qu'un seul argument bash.
            return "run /util bash -c " + shlex.quote(commande)
        raise RuntimeError("shell non détecté")

    def run(self, commande: str) -> tuple[str, str, int]:
        return self._exec_brut(self._adapter_commande(commande))

    def close(self) -> None:
        self.client.close()


@dataclass
class Resultat:
    equipement: str
    statut: str
    detail: str = ""
    duree: float = 0.0


def traiter_equipement(equipement: tuple[str, int], iso: Path, taille: int,
                        sha256: str, md5: str, utilisateur: str,
                        mot_de_passe: str, force: bool = False) -> Resultat:
    hote, port = equipement
    debut = time.monotonic()
    bigip: Optional[Bigip] = None
    sftp = None
    try:
        log(f"{hote}: connexion…")
        bigip = Bigip(hote, port, utilisateur, mot_de_passe)
        # Garantit la présence du répertoire cible, quel que soit le shell.
        sortie, erreur, code = bigip.run(f"mkdir -p {shlex.quote(DOSSIER_DISTANT)}")
        if code != 0:
            raise RuntimeError(f"création de {DOSSIER_DISTANT} impossible: {(erreur or sortie).strip()}")
        chemin_distant = f"{DOSSIER_DISTANT}/{iso.name}"
        if not force:
            sortie, erreur, code = bigip.run(f"test -f {shlex.quote(chemin_distant)} && echo __PRESENT__")
            if code == 0 and "__PRESENT__" in sortie:
                return Resultat(hote, "IGNORÉ", "fichier déjà présent (--force pour remplacer)", time.monotonic() - debut)
        # Espace disponible en octets; extraction de la dernière ligne de df.
        commande_df = f"df -P -B1 {shlex.quote(DOSSIER_DISTANT)} | tail -1 | awk '{{print $4}}'"
        sortie, erreur, code = bigip.run(commande_df)
        try:
            espace = int(sortie.strip().splitlines()[-1]) if code == 0 else None
        except (ValueError, IndexError):
            espace = None
        if espace is not None and espace < taille:
            raise RuntimeError(f"espace insuffisant: {fmt_taille(espace)} disponibles, {fmt_taille(taille)} requis")
        try:
            sftp = bigip.client.open_sftp()
        except Exception as exc:
            if bigip.shell == "tmsh":
                raise RuntimeError(
                    f"ouverture SFTP refusée sous tmsh; activez bash manuellement avec "
                    f"« tmsh modify auth user {utilisateur} shell bash » (commande non exécutée). Détail: {exc}"
                ) from exc
            raise RuntimeError(f"impossible d'ouvrir SFTP: {exc}") from exc
        deja = -1
        prochain = 10
        def progression(transfere: int, total: int) -> None:
            nonlocal deja, prochain
            pct = min(100, int(transfere * 100 / total)) if total else 100
            jalon = (pct // 10) * 10
            while prochain <= jalon and prochain <= 100:
                log(f"{hote}: transfert {prochain}% ({fmt_taille(transfere)} / {fmt_taille(total)})")
                deja = prochain
                prochain += 10
        log(f"{hote}: transfert de {iso.name} ({fmt_taille(taille)})…")
        sftp.put(str(iso), chemin_distant, callback=progression)
        # Vérification SHA-256 distante; sortie vide n'est pas considérée comme succès.
        sortie, erreur, code = bigip.run(f"sha256sum {shlex.quote(chemin_distant)}")
        match = re.search(r"\b([0-9a-fA-F]{64})\b", sortie)
        if code != 0 or not match:
            raise RuntimeError(f"SHA-256 distant indisponible ou invalide: {(erreur or sortie).strip() or 'sortie vide'}")
        if match.group(1).lower() != sha256.lower():
            raise RuntimeError("échec de vérification SHA-256 (empreinte différente)")
        return Resultat(hote, "OK", "transfert et SHA-256 vérifiés", time.monotonic() - debut)
    except Exception as exc:
        # Ne pas révéler les identifiants dans les journaux, même si un message tiers les contient.
        detail = str(exc).replace(mot_de_passe, "[masqué]") if mot_de_passe else str(exc)
        log(f"{hote}: {detail}", "ERREUR")
        return Resultat(hote, "ERREUR", detail, time.monotonic() - debut)
    finally:
        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                pass
        if bigip is not None:
            try:
                bigip.close()
            except Exception:
                pass


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Transférer un ISO BIG-IP vers /shared/images via SFTP (sans installation).")
    parser.add_argument("iso", help="chemin du fichier ISO local")
    parser.add_argument("hosts", nargs="*", help="équipements (hôte, hôte:port ou [IPv6]:port)")
    parser.add_argument("-f", "--hosts-file", help="fichier d'équipements, un par ligne (# pour les commentaires)")
    parser.add_argument("-u", "--user", help="login SSH (mot de passe toujours demandé de façon interactive)")
    parser.add_argument("-w", "--workers", type=int, default=4, help="nombre maximal de transferts parallèles (défaut: 4)")
    parser.add_argument("--force", action="store_true", help="remplacer un ISO déjà présent")
    args = parser.parse_args(argv)
    iso = Path(args.iso).expanduser()
    if not iso.is_file():
        parser.error(f"fichier ISO introuvable: {iso}")
    if args.workers < 1:
        parser.error("--workers doit être supérieur ou égal à 1")
    try:
        equipements = charger_hotes(args.hosts, args.hosts_file)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if not equipements:
        parser.error("fournir au moins un équipement ou un fichier -f/--hosts-file")
    # Les invites sont uniques et précèdent tout calcul de checksum local.
    utilisateur = args.user
    if utilisateur is None:
        utilisateur = input("Login [admin] : ").strip() or "admin"
    mot_de_passe = getpass.getpass("Mot de passe SSH : ")
    if not mot_de_passe:
        parser.error("le mot de passe ne peut pas être vide")
    taille = iso.stat().st_size
    log(f"Fichier: {iso.name} ({fmt_taille(taille)})")
    log("Calcul des empreintes locales (SHA-256 et MD5)…")
    try:
        sha256 = sha256_local(iso)
        md5 = md5_local(iso)
    except OSError as exc:
        log(f"lecture de l'ISO impossible: {exc}", "ERREUR")
        return 1
    conforme, commentaire = verifier_md5_fournisseur(iso, md5)
    log(f"SHA-256 local: {sha256}")
    log(f"MD5 local: {md5} — {commentaire}")
    if not conforme:
        log("Le checksum MD5 fournisseur ne correspond pas; arrêt avant transfert.", "ERREUR")
        return 1
    log(f"Équipements: {len(equipements)} | parallélisme: {args.workers} | destination: {DOSSIER_DISTANT}")
    resultats: list[Resultat] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(traiter_equipement, e, iso, taille, sha256, md5,
                               utilisateur, mot_de_passe, args.force) for e in equipements]
        for future in as_completed(futures):
            try:
                resultats.append(future.result())
            except Exception as exc:  # protection contre une erreur inattendue de worker
                log(f"Erreur inattendue d'un worker: {exc}", "ERREUR")
                resultats.append(Resultat("?", "ERREUR", str(exc)))
    print("\nRÉCAPITULATIF")
    print(f"{'Équipement':<28} {'Statut':<10} {'Durée':>8}  Détail")
    print("-" * 90)
    for r in sorted(resultats, key=lambda x: x.equipement):
        print(f"{r.equipement:<28} {r.statut:<10} {r.duree:>7.1f}s  {r.detail}")
    ok = sum(r.statut == "OK" for r in resultats)
    ignores = sum(r.statut == "IGNORÉ" for r in resultats)
    erreurs = sum(r.statut == "ERREUR" for r in resultats)
    print(f"\nTotal: {len(resultats)} | réussis: {ok} | ignorés: {ignores} | erreurs: {erreurs}")
    # Le mot de passe est conservé uniquement en mémoire pour l'authentification.
    mot_de_passe = ""
    return 1 if erreurs else 0


if __name__ == "__main__":
    sys.exit(main())
