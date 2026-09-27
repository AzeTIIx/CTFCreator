"""Durcissement SSH progressif et réversible — sans se verrouiller dehors."""

from __future__ import annotations

import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (  # noqa: E402
    AppContext,
    build_context,
    confirm,
    is_linux,
    print_status,
    run_cmd,
    utc_now,
    validate_port,
    which,
    write_report,
)

# 10- : chargé avant 50-cloud-init.conf (Ubuntu) — sshd garde la première valeur lue
DROPIN_NAME = "10-course-ctfd-hardening.conf"
DROPIN_DIR = Path("/etc/ssh/sshd_config.d")
BACKUP_DIR = Path("/var/backups/course-ctfd/sshd")

DEFAULT_SETTINGS = {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "KbdInteractiveAuthentication": "no",
    "PubkeyAuthentication": "yes",
    "PermitEmptyPasswords": "no",
    "X11Forwarding": "no",
    "AllowTcpForwarding": "no",
    "AllowAgentForwarding": "no",
    "MaxAuthTries": "3",
    "LoginGraceTime": "20",
    "ClientAliveInterval": "300",
    "ClientAliveCountMax": "2",
    "UsePAM": "yes",
}

# Types OpenSSH courants (pas de clé privée ici)
PUBKEY_RE = re.compile(
    r"^(ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521)|"
    r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+"
    r"[A-Za-z0-9+/=]+(?:\s+\S+)?$"
)


def _active_ssh_session() -> bool:
    return bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT"))


def normalize_pubkey(raw: str) -> str:
    line = " ".join(raw.strip().split())
    if not line or line.startswith("#"):
        raise RuntimeError("clé publique vide")
    if not PUBKEY_RE.match(line):
        raise RuntimeError(
            "format de clé publique invalide (attendu: ssh-ed25519 AAAA… [comment])"
        )
    return line


def pubkey_core(line: str) -> str:
    """type + material (sans commentaire) pour comparaison idempotente."""
    parts = line.split()
    if len(parts) < 2:
        raise RuntimeError("clé publique incomplète")
    return f"{parts[0]} {parts[1]}"


def resolve_pubkey(
    pubkey: str | None = None,
    pubkey_file: str | None = None,
    env: dict | None = None,
) -> str:
    env = env or {}
    if pubkey and pubkey_file:
        raise RuntimeError("fournir --pubkey OU --pubkey-file, pas les deux")
    if pubkey:
        return normalize_pubkey(pubkey)
    if pubkey_file:
        path = Path(pubkey_file)
        if not path.is_file():
            raise RuntimeError(f"fichier clé publique introuvable : {path}")
        return normalize_pubkey(path.read_text(encoding="utf-8").strip().splitlines()[0])
    env_inline = (env.get("ADMIN_SSH_PUBKEY") or "").strip()
    if env_inline:
        return normalize_pubkey(env_inline)
    env_file = (env.get("ADMIN_SSH_PUBKEY_FILE") or "").strip()
    if env_file:
        path = Path(env_file)
        if not path.is_file():
            raise RuntimeError(f"ADMIN_SSH_PUBKEY_FILE introuvable : {path}")
        return normalize_pubkey(path.read_text(encoding="utf-8").strip().splitlines()[0])
    raise RuntimeError(
        "Clé publique obligatoire. Exemple :\n"
        "  python3 scripts/main.py harden-ssh --pubkey-file ~/.ssh/id_ed25519.pub\n"
        "  python3 scripts/main.py harden-ssh --pubkey 'ssh-ed25519 AAAA… comment'\n"
        "Ou ADMIN_SSH_PUBKEY / ADMIN_SSH_PUBKEY_FILE dans .env"
    )


def install_authorized_key(ctx: AppContext, username: str, pubkey: str) -> dict:
    """Installe la clé dans authorized_keys sans supprimer les clés existantes."""
    import pwd  # module POSIX — indisponible sur Windows (dev)

    info = {"user": username, "installed": False, "already_present": False, "path": None}
    try:
        pw = pwd.getpwnam(username)
    except KeyError as exc:
        raise RuntimeError(f"utilisateur ADMIN_SSH_USER inconnu : {username}") from exc

    ssh_dir = Path(pw.pw_dir) / ".ssh"
    auth_keys = ssh_dir / "authorized_keys"
    info["path"] = str(auth_keys)
    core = pubkey_core(pubkey)

    if ctx.dry_run:
        print_status("INFO", f"[dry-run] installer clé pour {username} → {auth_keys}")
        info["installed"] = True
        return info

    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    os.chown(ssh_dir, pw.pw_uid, pw.pw_gid)
    os.chmod(ssh_dir, 0o700)

    existing = ""
    if auth_keys.is_file():
        existing = auth_keys.read_text(encoding="utf-8", errors="replace")
        for line in existing.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if pubkey_core(line) == core:
                    info["already_present"] = True
                    print_status("OK", f"Clé déjà présente dans {auth_keys}")
                    return info
            except RuntimeError:
                continue

    with auth_keys.open("a", encoding="utf-8") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write(pubkey + "\n")
    os.chown(auth_keys, pw.pw_uid, pw.pw_gid)
    os.chmod(auth_keys, 0o600)
    info["installed"] = True
    print_status("OK", f"Clé publique ajoutée pour {username} (clés existantes conservées)")
    return info


def _render_dropin(ctx: AppContext) -> str:
    lines = [
        "# Généré par course-ctfd-infra — ne pas éditer à la main sans sauvegarde",
        f"# generated_at={utc_now()}",
    ]
    for key, value in DEFAULT_SETTINGS.items():
        lines.append(f"{key} {value}")
    if (ctx.env.get("ALLOW_USERS_ENABLED") or "").lower() in {"1", "true", "yes"}:
        users = (ctx.env.get("ALLOW_USERS") or "").strip()
        if not users:
            raise RuntimeError("ALLOW_USERS_ENABLED=true mais ALLOW_USERS vide")
        for user in users.split():
            if not user.replace("-", "").replace("_", "").isalnum():
                raise RuntimeError(f"Nom d'utilisateur AllowUsers invalide : {user}")
        lines.append(f"AllowUsers {users}")
    port = (ctx.env.get("SSH_PORT") or "22").strip()
    if not validate_port(port):
        raise RuntimeError(f"SSH_PORT invalide : {port}")
    if (ctx.env.get("SSH_PORT_CHANGE") or "").lower() in {"1", "true", "yes"}:
        lines.append(f"Port {port}")
    return "\n".join(lines) + "\n"


def _backup_sshd(ctx: AppContext) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = BACKUP_DIR / stamp
    if ctx.dry_run:
        print_status("INFO", f"[dry-run] sauvegarde SSH vers {dest}")
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(dest, 0o700)
    for src in (Path("/etc/ssh/sshd_config"), DROPIN_DIR):
        if src.is_file():
            target = dest / src.name
            shutil.copy2(src, target)
            shutil.copymode(src, target)
        elif src.is_dir():
            target_dir = dest / src.name
            if not target_dir.exists():
                shutil.copytree(src, target_dir)
    return dest


def _restore_backup(ctx: AppContext, backup: Path) -> None:
    print_status("WARN", f"Restauration automatique SSH depuis {backup}")
    if ctx.dry_run:
        return
    cfg = backup / "sshd_config"
    if cfg.is_file():
        shutil.copy2(cfg, "/etc/ssh/sshd_config")
    dropin_file = DROPIN_DIR / DROPIN_NAME
    if dropin_file.exists():
        dropin_file.unlink()
    dropins = backup / "sshd_config.d"
    if dropins.is_dir():
        for item in dropins.iterdir():
            if item.is_file():
                shutil.copy2(item, DROPIN_DIR / item.name)
    run_cmd(ctx, ["sshd", "-t"], check=False)
    run_cmd(ctx, ["systemctl", "reload", "ssh"], check=False)


def _test_new_ssh_connection(ctx: AppContext, identity_file: str | None) -> dict:
    """Tente une vraie nouvelle connexion uniquement si une identity privée est fournie."""
    result = {
        "tested": False,
        "success": False,
        "reason": None,
        "identity_used": bool(identity_file),
    }
    if not identity_file:
        result["reason"] = (
            "pas de --identity : impossible de tester depuis l'hôte sans clé privée "
            "(ne pas interpréter comme un échec de config)"
        )
        return result

    id_path = Path(identity_file)
    if not id_path.is_file():
        result["reason"] = f"fichier identity introuvable : {id_path}"
        return result

    host = (ctx.env.get("TARGET_HOST") or "").strip()
    user = (ctx.env.get("ADMIN_SSH_USER") or "").strip()
    port = (ctx.env.get("SSH_PORT") or "22").strip()
    if not host or not user or "example.invalid" in host:
        # Fallback loopback si TARGET_HOST est l'IP publique parfois OK ;
        # sinon 127.0.0.1 pour test local
        host = "127.0.0.1"
        print_status("WARN", "TARGET_HOST absent/exemple — test via 127.0.0.1")

    if not which("ssh"):
        result["reason"] = "client ssh absent"
        return result

    argv = [
        "ssh",
        "-i",
        str(id_path),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=8",
        "-p",
        port,
        f"{user}@{host}",
        "true",
    ]
    if ctx.dry_run:
        result["reason"] = "dry-run — connexion réelle non effectuée"
        return result
    r = run_cmd(ctx, argv, timeout=20)
    result["tested"] = True
    result["success"] = r.ok
    if not r.ok:
        result["reason"] = "nouvelle connexion SSH échouée (détails non affichés)"
    return result


def run_harden_ssh(
    ctx: AppContext | None = None,
    *,
    pubkey: str | None = None,
    pubkey_file: str | None = None,
    identity_file: str | None = None,
) -> int:
    ctx = ctx or build_context()
    print_status("INFO", "Durcissement SSH — contrôles de sécurité préalables")

    if not is_linux():
        print_status(
            "WARN",
            "Durcissement SSH non exécuté : hôte non Linux. Marqué NON EXÉCUTÉ.",
        )
        write_report(
            ctx,
            "harden-ssh",
            {
                "generated_at": utc_now(),
                "status": "not_executed",
                "reason": "not_linux",
                "platform": sys.platform,
            },
        )
        return 0

    admin_user = (ctx.env.get("ADMIN_SSH_USER") or "").strip()
    if not admin_user:
        print_status("FAIL", "ADMIN_SSH_USER manquant")
        return 2

    try:
        pubkey_line = resolve_pubkey(pubkey, pubkey_file, dict(ctx.env))
    except RuntimeError as exc:
        print_status("FAIL", str(exc))
        return 2

    identity = identity_file or (ctx.env.get("ADMIN_SSH_IDENTITY_FILE") or "").strip() or None

    if not _active_ssh_session():
        if not confirm(
            ctx,
            "Aucune session SSH détectée (SSH_CONNECTION absent). "
            "Continuer uniquement si accès console fournisseur garanti ?",
        ):
            print_status("FAIL", "Session SSH active requise ou confirmation refusée")
            return 2

    second = (ctx.env.get("SECOND_ADMIN_ACCESS_CONFIRMED") or "").lower() in {
        "1",
        "true",
        "yes",
    }
    if not second:
        if not confirm(
            ctx,
            "Aucun second accès admin confirmé (SECOND_ADMIN_ACCESS_CONFIRMED). "
            "Confirmer que la console fournisseur suffit ?",
        ):
            return 2

    if not which("sshd") and not Path("/usr/sbin/sshd").exists():
        print_status("FAIL", "sshd introuvable")
        return 2

    test = run_cmd(ctx, ["sshd", "-t"])
    if not test.ok and not ctx.dry_run:
        print_status("FAIL", "sshd -t échoue déjà — corriger avant durcissement")
        return 2

    # 1) Installer la clé AVANT de couper l'auth password
    try:
        key_meta = install_authorized_key(ctx, admin_user, pubkey_line)
    except RuntimeError as exc:
        print_status("FAIL", str(exc))
        return 2

    if not confirm(ctx, "Appliquer le drop-in de durcissement SSH ?"):
        return 1

    backup = _backup_sshd(ctx)
    print_status("OK", f"Sauvegarde SSH : {backup}")

    try:
        content = _render_dropin(ctx)
    except RuntimeError as exc:
        print_status("FAIL", str(exc))
        return 2

    dropin_path = DROPIN_DIR / DROPIN_NAME
    if not ctx.dry_run:
        DROPIN_DIR.mkdir(parents=True, exist_ok=True)
        dropin_path.write_text(content, encoding="utf-8")
        os.chmod(dropin_path, 0o644)

    test2 = run_cmd(ctx, ["sshd", "-t"])
    if not test2.ok and not ctx.dry_run:
        print_status("FAIL", "Nouvelle config invalide — restauration")
        _restore_backup(ctx, backup)
        write_report(
            ctx,
            "harden-ssh",
            {"generated_at": utc_now(), "status": "rolled_back", "backup": str(backup)},
        )
        return 3

    reload = run_cmd(ctx, ["systemctl", "reload", "ssh"])
    if not reload.ok:
        reload = run_cmd(ctx, ["systemctl", "reload", "sshd"])
    if not reload.ok and not ctx.dry_run:
        print_status("FAIL", "Reload ssh échoué — restauration")
        _restore_backup(ctx, backup)
        return 3

    conn = _test_new_ssh_connection(ctx, identity)
    if conn["tested"] and not conn["success"]:
        print_status("FAIL", "Validation nouvelle connexion échouée — restauration automatique")
        _restore_backup(ctx, backup)
        print_status(
            "INFO",
            "Procédure console fournisseur : se connecter via le panneau VPS, "
            f"restaurer {backup}, puis systemctl reload ssh",
        )
        write_report(
            ctx,
            "harden-ssh",
            {
                "generated_at": utc_now(),
                "status": "rolled_back_after_conn_fail",
                "connection_test": conn,
                "pubkey_install": {
                    "installed": key_meta.get("installed"),
                    "already_present": key_meta.get("already_present"),
                    "path": key_meta.get("path"),
                },
                "backup": str(backup),
            },
        )
        return 4

    if not conn.get("tested"):
        print_status("WARN", conn.get("reason") or "connexion non testée automatiquement")
        if not confirm(
            ctx,
            "Confirmez qu'une AUTRE session SSH avec cette clé fonctionne "
            "(ne fermez pas la session courante) ?",
        ):
            print_status("FAIL", "Confirmation refusée — restauration")
            _restore_backup(ctx, backup)
            return 4
        status = "applied_unverified_manual_confirm"
    else:
        status = "applied_and_verified"

    write_report(
        ctx,
        "harden-ssh",
        {
            "generated_at": utc_now(),
            "status": status,
            "backup": str(backup),
            "dropin": str(dropin_path),
            "connection_test": conn,
            "pubkey_install": {
                "installed": key_meta.get("installed"),
                "already_present": key_meta.get("already_present"),
                "path": key_meta.get("path"),
                # Ne jamais logger la clé complète
                "key_type": pubkey_line.split()[0],
            },
            "allow_users_applied": (ctx.env.get("ALLOW_USERS_ENABLED") or "").lower()
            in {"1", "true", "yes"},
        },
    )
    print_status("OK", f"Durcissement SSH terminé — statut={status}")
    if status != "applied_and_verified":
        print_status(
            "INFO",
            "Pour une vérif auto la prochaine fois : "
            "harden-ssh --pubkey-file … --identity /chemin/clé_privée "
            "(identity uniquement pour le test, ne pas committer).",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(run_harden_ssh())
