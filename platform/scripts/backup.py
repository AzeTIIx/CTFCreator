"""Sauvegarde CTFd / volumes / configs — jamais destructive, sans secrets dans les logs."""

from __future__ import annotations

import json
import sys
import tarfile
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
    which,
    write_report,
)


def _backup_dir(ctx: AppContext) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    configured = Path(ctx.env.get("BACKUP_ROOT") or (ctx.root / "backups"))
    if not configured.is_absolute() or not is_linux():
        configured = ctx.root / "backups"
    target = configured / stamp
    target.mkdir(parents=True, exist_ok=True)
    try:
        target.chmod(0o700)
    except OSError:
        pass
    return target


def backup_compose_configs(ctx: AppContext, dest: Path) -> list[str]:
    saved: list[str] = []
    for rel in (
        "compose/docker-compose.ctfd.yml",
        "compose/docker-compose.registry.yml",
        "compose/nginx/ctfd.conf",
        ".env.example",
        "config/ctfd.env.example",
    ):
        src = ctx.root / rel
        if src.is_file():
            out = dest / "repo" / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(src.read_bytes())
            saved.append(rel)
    # Ne jamais copier .env / ctfd.env (secrets) dans une archive versionnée ;
    # si présents, les archiver à part avec permissions strictes hors git.
    secret_files = [ctx.root / ".env", ctx.root / "config" / "ctfd.env"]
    secrets_dir = dest / "secrets_local"
    for sf in secret_files:
        if sf.is_file():
            secrets_dir.mkdir(parents=True, exist_ok=True)
            try:
                secrets_dir.chmod(0o700)
            except OSError:
                pass
            target = secrets_dir / sf.name
            target.write_bytes(sf.read_bytes())
            try:
                target.chmod(0o600)
            except OSError:
                pass
            saved.append(f"secrets_local/{sf.name} (non journalisé en clair)")
    return saved


def backup_docker_volumes(ctx: AppContext, dest: Path) -> dict:
    result = {"attempted": False, "volumes": [], "errors": []}
    if not which("docker"):
        result["errors"].append("docker absent")
        return result
    volumes = [
        "course_ctfd_mysql",
        "course_ctfd_redis",
        "course_ctfd_uploads",
        "course_ctfd_logs",
        "course_registry_data",
    ]
    vol_dir = dest / "volumes"
    vol_dir.mkdir(parents=True, exist_ok=True)
    result["attempted"] = True
    alpine = ctx.env.get("ALPINE_IMAGE", "alpine:3.21.3")
    for vol in volumes:
        inspect = run_cmd(ctx, ["docker", "volume", "inspect", vol])
        if not inspect.ok:
            result["errors"].append(f"volume absent: {vol}")
            continue
        archive = vol_dir / f"{vol}.tar.gz"
        if ctx.dry_run:
            result["volumes"].append(vol)
            continue
        # Conteneur éphémère en lecture du volume uniquement
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{vol}:/volume:ro",
            "-v",
            f"{vol_dir.resolve()}:/backup",
            alpine,
            "tar",
            "czf",
            f"/backup/{vol}.tar.gz",
            "-C",
            "/volume",
            ".",
        ]
        r = run_cmd(ctx, cmd, timeout=600)
        if r.ok and archive.exists():
            result["volumes"].append(vol)
        else:
            result["errors"].append(f"échec sauvegarde {vol}")
    return result


def backup_db_dump(ctx: AppContext, dest: Path) -> dict:
    """Dump logique MariaDB si la stack tourne — sans afficher le mot de passe."""
    out = {"attempted": False, "ok": False}
    if not which("docker"):
        return out
    ps = run_cmd(
        ctx,
        [
            "docker",
            "ps",
            "--filter",
            "name=db",
            "--filter",
            "name=course-ctfd",
            "--format",
            "{{.Names}}",
        ],
    )
    names = [n.strip() for n in (ps.stdout or "").splitlines() if n.strip()]
    db_container = next((n for n in names if n.endswith("-db-1") or n.endswith("_db_1") or n == "db"), None)
    if not db_container:
        # Chercher plus large
        all_ps = run_cmd(ctx, ["docker", "ps", "--format", "{{.Names}}"])
        for n in (all_ps.stdout or "").splitlines():
            if n.strip().endswith("-db-1") or "_db_" in n:
                db_container = n.strip()
                break
    if not db_container:
        out["note"] = "conteneur db introuvable — dump logique ignoré"
        return out
    out["attempted"] = True
    dump_path = dest / "db" / "ctfd.sql.gz"
    dump_path.parent.mkdir(parents=True, exist_ok=True)
    password = ctx.env.get("DB_ROOT_PASSWORD", "")
    if not password:
        out["note"] = "DB_ROOT_PASSWORD absent — dump ignoré"
        return out
    if ctx.dry_run:
        out["ok"] = True
        return out
    # Utiliser env Docker pour éviter d'afficher le mot de passe dans ps
    r = run_cmd(
        ctx,
        [
            "docker",
            "exec",
            "-e",
            "MYSQL_PWD=***",  # placeholder — vrai passage via env ci-dessous impossible sans secret
            db_container,
            "true",
        ],
    )
    # Approche : docker exec avec -e MYSQL_PWD depuis environnement process filtré
    import os
    import subprocess

    env = dict(os.environ)
    env["MYSQL_PWD"] = password
    try:
        with open(dump_path, "wb") as fh:
            p1 = subprocess.Popen(
                [
                    "docker",
                    "exec",
                    "-e",
                    "MYSQL_PWD",
                    db_container,
                    "mysqldump",
                    "-uroot",
                    "--single-transaction",
                    "--routines",
                    "ctfd",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                shell=False,
            )
            assert p1.stdout is not None
            import gzip

            with gzip.open(fh, "wb") as gz:
                while True:
                    chunk = p1.stdout.read(1024 * 64)
                    if not chunk:
                        break
                    gz.write(chunk)
            stderr = (p1.communicate()[1] or b"").decode("utf-8", errors="replace")
            if p1.returncode != 0:
                out["ok"] = False
                out["error"] = "mysqldump a échoué (détails rédigés)"
                print_status("FAIL", "Dump SQL échoué")
            else:
                out["ok"] = True
                try:
                    dump_path.chmod(0o600)
                except OSError:
                    pass
    except OSError as exc:
        out["ok"] = False
        out["error"] = type(exc).__name__
    # Nettoyer référence locale
    password = ""
    env.pop("MYSQL_PWD", None)
    return out


def run_backup(ctx: AppContext | None = None) -> int:
    ctx = ctx or build_context()
    print_status("INFO", "Démarrage sauvegarde (non destructive)")
    if not confirm(ctx, "Créer une sauvegarde maintenant ?"):
        return 1

    dest = _backup_dir(ctx)
    meta = {
        "generated_at": utc_now(),
        "destination": str(dest),
        "files": backup_compose_configs(ctx, dest),
        "volumes": backup_docker_volumes(ctx, dest),
        "db_dump": backup_db_dump(ctx, dest) if is_linux() else {"skipped": "non-linux"},
    }
    (dest / "MANIFEST.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    # Archive récursive hors secrets déjà dans secrets_local
    archive = dest.parent / f"{dest.name}-bundle.tar.gz"
    if not ctx.dry_run:
        with tarfile.open(archive, "w:gz") as tar:
            for item in dest.rglob("*"):
                if "secrets_local" in item.parts:
                    continue  # secrets restent hors bundle transportable
                tar.add(item, arcname=str(item.relative_to(dest.parent)))
        try:
            archive.chmod(0o600)
        except OSError:
            pass
    write_report(
        ctx,
        "backup",
        {
            "generated_at": utc_now(),
            "dest": str(dest),
            "bundle": str(archive),
            "volume_ok": meta["volumes"].get("volumes", []),
            "volume_errors": meta["volumes"].get("errors", []),
            "db_dump_ok": meta["db_dump"].get("ok"),
        },
    )
    print_status("OK", f"Sauvegarde disponible sous {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_backup())
