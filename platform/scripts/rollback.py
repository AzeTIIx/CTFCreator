"""Retour arrière contrôlé — confirmation obligatoire, pas de prune destructif."""

from __future__ import annotations

import sys
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


def _rollback_ssh(ctx: AppContext) -> dict:
    backup_root = Path("/var/backups/course-ctfd/sshd")
    if not is_linux():
        return {"status": "not_executed", "reason": "not_linux"}
    if not backup_root.is_dir():
        return {"status": "no_backup", "passed": False}
    backups = sorted([p for p in backup_root.iterdir() if p.is_dir()], reverse=True)
    if not backups:
        return {"status": "no_backup", "passed": False}
    latest = backups[0]
    if not confirm(ctx, f"Restaurer la config SSH depuis {latest} ?"):
        return {"status": "cancelled"}
    from harden_ssh import _restore_backup

    _restore_backup(ctx, latest)
    return {"status": "restored", "backup": str(latest)}


def _rollback_firewall(ctx: AppContext) -> dict:
    backup_root = Path("/var/backups/course-ctfd/firewall")
    if not is_linux():
        return {"status": "not_executed", "reason": "not_linux"}
    if not backup_root.is_dir():
        return {"status": "no_backup"}
    backups = sorted([p for p in backup_root.iterdir() if p.is_dir()], reverse=True)
    if not backups:
        return {"status": "no_backup"}
    latest = backups[0]
    if not confirm(ctx, f"Restaurer le pare-feu depuis {latest} ?"):
        return {"status": "cancelled"}
    nft_file = latest / "nftables.ruleset"
    if nft_file.is_file() and which("nft"):
        if not ctx.assume_yes:
            print_status(
                "WARN",
                "Restauration nftables complète nécessite --yes (remplacement ruleset sensible).",
            )
            return {"status": "needs_yes", "backup": str(latest)}
        r = run_cmd(ctx, ["nft", "-f", str(nft_file)])
        return {"status": "restored_nft" if r.ok else "failed", "backup": str(latest)}
    ufw_file = latest / "ufw-status.txt"
    if ufw_file.is_file():
        print_status(
            "INFO",
            "Sauvegarde ufw textuelle trouvée — restauration manuelle requise "
            "(ufw ne rejoue pas un status file). Voir docs/operations.md.",
        )
        return {"status": "manual_required", "backup": str(latest)}
    return {"status": "unknown_backup_format", "backup": str(latest)}


def _rollback_compose(ctx: AppContext) -> dict:
    if not which("docker"):
        return {"status": "docker_absent"}
    if not confirm(
        ctx,
        "Arrêter la stack CTFd (docker compose stop) sans supprimer volumes ?",
    ):
        return {"status": "cancelled"}
    compose = ctx.root / "compose" / "docker-compose.ctfd.yml"
    project = ctx.env.get("COMPOSE_PROJECT_NAME", "course-ctfd")
    r = run_cmd(
        ctx,
        ["docker", "compose", "-p", project, "-f", str(compose), "stop"],
        cwd=ctx.root / "compose",
    )
    return {"status": "stopped" if r.ok or ctx.dry_run else "failed"}


def run_rollback(ctx: AppContext | None = None, target: str = "all") -> int:
    ctx = ctx or build_context()
    print_status("INFO", f"Rollback demandé : {target}")
    if not confirm(ctx, "Confirmer le retour arrière (action potentiellement disruptive) ?"):
        return 1

    report = {"generated_at": utc_now(), "target": target, "actions": {}}

    if target in {"all", "ssh"}:
        report["actions"]["ssh"] = _rollback_ssh(ctx)
    if target in {"all", "firewall"}:
        report["actions"]["firewall"] = _rollback_firewall(ctx)
    if target in {"all", "ctfd"}:
        report["actions"]["ctfd"] = _rollback_compose(ctx)

    write_report(ctx, "rollback", report)
    print_status("OK", "Rollback terminé (voir rapport). Volumes préservés.")
    print_status(
        "INFO",
        "Commandes destructives (rm volume, prune) volontairement absentes.",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run_rollback())
