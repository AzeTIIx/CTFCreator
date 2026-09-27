"""Configuration pare-feu — un seul backend, SSH any (admin mobile), pas de prune."""

from __future__ import annotations

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
from preflight import detect_firewall  # noqa: E402


def _choose_backend(ctx: AppContext) -> str:
    configured = (ctx.env.get("FIREWALL_BACKEND") or "auto").strip().lower()
    inventory = detect_firewall(ctx)
    detected = inventory.get("chosen") or "none_detected"

    if configured == "auto":
        if detected in {"ufw", "nftables"}:
            return detected
        if which("nft"):
            return "nftables"
        if which("ufw"):
            return "ufw"
        return "none"
    if configured in {"ufw", "nftables"}:
        if configured == "ufw" and inventory.get("nftables", {}).get("present"):
            print_status(
                "WARN",
                "nftables présent — on n'installe/active pas ufw en parallèle sans décision manuelle.",
            )
        if configured == "nftables" and "Status: active" in str(
            inventory.get("ufw", {}).get("status", "")
        ):
            print_status(
                "WARN",
                "ufw actif détecté — bascule nftables refusée automatiquement.",
            )
            return "ufw"
        return configured
    raise RuntimeError(f"FIREWALL_BACKEND invalide : {configured}")


def _backup_rules(ctx: AppContext, backend: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = Path("/var/backups/course-ctfd/firewall") / stamp
    if not is_linux():
        dest = ctx.root / "backups" / "firewall" / stamp
    if ctx.dry_run:
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    if backend == "ufw" and which("ufw"):
        r = run_cmd(ctx, ["ufw", "status", "numbered"])
        (dest / "ufw-status.txt").write_text(r.stdout or "", encoding="utf-8")
    if backend == "nftables" and which("nft"):
        r = run_cmd(ctx, ["nft", "list", "ruleset"])
        (dest / "nftables.ruleset").write_text(r.stdout or "", encoding="utf-8")
    return dest


def _apply_ufw(ctx: AppContext) -> dict:
    ssh_port = ctx.env.get("SSH_PORT", "22")
    if not validate_port(ssh_port):
        raise RuntimeError("SSH_PORT invalide")

    steps = []
    # SSH ouvert depuis any — admin mobile ; mitigation = clés uniquement (harden-ssh)
    steps.append(["ufw", "allow", f"{ssh_port}/tcp"])
    if (ctx.env.get("HTTP_PUBLIC") or "true").lower() in {"1", "true", "yes"}:
        steps.append(["ufw", "allow", "80/tcp"])
    if (ctx.env.get("HTTPS_PUBLIC") or "true").lower() in {"1", "true", "yes"}:
        steps.append(["ufw", "allow", "443/tcp"])
    # Ports dynamiques du plugin 0xfbad (host port 40000-59999)
    if (ctx.env.get("DEPLOY_MODE") or "").strip().lower() == "containers":
        steps.append(["ufw", "allow", "40000:59999/tcp"])
    results = []
    for argv in steps:
        r = run_cmd(ctx, argv)
        results.append({"argv": argv, "ok": r.ok})
    r_def = run_cmd(ctx, ["ufw", "default", "deny", "incoming"])
    results.append({"argv": ["ufw", "default", "deny", "incoming"], "ok": r_def.ok})
    r_out = run_cmd(ctx, ["ufw", "default", "allow", "outgoing"])
    results.append({"argv": ["ufw", "default", "allow", "outgoing"], "ok": r_out.ok})
    if confirm(ctx, "Activer ufw maintenant ?"):
        r_en = run_cmd(ctx, ["ufw", "--force", "enable"])
        results.append({"argv": ["ufw", "--force", "enable"], "ok": r_en.ok})
    return {"backend": "ufw", "results": results, "ssh_source": "any"}


def _apply_nftables(ctx: AppContext) -> dict:
    ssh_port = ctx.env.get("SSH_PORT", "22")
    if not validate_port(ssh_port):
        raise RuntimeError("SSH_PORT invalide")

    http_rule = ""
    https_rule = ""
    challenge_ports_rule = ""
    if (ctx.env.get("HTTP_PUBLIC") or "true").lower() in {"1", "true", "yes"}:
        http_rule = "tcp dport 80 accept"
    if (ctx.env.get("HTTPS_PUBLIC") or "true").lower() in {"1", "true", "yes"}:
        https_rule = "tcp dport 443 accept"
    if (ctx.env.get("DEPLOY_MODE") or "").strip().lower() == "containers":
        # Plage host ports du plugin 0xfbad (voir docker_host_manager._run_with_port_retry)
        challenge_ports_rule = "tcp dport 40000-59999 accept"

    rules = f"""#!/usr/sbin/nft -f
# course-ctfd-infra — table dédiée (pas de flush global)
# SSH : any (admin mobile) — compensé par durcissement clés uniquement
table inet course_ctfd {{
  chain input {{
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport {ssh_port} accept
    {http_rule}
    {https_rule}
    {challenge_ports_rule}
    # registre 5000 : jamais accepté ici
  }}
}}
"""
    path = Path("/etc/nftables.d/course-ctfd.nft")
    if ctx.dry_run:
        print_status("INFO", "[dry-run] écriture règles nftables course_ctfd")
        return {"backend": "nftables", "path": str(path), "applied": False, "ssh_source": "any"}

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rules, encoding="utf-8")
    r = run_cmd(ctx, ["nft", "-f", str(path)])
    return {
        "backend": "nftables",
        "path": str(path),
        "applied": r.ok,
        "stderr_redacted": bool(r.stderr),
        "ssh_source": "any",
    }


def run_configure_firewall(ctx: AppContext | None = None) -> int:
    ctx = ctx or build_context()
    print_status("INFO", "Configuration pare-feu")

    if not is_linux():
        print_status("WARN", "Pare-feu non configuré : hôte non Linux. Marqué NON EXÉCUTÉ.")
        write_report(
            ctx,
            "firewall",
            {
                "generated_at": utc_now(),
                "status": "not_executed",
                "reason": "not_linux",
            },
        )
        return 0

    try:
        backend = _choose_backend(ctx)
    except RuntimeError as exc:
        print_status("FAIL", str(exc))
        return 2

    if backend == "none":
        print_status(
            "FAIL",
            "Aucun backend pare-feu détecté. Installer nftables OU ufw manuellement, pas les deux.",
        )
        return 2

    print_status("INFO", f"Backend retenu : {backend}")
    print_status(
        "WARN",
        "SSH autorisé depuis any (pas de filtre IP) — exiger harden-ssh (clés, pas de mot de passe).",
    )
    if not confirm(ctx, f"Sauvegarder puis appliquer les règles {backend} ?"):
        return 1

    backup = _backup_rules(ctx, backend)
    print_status("OK", f"Sauvegarde pare-feu : {backup}")

    try:
        if backend == "ufw":
            result = _apply_ufw(ctx)
        else:
            result = _apply_nftables(ctx)
    except RuntimeError as exc:
        print_status("FAIL", str(exc))
        return 2

    verify = {}
    ssh_port = ctx.env.get("SSH_PORT", "22")
    if backend == "ufw":
        r = run_cmd(ctx, ["ufw", "status"])
        verify["ufw_status_ok"] = r.ok
        verify["ssh_rule_present"] = ssh_port in (r.stdout or "")
    else:
        r = run_cmd(ctx, ["nft", "list", "table", "inet", "course_ctfd"])
        verify["nft_table_present"] = r.ok

    write_report(
        ctx,
        "firewall",
        {
            "generated_at": utc_now(),
            "status": "applied",
            "backend": backend,
            "backup": str(backup),
            "result": result,
            "verify": verify,
            "ports": {
                "ssh": {"port": ssh_port, "source": "any"},
                "http": {"port": 80, "source": "any" if ctx.env.get("HTTP_PUBLIC") else "closed"},
                "https": {"port": 443, "source": "any" if ctx.env.get("HTTPS_PUBLIC") else "closed"},
                "registry": {"port": 5000, "source": "never_public"},
                "db": {"port": 3306, "source": "never_published"},
                "redis": {"port": 6379, "source": "never_published"},
            },
        },
    )
    print_status("OK", f"Pare-feu configuré ({backend})")
    print_status(
        "INFO",
        "Vérifier SSH depuis un réseau quelconque avec clé ; password auth doit être refusé.",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run_configure_firewall())
