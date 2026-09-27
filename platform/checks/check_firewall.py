"""Contrôles pare-feu."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from common import AppContext, is_linux, run_cmd, which  # noqa: E402


def run_check(ctx: AppContext) -> dict[str, Any]:
    if not is_linux():
        return {
            "status": "not_executed",
            "passed": False,
            "message": "Hôte non Linux — contrôle pare-feu réel non exécuté",
        }

    ssh_port = (ctx.env.get("SSH_PORT") or "22").strip()
    findings: dict[str, Any] = {"ssh_source": "any", "ssh_port": ssh_port}

    if which("ufw"):
        r = run_cmd(ctx, ["ufw", "status"])
        findings["ufw"] = {
            "ok": r.ok,
            "active": "Status: active" in (r.stdout or ""),
            "mentions_ssh": ssh_port in (r.stdout or ""),
        }
        if findings["ufw"]["active"] and findings["ufw"]["mentions_ssh"]:
            return {
                "status": "ufw_active_with_ssh",
                "passed": True,
                "findings": findings,
            }

    if which("nft"):
        r = run_cmd(ctx, ["nft", "list", "table", "inet", "course_ctfd"])
        if r.ok:
            return {
                "status": "nft_course_ctfd_present",
                "passed": True,
                "findings": findings,
            }
        findings["nft_course_table"] = False

    return {
        "status": "firewall_not_verified",
        "passed": False,
        "message": "Aucune configuration course-ctfd vérifiable (ufw actif avec SSH ou table nft course_ctfd)",
        "findings": findings,
    }
