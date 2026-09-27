"""Contrôles SSH — jamais de succès simulé."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from common import AppContext, is_linux, which  # noqa: E402


def run_check(ctx: AppContext) -> dict[str, Any]:
    if not is_linux():
        return {
            "status": "not_executed",
            "passed": False,
            "message": "Hôte non Linux — contrôle SSH réel non exécuté",
        }

    candidates = [
        Path("/etc/ssh/sshd_config.d/10-course-ctfd-hardening.conf"),
        Path("/etc/ssh/sshd_config.d/50-course-ctfd-hardening.conf"),  # ancien nom
    ]
    dropin = next((c for c in candidates if c.is_file()), candidates[0])
    sshd = which("sshd") or Path("/usr/sbin/sshd").exists()
    if not sshd:
        return {"status": "sshd_absent", "passed": False, "message": "sshd absent"}

    from common import run_cmd

    test = run_cmd(ctx, ["sshd", "-t"])
    if not test.ok:
        return {"status": "sshd_t_failed", "passed": False, "message": "sshd -t échoue"}

    if not dropin.is_file():
        return {
            "status": "hardening_not_applied",
            "passed": False,
            "message": "Drop-in de durcissement absent (harden-ssh non appliqué)",
        }

    # Présence des directives clés
    text = dropin.read_text(encoding="utf-8", errors="replace")
    required = ["PermitRootLogin no", "PasswordAuthentication no", "PubkeyAuthentication yes"]
    missing = [r for r in required if r not in text]
    if missing:
        return {
            "status": "incomplete_hardening",
            "passed": False,
            "message": f"Directives manquantes : {missing}",
        }

    # Configuration EFFECTIVE : un drop-in chargé avant le nôtre (ex. 50-cloud-init.conf)
    # peut imposer PasswordAuthentication yes — sshd garde la première valeur lue.
    effective = run_cmd(ctx, ["sshd", "-T"])
    if effective.ok:
        eff = {
            line.split(None, 1)[0].lower(): (line.split(None, 1)[1].strip().lower() if " " in line else "")
            for line in effective.stdout.splitlines()
            if line.strip()
        }
        expected = {
            "permitrootlogin": "no",
            "passwordauthentication": "no",
            "kbdinteractiveauthentication": "no",
            "pubkeyauthentication": "yes",
        }
        wrong = {k: eff.get(k) for k, v in expected.items() if k in eff and eff[k] != v}
        if wrong:
            return {
                "status": "effective_config_weak",
                "passed": False,
                "message": f"Config sshd effective non conforme (drop-in écrasé ?) : {wrong}",
            }

    return {
        "status": "hardening_file_present",
        "passed": True,
        "message": "Drop-in présent et sshd -t OK (test nouvelle connexion : voir rapport harden-ssh)",
        "note": "Un passed ici ne remplace pas le test de nouvelle connexion SSH",
    }
