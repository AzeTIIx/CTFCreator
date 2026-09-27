"""Vérifications fonctionnelles — aucun succès simulé."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "checks"))

from common import AppContext, build_context, is_linux, print_status, utc_now, write_report  # noqa: E402

import check_ctfd  # noqa: E402
import check_firewall  # noqa: E402
import check_isolation  # noqa: E402
import check_plugins  # noqa: E402
import check_ssh  # noqa: E402


def run_verify(ctx: AppContext | None = None) -> int:
    ctx = ctx or build_context()
    print_status("INFO", "Vérifications fonctionnelles")

    results = {
        "generated_at": utc_now(),
        "host_linux": is_linux(),
        "checks": {},
    }
    failed = False

    checkers = [
        ("ssh", check_ssh.run_check),
        ("firewall", check_firewall.run_check),
        ("ctfd", check_ctfd.run_check),
        ("plugins", check_plugins.run_check),
        ("isolation", check_isolation.run_check),
    ]

    for name, fn in checkers:
        print_status("INFO", f"Vérification : {name}")
        try:
            outcome = fn(ctx)
        except Exception as exc:  # noqa: BLE001
            outcome = {
                "status": "error",
                "passed": False,
                "error": type(exc).__name__,
                "message": str(exc),
            }
        results["checks"][name] = outcome
        passed = bool(outcome.get("passed"))
        status = outcome.get("status", "unknown")
        if passed:
            print_status("OK", f"{name}: {status}")
        else:
            failed = True
            print_status("FAIL", f"{name}: {status} — {outcome.get('message', '')}")

    results["conformant"] = not failed and is_linux()
    if not is_linux():
        results["conformant"] = False
        results["note"] = (
            "Hôte non Linux : les vérifications d'infrastructure réelle sont marquées "
            "non exécutées / non conformes. Aucun résultat n'est simulé comme réussi."
        )

    write_report(ctx, "verify", results)
    latest = ctx.reports_dir / "verify-latest.json"
    latest.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if failed or not is_linux():
        print_status("FAIL", "Déploiement NON CONFORME")
        return 1
    print_status("OK", "Toutes les vérifications obligatoires ont réussi")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_verify())
