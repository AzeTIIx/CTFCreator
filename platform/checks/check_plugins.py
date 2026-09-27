"""Contrôles plugins — refuse OrangeJuice ; accepte challenge_containers (0xfbad)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from common import AppContext  # noqa: E402

REFUSED = (
    "TheOriginalOrangeJuice",
    "1b86917d44fab583d2cee00b0875e8442b6827c9",
)

ACCEPTED = {
    "challenge_containers": "0xfbad/ctfd-challenge-container-plugin",
}


def _docs_mark_accepted(compat_text: str, plugin_key: str) -> bool:
    if plugin_key != "challenge_containers":
        return False
    marker = "0xfbad/ctfd-challenge-container-plugin"
    idx = compat_text.find(marker)
    if idx < 0:
        return False
    rest = compat_text[idx:]
    next_h = rest.find("\n## ", 1)
    chunk = rest if next_h < 0 else rest[:next_h]
    for line in chunk.splitlines():
        if "écision" not in line and "Decision" not in line and "Décision" not in line:
            continue
        low = line.lower()
        if "accepté" in low and "refusé" not in low:
            return True
    return False


def run_check(ctx: AppContext) -> dict[str, Any]:
    selection = (ctx.env.get("PLUGIN_SELECTION") or "none").strip().lower()
    mode = (ctx.env.get("DEPLOY_MODE") or "degraded").strip().lower()
    plugins_dir = ctx.root / "plugins"

    refused_found = []
    if plugins_dir.is_dir():
        for path in plugins_dir.rglob("*"):
            combined = str(path).lower()
            if any(r.lower() in combined for r in REFUSED):
                refused_found.append(str(path.relative_to(ctx.root)))

    if refused_found:
        return {
            "status": "refused_plugin_present",
            "passed": False,
            "message": "Plugin refusé présent dans plugins/",
            "paths": refused_found,
        }

    compat = ctx.root / "docs" / "plugin-compatibility.md"
    text = compat.read_text(encoding="utf-8") if compat.is_file() else ""

    if selection in {"", "none", "degraded"}:
        if mode == "containers":
            return {
                "status": "containers_without_plugin_selection",
                "passed": False,
                "message": "DEPLOY_MODE=containers exige PLUGIN_SELECTION=challenge_containers",
            }
        return {
            "status": "degraded_no_container_plugin",
            "passed": True,
            "message": "Mode degraded : pas de plugin d'instances sélectionné.",
        }

    if selection not in ACCEPTED:
        return {
            "status": "unknown_plugin_selection",
            "passed": False,
            "message": f"PLUGIN_SELECTION={selection} non reconnu (attendu: challenge_containers)",
        }

    if not _docs_mark_accepted(text, selection):
        return {
            "status": "plugin_not_accepted_in_docs",
            "passed": False,
            "message": f"{selection} sans décision 'accepté' dans plugin-compatibility.md",
        }

    plugin_path = plugins_dir / "challenge_containers" / "__init__.py"
    if not plugin_path.is_file():
        return {
            "status": "plugin_files_missing",
            "passed": False,
            "message": "plugins/challenge_containers/__init__.py manquant",
        }

    if mode not in {"containers", "degraded"}:
        return {
            "status": "invalid_deploy_mode",
            "passed": False,
            "message": f"DEPLOY_MODE={mode} invalide",
        }

    return {
        "status": "challenge_containers_accepted",
        "passed": True,
        "message": (
            "Plugin challenge_containers (0xfbad) accepté (docs). "
            "Configurer /admin/config → Challenge Containers ; "
            "précharger les images sur le daemon local. "
            "Socket Docker monté dans CTFd (exigence amont)."
        ),
        "selection": selection,
        "mode": mode,
    }
