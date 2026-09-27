"""Contrôles d'isolation — mode containers avec challenge_containers (0xfbad)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from common import AppContext, is_linux, run_cmd, which  # noqa: E402


def run_check(ctx: AppContext) -> dict[str, Any]:
    mode = (ctx.env.get("DEPLOY_MODE") or "degraded").strip().lower()
    selection = (ctx.env.get("PLUGIN_SELECTION") or "none").strip().lower()

    if mode == "degraded" and selection in {"", "none", "degraded"}:
        running_challenges = []
        if which("docker"):
            r = run_cmd(ctx, ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}"])
            if r.ok:
                for line in r.stdout.splitlines():
                    low = line.lower()
                    if any(x in low for x in ("challenge", "ctfd-chall", "chall_", "instance_")):
                        running_challenges.append(line.strip())
        if running_challenges:
            return {
                "status": "unexpected_challenge_containers",
                "passed": False,
                "message": "Conteneurs challenge détectés en mode degraded",
                "containers": running_challenges,
            }
        return {
            "status": "degraded_no_student_instances",
            "passed": True,
            "message": "Pas d'instances étudiants — isolation N/A.",
            "tests_executed": False,
            "host_linux": is_linux(),
        }

    if not which("docker"):
        return {"status": "docker_absent", "passed": False, "message": "Docker absent"}

    findings: dict[str, Any] = {"selection": selection, "mode": mode}

    inspect = run_cmd(
        ctx,
        [
            "docker",
            "inspect",
            f"{ctx.env.get('COMPOSE_PROJECT_NAME') or 'course-ctfd'}-ctfd-1",
            "--format",
            "{{range .Mounts}}{{.Source}} -> {{.Destination}}{{println}}{{end}}",
        ],
    )
    mounts = inspect.stdout if inspect.ok else ""
    findings["inspect_ok"] = inspect.ok
    findings["mounts"] = mounts

    if selection == "challenge_containers":
        if "challenge_containers" not in mounts:
            return {
                "status": "plugin_not_mounted",
                "passed": False,
                "message": "Plugin challenge_containers non monté dans CTFd",
                "findings": findings,
            }
        if "docker.sock" not in mounts:
            return {
                "status": "docker_socket_missing",
                "passed": False,
                "message": (
                    "Socket Docker absent des mounts CTFd — requis par le contexte local 0xfbad"
                ),
                "findings": findings,
            }
        return {
            "status": "accepted_partial_isolation_controls",
            "passed": True,
            "message": (
                "Contrôles partiels OK (plugin monté, socket présent — exigence amont). "
                "Risque résiduel socket assumé. Recette manuelle encore requise : "
                "2 instances, egress, voisinage, limites (docs/verification-checklist.md)."
            ),
            "tests_executed": False,
            "findings": findings,
            "host_linux": is_linux(),
        }

    return {
        "status": "unknown_container_selection",
        "passed": False,
        "message": f"Sélection plugin inattendue pour isolation : {selection}",
        "findings": findings,
    }
