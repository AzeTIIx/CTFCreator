"""Orchestration Docker par instance (host : nécessite docker + le binaire wg
pour les clés). Chaque fonction renvoie un CompletedProcess pour le rendu.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .compose import instance_env
from .model import Box, Instance


def _compose(box: Box, inst: Instance, *args: str, timeout: int = 1200) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-p", inst.project, "-f", str(box.compose_path), *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          cwd=str(box.path), env=instance_env(box, inst))


def run_prebuild(box: Box) -> subprocess.CompletedProcess | None:
    """Hook de pré-build de la box (ex. génération de clés), une fois par box."""
    if not box.prebuild:
        return None
    script = box.path / box.prebuild
    if not script.is_file():
        return None
    return subprocess.run(["bash", str(script)], capture_output=True, text=True,
                          cwd=str(box.path))


def up(box: Box, inst: Instance, build: bool = True, no_cache: bool = False) -> subprocess.CompletedProcess:
    args = ["up", "-d"]
    if build:
        args.append("--build")
    if no_cache:
        # compose n'a pas --no-cache sur up ; on build d'abord.
        b = _compose(box, inst, "build", "--no-cache")
        if b.returncode != 0:
            return b
    return _compose(box, inst, *args)


def down(box: Box, inst: Instance) -> subprocess.CompletedProcess:
    return _compose(box, inst, "down", "-v", "--remove-orphans", timeout=180)


def ps(box: Box, inst: Instance) -> subprocess.CompletedProcess:
    return _compose(box, inst, "ps", "--format", "{{.Service}} {{.Status}}", timeout=30)


def is_up(box: Box, inst: Instance) -> bool:
    r = ps(box, inst)
    return r.returncode == 0 and bool(r.stdout.strip())
