"""Vendoring epingle de themes / plugins — jamais main/latest."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import AppContext, build_context, print_status  # noqa: E402

THEME_REPO = "https://github.com/hmrserver/CTFd-theme-pixo.git"
THEME_COMMIT = "67abc2b8a444206061ad6f6070b5e5e17215336b"
THEME_DIRNAME = "pixo"

PLUGIN_REPO = "https://github.com/0xfbad/ctfd-challenge-container-plugin.git"
PLUGIN_COMMIT = "1023885a0bbcdcd0c027c132c309ac690233ecd2"
PLUGIN_DIRNAME = "challenge_containers"


def _run(argv: list[str], cwd: Path | None = None) -> None:
    print_status("INFO", "exec: " + " ".join(argv))
    completed = subprocess.run(argv, cwd=str(cwd) if cwd else None, shell=False, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"commande echouee ({completed.returncode}): {' '.join(argv)}")


def _replace_dir(src: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".git"))


def vendor_theme(ctx: AppContext | None = None) -> int:
    ctx = ctx or build_context()
    root = ctx.root
    dest = root / "themes" / THEME_DIRNAME
    print_status("INFO", f"Vendor theme pixo @ {THEME_COMMIT}")
    with tempfile.TemporaryDirectory(prefix="ctfd-theme-") as tmp:
        tmp_path = Path(tmp) / "repo"
        _run(["git", "clone", "--filter=blob:none", "--no-checkout", THEME_REPO, str(tmp_path)])
        _run(["git", "fetch", "--depth", "1", "origin", THEME_COMMIT], cwd=tmp_path)
        _run(["git", "checkout", THEME_COMMIT], cwd=tmp_path)
        _replace_dir(tmp_path, dest)
    (root / "themes" / "PIN.txt").write_text(
        "\n".join(
            [
                "name=pixo",
                f"repo={THEME_REPO.rstrip('.git')}",
                f"commit={THEME_COMMIT}",
                "declared_ctfd_compat=3.3.0",
                "target_ctfd=3.8.6",
                "note=Re-vendored by scripts/vendor_assets.py",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print_status("OK", f"Theme installe dans {dest}")
    return 0


def vendor_plugin_containers(ctx: AppContext | None = None) -> int:
    ctx = ctx or build_context()
    root = ctx.root
    dest = root / "plugins" / PLUGIN_DIRNAME
    print_status("INFO", f"Vendor plugin challenge_containers @ {PLUGIN_COMMIT}")
    with tempfile.TemporaryDirectory(prefix="ctfd-plugin-") as tmp:
        tmp_path = Path(tmp) / "repo"
        _run(["git", "clone", "--filter=blob:none", "--no-checkout", PLUGIN_REPO, str(tmp_path)])
        _run(["git", "fetch", "--depth", "1", "origin", PLUGIN_COMMIT], cwd=tmp_path)
        _run(["git", "checkout", PLUGIN_COMMIT], cwd=tmp_path)
        _replace_dir(tmp_path, dest)
    (root / "plugins" / "PIN.txt").write_text(
        "\n".join(
            [
                "name=challenge_containers",
                f"repo={PLUGIN_REPO.rstrip('.git')}",
                f"commit={PLUGIN_COMMIT}",
                "path_in_repo=repo root",
                "target_ctfd=3.8.6",
                "license=UNDECLARED_ON_GITHUB",
                "status=ACCEPTED_BY_OPERATOR",
                "note=Requires docker.sock for local context. Re-vendored by scripts/vendor_assets.py",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print_status("OK", f"Plugin installe dans {dest}")
    return 0


# Alias historique pour main.py
vendor_plugin_docker = vendor_plugin_containers


if __name__ == "__main__":
    raise SystemExit(vendor_theme())
