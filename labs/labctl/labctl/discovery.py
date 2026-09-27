"""Découverte des box : lit les box.yml sous infra/challenges/."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from .model import Box, LabctlError

# CTFCreator/labs/labctl/labctl/discovery.py -> parents[2] = CTFCreator/labs/
INFRA_ROOT = Path(__file__).resolve().parents[2]
# Les box vivent dans le dossier du client : LABCTL_BOXES=<chemin>/challenges
CHALLENGES_ROOT = Path(os.environ.get("LABCTL_BOXES") or (INFRA_ROOT / "boxes")).resolve()
IGNORED = {"_template", "__pycache__"}


def load_box(box_dir: Path) -> Box:
    manifest = box_dir / "box.yml"
    if not manifest.is_file():
        raise LabctlError(f"box.yml manquant dans {box_dir}")
    with manifest.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return Box(
        name=data.get("name", box_dir.name),
        path=box_dir,
        title=data.get("title", ""),
        entry_service=data.get("entry_service", "gateway"),
        entry_ip_offset=int(data.get("entry_ip_offset", 10)),
        ports=[int(p) for p in data.get("ports", [22])],
        compose=data.get("compose", "compose.yml"),
        prebuild=data.get("prebuild"),
        flags=list(data.get("flags", [])),
        ssh_user=data.get("ssh_user", ""),
        description=data.get("description", ""),
    )


def discover_boxes(root: Path | None = None) -> list[Box]:
    root = root or CHALLENGES_ROOT
    if not root.is_dir():
        return []
    boxes: list[Box] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or entry.name in IGNORED or entry.name.startswith("."):
            continue
        if (entry / "box.yml").is_file():
            boxes.append(load_box(entry))
    return boxes


def get_box(name: str, root: Path | None = None) -> Box:
    for box in discover_boxes(root):
        if box.name == name or box.slug == name:
            return box
    raise LabctlError(f"box introuvable: {name}")
