"""Création d'une nouvelle box depuis challenges/_template/."""

from __future__ import annotations

import shutil
from pathlib import Path

from . import discovery
from .model import LabctlError, slugify

# Modèle livré avec CTFCreator (templates/box) ; repli sur <boxes>/_template
_SHIPPED = Path(__file__).resolve().parents[3] / "templates" / "box"


def _template() -> Path:
    return _SHIPPED if _SHIPPED.is_dir() else discovery.CHALLENGES_ROOT / "_template"


def scaffold_box(name: str) -> Path:
    slug = slugify(name)
    dest = discovery.CHALLENGES_ROOT / slug
    template = _template()
    if dest.exists():
        raise LabctlError(f"la box existe déjà : {dest}")
    if not template.is_dir():
        raise LabctlError(f"template introuvable : {template}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(template, dest)
    # Remplace le placeholder de nom dans les fichiers texte.
    for path in dest.rglob("*"):
        if path.is_file() and path.suffix in {".yml", ".yaml", ".md", ".txt"}:
            try:
                txt = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if "__BOX_NAME__" in txt:
                path.write_text(txt.replace("__BOX_NAME__", slug), encoding="utf-8")
    return dest
