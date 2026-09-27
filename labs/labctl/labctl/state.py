"""Persistance de l'état de déploiement (JSON) et des clés WireGuard.

État dans infra/labctl/state/ :
  - deployment.json : la liste des instances (box, user, index) ;
  - wg/server.key, wg/server.pub : clés du serveur WireGuard ;
  - wg/clients/<project>.key|.pub : clés par binôme.
Les clés sont des secrets : le dossier state/ est gitignoré.
"""

from __future__ import annotations

import json
from pathlib import Path

from .model import Deployment

import os  # noqa: E402

INFRA_ROOT = Path(__file__).resolve().parents[2]
# État (clés WireGuard !) : par défaut labs/labctl/state/, surcharge LABCTL_STATE
STATE_DIR = Path(os.environ.get("LABCTL_STATE") or (INFRA_ROOT / "labctl" / "state")).resolve()
DEPLOY_FILE = STATE_DIR / "deployment.json"
SETTINGS_FILE = STATE_DIR / "settings.json"
WG_DIR = STATE_DIR / "wg"
WG_CLIENTS_DIR = WG_DIR / "clients"


def ensure_dirs() -> None:
    for d in (STATE_DIR, WG_DIR, WG_CLIENTS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_deployment() -> Deployment:
    if not DEPLOY_FILE.is_file():
        return Deployment()
    with DEPLOY_FILE.open(encoding="utf-8") as fh:
        return Deployment.from_dict(json.load(fh))


def save_deployment(deploy: Deployment) -> None:
    ensure_dirs()
    tmp = DEPLOY_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(deploy.to_dict(), fh, indent=2, ensure_ascii=False)
    tmp.replace(DEPLOY_FILE)


def load_settings() -> dict:
    if not SETTINGS_FILE.is_file():
        return {}
    try:
        with SETTINGS_FILE.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_settings(settings: dict) -> None:
    ensure_dirs()
    with SETTINGS_FILE.open("w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2, ensure_ascii=False)
