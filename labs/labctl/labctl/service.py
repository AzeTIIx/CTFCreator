"""Couche d'orchestration : opérations batch appelées par l'UI.

Sépare la logique (allocation, génération, docker) du rendu Rich.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import deploy as dep
from . import firewall, state, wireguard
from .model import ADMIN_WG_IP, LAB_SUPERNET, Box, Deployment, Instance

WG_IF = "wg0"
WG_ETC = Path("/etc/wireguard/wg0.conf")


def add_users(deploy: Deployment, box: Box, labels: list[str]) -> list[Instance]:
    made = [deploy.add(box.name, lbl) for lbl in labels]
    save(deploy)
    return made


def save(deploy: Deployment) -> None:
    state.save_deployment(deploy)


@dataclass
class StepResult:
    ok: bool
    label: str
    detail: str = ""


def deploy_instances(box: Box, instances: list[Instance], no_cache: bool = False):
    """Génère les résultats étape par étape (générateur, pour un rendu live)."""
    pre = dep.run_prebuild(box)
    if pre is not None:
        yield StepResult(pre.returncode == 0, "prébuild",
                         "" if pre.returncode == 0 else pre.stderr[-300:])
    for inst in instances:
        r = dep.up(box, inst, build=True, no_cache=no_cache)
        yield StepResult(r.returncode == 0, f"{inst.user} ({inst.entry_ip})",
                         "" if r.returncode == 0 else r.stderr[-300:])


def destroy_instance(deploy: Deployment, box: Box, inst: Instance) -> StepResult:
    r = dep.down(box, inst)
    deploy.remove(inst.box, inst.user)
    save(deploy)
    return StepResult(r.returncode == 0, f"{inst.user}", "" if r.returncode == 0 else r.stderr[-200:])


def write_wireguard(deploy: Deployment, endpoint: str) -> dict:
    """Écrit wg0.conf (serveur) + un .conf par binôme dans state/wg/.
    Renvoie {'server': path, 'clients': {project: path}}. Nécessite `wg`."""
    state.ensure_dirs()
    server_priv, server_pub = wireguard.ensure_server_keys()
    peers = []
    clients: dict[str, Path] = {}
    for inst in sorted(deploy.instances, key=lambda x: x.index):
        cpriv, cpub = wireguard.client_keys(inst)
        peers.append((inst.project, cpub, inst.wg_peer_ip))
        conf = wireguard.render_client_conf(
            cpriv, server_pub, endpoint, inst.wg_peer_ip, inst.access_subnet)
        cpath = state.WG_CLIENTS_DIR / f"{inst.project}.conf"
        cpath.write_text(conf, encoding="utf-8")
        clients[inst.project] = cpath
    # Peer "admin" : un seul profil qui route TOUT le lab, pour tester chaque
    # box depuis une seule Exegol (le pare-feu lui accorde tout le supernet).
    apriv, apub = wireguard.admin_keys()
    peers.append(("admin (tout le lab)", apub, ADMIN_WG_IP))
    admin_conf = wireguard.render_client_conf(apriv, server_pub, endpoint, ADMIN_WG_IP, LAB_SUPERNET)
    admin_path = state.WG_CLIENTS_DIR / "admin.conf"
    admin_path.write_text(admin_conf, encoding="utf-8")

    server_conf = wireguard.render_server_conf(server_priv, peers)
    spath = state.WG_DIR / "wg0.conf"
    spath.write_text(server_conf, encoding="utf-8")
    return {"server": spath, "clients": clients, "admin": admin_path}


def write_firewall_script(deploy: Deployment, **kw) -> Path:
    out = state.STATE_DIR / "firewall-lab.gen.sh"
    return firewall.write_script(deploy.instances, out, **kw)


def apply_firewall(deploy: Deployment, **kw):
    return firewall.apply(deploy.instances, **kw)


# --------------------------------------------------------------------------
# Réconciliation hôte automatique (VPS) : serveur WireGuard + pare-feu
# --------------------------------------------------------------------------

def host_ready() -> bool:
    """Vrai si on peut muter l'hôte : Linux + root + wg + iptables."""
    if os.name != "posix":
        return False
    try:
        if os.geteuid() != 0:
            return False
    except AttributeError:
        return False
    return bool(shutil.which("wg") and shutil.which("iptables"))


def _server_conf_text(deploy: Deployment) -> str:
    server_priv, _ = wireguard.ensure_server_keys()
    peers = []
    for inst in sorted(deploy.instances, key=lambda x: x.index):
        _, cpub = wireguard.client_keys(inst)
        peers.append((inst.project, cpub, inst.wg_peer_ip))
    _, apub = wireguard.admin_keys()
    peers.append(("admin", apub, ADMIN_WG_IP))
    return wireguard.render_server_conf(server_priv, peers)


def sync_server_wg(deploy: Deployment) -> None:
    """Régénère la config serveur (tous les peers + admin), l'installe dans
    /etc/wireguard/wg0.conf et la recharge à chaud (ou monte wg0)."""
    conf = _server_conf_text(deploy)
    (state.WG_DIR / "wg0.conf").write_text(conf, encoding="utf-8")
    WG_ETC.write_text(conf, encoding="utf-8")
    try:
        WG_ETC.chmod(0o600)
    except OSError:
        pass
    if subprocess.run(["wg", "show", WG_IF], capture_output=True).returncode != 0:
        subprocess.run(["wg-quick", "up", WG_IF], capture_output=True, text=True)
    else:
        strip = subprocess.run(["wg-quick", "strip", WG_IF], capture_output=True, text=True)
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False, encoding="utf-8") as fh:
            fh.write(strip.stdout)
            tmp = fh.name
        subprocess.run(["wg", "syncconf", WG_IF, tmp], capture_output=True, text=True)
        try:
            os.unlink(tmp)
        except OSError:
            pass


def reconcile_host(deploy: Deployment) -> list[StepResult]:
    """Applique l'état hôte après deploy/destroy : WireGuard serveur + pare-feu.
    No-op (avec message) hors VPS. Idempotent."""
    if not host_ready():
        return [StepResult(False, "hôte", "non-root ou wg/iptables absent — étape à faire sur la Debian")]
    out: list[StepResult] = []
    try:
        sync_server_wg(deploy)
        out.append(StepResult(True, "wireguard serveur", "rechargé"))
    except Exception as e:  # noqa: BLE001
        out.append(StepResult(False, "wireguard serveur", str(e)[:200]))
    write_firewall_script(deploy)
    r = apply_firewall(deploy)
    out.append(StepResult(r.returncode == 0, "pare-feu",
                          "" if r.returncode == 0 else (r.stderr or r.stdout)[-200:]))
    return out
