"""Génération WireGuard : clés (via `wg`) et rendu des configs (pur, testable).

- render_server_conf / render_client_conf : texte pur, sans dépendance à `wg`.
- gen_keypair / ensure_server_keys / client_keys : nécessitent le binaire `wg`
  (présent sur la Debian ; peut manquer sur le poste de dev Windows).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .model import WG_PORT, WG_SERVER_CIDR, Instance
from . import state


def wg_available() -> bool:
    return shutil.which("wg") is not None


def gen_keypair() -> tuple[str, str]:
    if not wg_available():
        raise RuntimeError("binaire `wg` introuvable (installe wireguard-tools)")
    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
    return priv, pub


# --------------------------------------------------------------------------
# Rendu (pur)
# --------------------------------------------------------------------------

def render_server_conf(server_priv: str, peers: list[tuple[str, str, str]]) -> str:
    """peers = [(label, client_pubkey, client_ip)]."""
    lines = [
        "[Interface]",
        f"Address = {WG_SERVER_CIDR}",
        f"ListenPort = {WG_PORT}",
        f"PrivateKey = {server_priv}",
        "",
    ]
    for label, pub, ip in peers:
        lines += [
            f"# {label}",
            "[Peer]",
            f"PublicKey = {pub}",
            f"AllowedIPs = {ip}/32",
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def render_client_conf(client_priv: str, server_pub: str, endpoint: str,
                       client_ip: str, target_subnet: str) -> str:
    """Le client ne route dans le tunnel QUE le /24 de sa cible."""
    return (
        "[Interface]\n"
        f"Address = {client_ip}/32\n"
        f"PrivateKey = {client_priv}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"Endpoint = {endpoint}:{WG_PORT}\n"
        f"AllowedIPs = {target_subnet}\n"
        "PersistentKeepalive = 25\n"
    )


# --------------------------------------------------------------------------
# Gestion des clés persistées (host)
# --------------------------------------------------------------------------

def ensure_server_keys() -> tuple[str, str]:
    state.ensure_dirs()
    priv_f = state.WG_DIR / "server.key"
    pub_f = state.WG_DIR / "server.pub"
    if priv_f.is_file() and pub_f.is_file():
        return priv_f.read_text().strip(), pub_f.read_text().strip()
    priv, pub = gen_keypair()
    priv_f.write_text(priv + "\n", encoding="utf-8")
    pub_f.write_text(pub + "\n", encoding="utf-8")
    try:
        priv_f.chmod(0o600)
    except OSError:
        pass
    return priv, pub


def _named_keys(name: str) -> tuple[str, str]:
    state.ensure_dirs()
    priv_f = state.WG_CLIENTS_DIR / f"{name}.key"
    pub_f = state.WG_CLIENTS_DIR / f"{name}.pub"
    if priv_f.is_file() and pub_f.is_file():
        return priv_f.read_text().strip(), pub_f.read_text().strip()
    priv, pub = gen_keypair()
    priv_f.write_text(priv + "\n", encoding="utf-8")
    pub_f.write_text(pub + "\n", encoding="utf-8")
    try:
        priv_f.chmod(0o600)
    except OSError:
        pass
    return priv, pub


def client_keys(inst: Instance) -> tuple[str, str]:
    return _named_keys(inst.project)


def admin_keys() -> tuple[str, str]:
    return _named_keys("admin")
