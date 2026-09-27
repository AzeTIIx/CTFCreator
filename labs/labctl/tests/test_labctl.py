"""Tests de la logique pure de labctl (sans Docker/WireGuard)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from labctl import firewall, wireguard  # noqa: E402
from labctl.discovery import discover_boxes  # noqa: E402
from labctl.model import Deployment, Instance, LabctlError, validate_no_overlap  # noqa: E402


# --- allocation ------------------------------------------------------------

def test_index_allocation_and_derivation():
    d = Deployment()
    a = d.add("box-a", "binome01")
    b = d.add("box-a", "binome02")
    assert (a.index, b.index) == (1, 2)
    assert a.entry_ip == "172.30.1.10"
    assert a.access_subnet == "172.30.1.0/24"
    assert a.bridge_name == "acc_b1"
    assert a.internal_bridge_name == "int_b1"
    assert a.wg_peer_ip == "10.99.0.11"
    assert b.wg_peer_ip == "10.99.0.12"
    assert a.project == "lab-box-a-binome01"


def test_add_is_idempotent():
    d = Deployment()
    x1 = d.add("box-a", "binome01")
    x2 = d.add("box-a", "binome01")
    assert x1 is x2 and len(d.instances) == 1


def test_reuse_freed_index():
    d = Deployment()
    d.add("b", "u1"); d.add("b", "u2"); d.add("b", "u3")
    d.remove("b", "u2")               # libère l'index 2
    assert d.add("b", "u4").index == 2


def test_multi_box_no_subnet_collision():
    d = Deployment()
    d.add("box-a", "u1")              # index 1
    d.add("box-b", "u1")              # index 2 (global) -> pas de collision
    validate_no_overlap(d)
    subnets = {i.access_subnet for i in d.instances}
    assert len(subnets) == 2


def test_index_out_of_range():
    with pytest.raises(LabctlError):
        Instance("b", "u", 999).entry_ip


# --- WireGuard (rendu pur) -------------------------------------------------

def test_render_client_conf():
    conf = wireguard.render_client_conf(
        "PRIV", "SRVPUB", "1.2.3.4", "10.99.0.11", "172.30.1.0/24")
    assert "Endpoint = 1.2.3.4:51820" in conf
    assert "AllowedIPs = 172.30.1.0/24" in conf
    assert "Address = 10.99.0.11/32" in conf


def test_render_server_conf_lists_peers():
    conf = wireguard.render_server_conf("SRVPRIV", [("b01", "P1", "10.99.0.11")])
    assert "ListenPort = 51820" in conf
    assert "PublicKey = P1" in conf
    assert "AllowedIPs = 10.99.0.11/32" in conf


# --- pare-feu (rendu pur) --------------------------------------------------

def test_firewall_has_per_instance_accept_and_guards():
    d = Deployment()
    d.add("box-a", "u1"); d.add("box-a", "u2")
    script = firewall.render_firewall_script(d.instances)
    # un ACCEPT par binôme, lié à son peer et son subnet
    assert "-s 10.99.0.11 -d 172.30.1.0/24 -j ACCEPT" in script
    assert "-s 10.99.0.12 -d 172.30.2.0/24 -j ACCEPT" in script
    # garde-fous
    assert '-i "$WG_IF" -j DROP' in script
    assert 'DOCKER_SUPERNET="172.16.0.0/12"' in script
    assert '-d "$DOCKER_SUPERNET" -j DROP' in script     # inter-bridge (CTFd/DB/...)
    assert '-o "$PUB_IF" -j DROP' in script             # egress
    assert "iptables -t raw -I PREROUTING" in script     # bypass Docker anti-direct-routing


# --- découverte des box ----------------------------------------------------

def test_discovers_boxes_and_ignores_template(tmp_path):
    for name in ("ma-box", "_template"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "box.yml").write_text(f"name: {name}\n", encoding="utf-8")
    names = {b.name for b in discover_boxes(tmp_path)}
    assert "ma-box" in names
    assert "_template" not in names
