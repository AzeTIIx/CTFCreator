"""Génération du pare-feu (cloisonnement prouvé de infra/lab-network/).

render_firewall_script() produit un script bash idempotent qui pose, pour les
instances actives :
  - UFW : allow 22/80/443/51820 ; deny VPN+lab -> services hôte ;
          DEFAULT_FORWARD_POLICY=ACCEPT ; ip_forward persistant ;
  - table raw : bypass wg0 -> lab (contourne l'anti-direct-routing de Docker) ;
  - DOCKER-USER : chaque peer VPN -> SA cible seulement ; puis DROP du reste
                  (autre binôme, hôte-transit, egress), et blocage inter-bridge
                  cible -> CTFd/DB/registre/dockerproxy.
Le texte est pur (testable). apply() l'exécute (host Debian uniquement).
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from .model import ADMIN_WG_IP, DOCKER_SUPERNET, LAB_SUPERNET, WG_PORT, Instance

DEFAULT_HOST_PORTS = ("22", "80", "443")


def render_firewall_script(instances: list[Instance], *, wg_if: str = "wg0",
                           pub_if: str = "eth0",
                           host_ports: tuple[str, ...] = DEFAULT_HOST_PORTS,
                           wg_net: str = "10.99.0.0/24") -> str:
    accepts = "\n".join(
        f'iptables -A DOCKER-USER -i "$WG_IF" -s {i.wg_peer_ip} -d {i.access_subnet} -j ACCEPT'
        f'   # {i.box}/{i.user}'
        for i in sorted(instances, key=lambda x: x.index)
    ) or "# (aucune instance active)"

    ports_sh = " ".join(host_ports)
    return f"""#!/usr/bin/env bash
# GÉNÉRÉ PAR labctl — ne pas éditer à la main. Cloisonnement du lab.
# Idempotent. À relancer après tout `systemctl restart docker` / provisioning.
set -euo pipefail
[ "$(id -u)" = 0 ] || {{ echo "Lance en root."; exit 1; }}

WG_IF="{wg_if}"
PUB_IF="{pub_if}"
WG_NET="{wg_net}"
LAB_SUPERNET="{LAB_SUPERNET}"
DOCKER_SUPERNET="{DOCKER_SUPERNET}"
HOST_PORTS="{ports_sh}"

echo "==> UFW (hôte)"
ufw allow 22/tcp    comment 'ssh admin'     >/dev/null || true
ufw allow 80/tcp    comment 'ctfd http'     >/dev/null || true
ufw allow 443/tcp   comment 'ctfd https'    >/dev/null || true
ufw allow {WG_PORT}/udp comment 'wireguard lab' >/dev/null || true
grep -q '^DEFAULT_FORWARD_POLICY="ACCEPT"' /etc/default/ufw || \\
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
grep -q '^net/ipv4/ip_forward=1' /etc/ufw/sysctl.conf || echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf
for net in "$WG_NET" "$LAB_SUPERNET"; do
  for p in $HOST_PORTS; do
    ufw insert 1 deny from "$net" to any port "$p" proto tcp >/dev/null 2>&1 || true
  done
done
ufw --force enable >/dev/null
ufw reload >/dev/null
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "==> table raw : bypass wg0 -> lab (Docker anti-direct-routing)"
iptables -t raw -C PREROUTING -i "$WG_IF" -d "$LAB_SUPERNET" -j ACCEPT 2>/dev/null || \\
  iptables -t raw -I PREROUTING -i "$WG_IF" -d "$LAB_SUPERNET" -j ACCEPT

echo "==> DOCKER-USER : cloisonnement par user"
iptables -F DOCKER-USER 2>/dev/null || true
iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# admin : un seul peer qui atteint TOUT le lab (pour tester depuis une Exegol)
iptables -A DOCKER-USER -i "$WG_IF" -s {ADMIN_WG_IP} -d "$LAB_SUPERNET" -j ACCEPT
{accepts}
iptables -A DOCKER-USER -i "$WG_IF" -j DROP
iptables -A DOCKER-USER -s "$LAB_SUPERNET" -d "$DOCKER_SUPERNET" -j DROP
iptables -A DOCKER-USER -s "$LAB_SUPERNET" -o "$PUB_IF" -j DROP

echo "[+] Cloisonnement appliqué ({len(instances)} instance(s))."
"""


def write_script(instances: list[Instance], out_path: Path, **kw) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_firewall_script(instances, **kw), encoding="utf-8")
    try:
        out_path.chmod(0o755)
    except OSError:
        pass
    return out_path


def apply(instances: list[Instance], **kw) -> subprocess.CompletedProcess:
    """Exécute le script généré (host Debian). Nécessite root + iptables/ufw."""
    script = render_firewall_script(instances, **kw)
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8") as fh:
        fh.write(script)
        tmp = fh.name
    return subprocess.run(["bash", tmp], capture_output=True, text=True)
