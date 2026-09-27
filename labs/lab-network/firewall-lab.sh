#!/usr/bin/env bash
# firewall-lab.sh — cloisonnement du lab d'intrusion (VPS Debian 12).
#
# Environnement CIBLE (validé pas à pas sur le VPS) :
#   - hôte géré par UFW (backend iptables-nft), INPUT policy DROP ;
#   - Docker 27 (ajoute des DROP anti-direct-routing dans la table raw) ;
#   - accès étudiant par WireGuard (wg0), un /24 Docker routé par binôme.
#
# Ce script consolide la config prouvée + pose les garde-fous d'isolation.
# Ordre : (1) réglages hôte via UFW, (2) bypass raw pour wg0→lab (Docker 27),
# (3) filtrage FORWARD dans DOCKER-USER (par-binôme + blocages).
#
# ⚠️ Garde une console hors-bande ouverte. Lance-le APRÈS avoir provisionné
#    les binômes, et RELANCE-le après tout redémarrage de Docker (Docker
#    réécrit ses règles raw/forward).

set -euo pipefail

# --- Variables -------------------------------------------------------------
WG_IF="wg0"
WG_NET="10.99.0.0/24"           # peers WireGuard (Kali des binômes)
PUB_IF="eth0"                  # interface publique (egress)
LAB_SUPERNET="172.30.0.0/16"    # tous les access_b<b>
DOCKER_SUPERNET="172.16.0.0/12" # TOUS les bridges (CTFd/DB/Redis/registre/proxy + lab)
HOST_SVC_PORTS="22 80 443"      # services hôte à interdire au lab/VPN (CTFd derrière nginx)
NB_BINOMES="${NB_BINOMES:-10}"
# binôme b : peer 10.99.0.$((10+b))  ->  cible 172.30.$b.0/24
# --------------------------------------------------------------------------

need_root() { [ "$(id -u)" = 0 ] || { echo "Lance en root."; exit 1; }; }
need_root

echo "==> (1/3) Réglages hôte via UFW"
# a) Allows de base — SSH EN PREMIER pour ne jamais se verrouiller, puis
#    CTFd (nginx 80/443) et la poignée de main WireGuard.
ufw allow 22/tcp    comment 'ssh admin'     >/dev/null || true
ufw allow 80/tcp    comment 'ctfd http'     >/dev/null || true
ufw allow 443/tcp   comment 'ctfd https'    >/dev/null || true
ufw allow 51820/udp comment 'wireguard lab' >/dev/null || true
# b) Autoriser le transit (routé). Le filtrage fin est fait par DOCKER-USER.
if ! grep -q '^DEFAULT_FORWARD_POLICY="ACCEPT"' /etc/default/ufw; then
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
fi
# c) Rendre ip_forward persistant CÔTÉ UFW (il écrase le sysctl système au reload).
grep -q '^net/ipv4/ip_forward=1' /etc/ufw/sysctl.conf || echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf
# d) Interdire au lab ET au VPN d'atteindre les services de l'hôte
#    (CTFd via nginx 80/443, SSH 22). INPUT policy est DROP, mais 22/80/443
#    sont "allow from any" -> on insère des deny prioritaires pour ces sources.
for net in "$WG_NET" "$LAB_SUPERNET"; do
  for p in $HOST_SVC_PORTS; do
    ufw insert 1 deny from "$net" to any port "$p" proto tcp >/dev/null 2>&1 || true
  done
done
# e) Activer UFW (idempotent) et recharger.
ufw --force enable >/dev/null
ufw reload >/dev/null
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "==> (2/3) Bypass raw pour wg0 -> lab (contourne le DROP anti-direct-routing de Docker 27)"
# Sans cette règle, la table raw jette 'dst=<cible> ! -i <bridge>' AVANT FORWARD :
# le trafic WireGuard (arrivant par wg0) n'atteindrait jamais les cibles.
# Insérée en tête de raw/PREROUTING, avant les DROP de Docker.
iptables -t raw -C PREROUTING -i "$WG_IF" -d "$LAB_SUPERNET" -j ACCEPT 2>/dev/null || \
  iptables -t raw -I PREROUTING -i "$WG_IF" -d "$LAB_SUPERNET" -j ACCEPT

echo "==> (3/3) Filtrage FORWARD (chaîne DOCKER-USER)"
# DOCKER-USER est traversée en premier dans FORWARD et n'est pas gérée par
# Docker : on la reconstruit entièrement pour le lab.
iptables -F DOCKER-USER 2>/dev/null || true

# 3a) Retours de connexions établies.
iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# 3b) Chaque binôme : SON peer -> UNIQUEMENT sa cible.
for b in $(seq 1 "$NB_BINOMES"); do
  peer="10.99.0.$((10 + b))"
  target_net="172.30.$b.0/24"
  iptables -A DOCKER-USER -i "$WG_IF" -s "$peer" -d "$target_net" -j ACCEPT
done

# 3c) Tout autre trafic issu du VPN est jeté (autre binôme, hôte-transit,
#     Internet) : un peer ne peut atteindre QUE sa cible.
iptables -A DOCKER-USER -i "$WG_IF" -j DROP

# 3d) Depuis une cible compromise : bloquer l'inter-bridge (CTFd/DB/Redis/
#     registre/dockerproxy + autres binômes). CRUCIAL (dockerproxy = évasion).
iptables -A DOCKER-USER -s "$LAB_SUPERNET" -d "$DOCKER_SUPERNET" -j DROP

# 3e) Depuis une cible : couper l'egress Internet.
iptables -A DOCKER-USER -s "$LAB_SUPERNET" -o "$PUB_IF" -j DROP

echo ""
echo "[+] Cloisonnement appliqué (NB_BINOMES=$NB_BINOMES)."
echo "    Vérifs :  iptables -t raw -S PREROUTING | grep $WG_IF"
echo "              iptables -vnL DOCKER-USER"
echo "              ufw status | grep -E 'DENY|51820'"
echo ""
echo "[i] Persistance : les règles raw/DOCKER-USER ne survivent ni au reboot ni"
echo "    à un 'systemctl restart docker'. NE PAS utiliser iptables-persistent"
echo "    (incompatible ufw + risqué avec Docker). Utilise la unit systemd"
echo "    lab-firewall.service (After=docker.service) qui rejoue ce script, et"
echo "    relance-le à la main après chaque provisioning de binôme."
echo "[i] IPv6 : lab IPv4 only ; durcis l'accès IPv6 à CTFd/SSH séparément."
echo ""
echo "[!] Déroule la RECETTE d'isolation (README §Recette) AVANT d'ouvrir aux"
echo "    étudiants : nmap=cible seule, VPN->hôte 22/80/443 KO, VPN->voisin KO,"
echo "    cible->CTFd/DB/dockerproxy KO, egress KO."
