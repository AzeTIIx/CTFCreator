#!/usr/bin/env bash
# provision-binome.sh — provisionne UN binôme : cible isolée + peer WireGuard.
#
# ⚠️ À RECETTER SUR LA CIBLE (Debian + WireGuard + Docker). Non exécuté sur le
#    poste de dev (Windows). La partie « cible Docker » (docker compose) a été
#    validée localement ; la partie WireGuard doit être recettée sur le VPS.
#
# Usage :
#   ./provision-binome.sh <numero_binome> <ip_publique_vps>
# Exemple :
#   ./provision-binome.sh 1 203.0.113.10
#
# Effets :
#   - lance la stack cible pour le binôme (réseau 172.30.<b>.0/24, gateway
#     172.30.<b>.10, vrais ports 21/22/80, intranet non routé) ;
#   - génère une paire de clés WireGuard pour le binôme ;
#   - écrit le profil client ./out/binome<NN>.conf à remettre au binôme ;
#   - affiche le bloc [Peer] à coller dans /etc/wireguard/wg0.conf.
#
# Les flags de séance doivent être exportés AVANT (FLAG_RECON=… etc.) pour
# être cuits dans l'image ; sinon le placeholder AFLO{local_test_only} est
# utilisé.

set -euo pipefail

B="${1:?numero de binôme requis}"
VPS_PUB_IP="${2:?ip publique du VPS requise}"
SERVER_PUBKEY_FILE="${SERVER_PUBKEY_FILE:-/etc/wireguard/server.pub}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/out"
mkdir -p "$OUT_DIR"

NN=$(printf '%02d' "$B")
PROJECT="binome$NN"
TARGET_SUBNET="172.30.$B.0/24"
TARGET_IP="172.30.$B.10"
VPN_CLIENT_ADDR="10.99.0.$((10 + B))"

CHALL_DIR="$SCRIPT_DIR/../deploy_challenges/challenges/s07-s08-intrusion-fil-rouge"
echo "[*] Binôme $B : clés du pivot (jalon 7) si nécessaire"
if [[ ! -f "$CHALL_DIR/challenge/gateway/secrets/id_ed25519" ]]; then
  bash "$CHALL_DIR/gen-pivot-key.sh"
fi

echo "[*] Binôme $B : lancement de la cible (projet $PROJECT, cible $TARGET_IP)"
BINOME_ID="$B" docker compose -p "$PROJECT" \
  -f "$SCRIPT_DIR/docker-compose.target.yml" up -d --build

echo "[*] Génération des clés WireGuard du binôme"
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(printf '%s' "$CLIENT_PRIV" | wg pubkey)

if [[ -f "$SERVER_PUBKEY_FILE" ]]; then
  SERVER_PUB=$(cat "$SERVER_PUBKEY_FILE")
else
  SERVER_PUB="<CLE_PUBLIQUE_SERVEUR>"
  echo "[!] $SERVER_PUBKEY_FILE introuvable — remplace <CLE_PUBLIQUE_SERVEUR> à la main."
fi

CONF="$OUT_DIR/$PROJECT.conf"
sed \
  -e "s#<VPN_CLIENT_ADDR>#$VPN_CLIENT_ADDR#g" \
  -e "s#<CLE_PRIVEE_CLIENT>#$CLIENT_PRIV#g" \
  -e "s#<CLE_PUBLIQUE_SERVEUR>#$SERVER_PUB#g" \
  -e "s#<IP_PUBLIQUE_VPS>#$VPS_PUB_IP#g" \
  -e "s#<TARGET_SUBNET>#$TARGET_SUBNET#g" \
  "$SCRIPT_DIR/wireguard/client.conf.template" > "$CONF"

echo ""
echo "[+] Profil client écrit : $CONF  (à remettre AU SEUL binôme $B)"
echo ""
echo "[+] À AJOUTER dans /etc/wireguard/wg0.conf puis 'wg syncconf wg0 <(wg-quick strip wg0)' :"
echo "    # --- binôme $B ---"
echo "    [Peer]"
echo "    PublicKey = $CLIENT_PUB"
echo "    AllowedIPs = $VPN_CLIENT_ADDR/32"
echo ""
echo "[i] Cible du binôme $B : $TARGET_IP  ports 21 (FTP) / 22 (SSH) / 80 (HTTP)"
echo "[i] Après avoir (ré)appliqué firewall-lab.sh (NB_BINOMES>=$B), teste la recette d'isolation."
