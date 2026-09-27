#!/usr/bin/env bash
# Installation de la supervision (cAdvisor + node_exporter + Prometheus + Grafana).
# Usage (root) :
#   ./install.sh                                   # stack seule
#   ./install.sh --ssh-tunnel "azetix denis fafanellu"   # + autorise le tunnel SSH vers Grafana
# Idempotent : relançable ; ne régénère pas le mot de passe Grafana existant.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -p monitoring --project-directory "$DIR" -f "$DIR/docker-compose.monitoring.yml")
TUNNEL_USERS=""
SSHD_DROPIN=/etc/ssh/sshd_config.d/60-monitoring-tunnel.conf

ok()   { printf '[OK]   %s\n' "$*"; }
info() { printf '[INFO] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-tunnel) TUNNEL_USERS="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) fail "Argument inconnu : $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "À lancer en root (sudo)."
command -v docker >/dev/null || fail "docker absent"
docker compose version >/dev/null 2>&1 || fail "plugin docker compose v2 absent"
command -v curl >/dev/null || fail "curl absent (apt install curl)"

# --- Secret Grafana -----------------------------------------------------------
ENV_FILE="$DIR/.env"
if [[ ! -f "$ENV_FILE" ]] || ! grep -q '^GRAFANA_ADMIN_PASSWORD=.' "$ENV_FILE"; then
  umask 077
  pw="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
  echo "GRAFANA_ADMIN_PASSWORD=$pw" >> "$ENV_FILE"
  unset pw
  ok "Mot de passe admin Grafana généré dans $ENV_FILE (non affiché)"
fi
chmod 600 "$ENV_FILE"

# --- Validation config ----------------------------------------------------------
PROM_IMAGE="$(grep -E '^PROMETHEUS_IMAGE=' "$ENV_FILE" | cut -d= -f2- || true)"
PROM_IMAGE="${PROM_IMAGE:-prom/prometheus:v3.13.0}"
"${COMPOSE[@]}" config -q || fail "docker-compose.monitoring.yml invalide"
"${COMPOSE[@]}" pull || fail "pull échoué — vérifier les tags d'images (cAdvisor : ghcr.io/google/cadvisor:<version>)"
docker run --rm --entrypoint promtool -v "$DIR/prometheus:/etc/prometheus:ro" "$PROM_IMAGE" \
  check config /etc/prometheus/prometheus.yml >/dev/null || fail "prometheus.yml / règles invalides (promtool)"
ok "Config Prometheus + règles validées (promtool)"

# --- Démarrage ------------------------------------------------------------------
"${COMPOSE[@]}" up -d
info "Attente de Prometheus et Grafana…"
for i in $(seq 1 30); do
  if curl -fsS -o /dev/null http://127.0.0.1:9090/-/ready && curl -fsS -o /dev/null http://127.0.0.1:3000/api/health; then
    ok "Prometheus et Grafana prêts"; break
  fi
  [[ $i -eq 30 ]] && fail "Timeout — voir : ${COMPOSE[*]} logs --tail 50"
  sleep 3
done

# Laisse passer au moins un scrape
sleep 20
curl -fsS http://127.0.0.1:9090/api/v1/targets | python3 -c '
import json,sys
bad=0
for t in json.load(sys.stdin)["data"]["activeTargets"]:
    h=t["health"]; bad+= h!="up"
    tag="OK" if h=="up" else "FAIL"
    print("[%-4s] cible %-11s %s %s" % (tag, t["labels"]["job"], h, t.get("lastError","")))
sys.exit(1 if bad else 0)
' || fail "Au moins une cible de scrape est down"

q() { curl -fsS --get http://127.0.0.1:9090/api/v1/query --data-urlencode "query=$1" \
      | python3 -c 'import json,sys;r=json.load(sys.stdin)["data"]["result"];print(r[0]["value"][1] if r else "0")'; }
n_ctfd="$(q 'count(container_memory_working_set_bytes{container_label_com_docker_compose_service=~"ctfd|nginx|db|cache"})')"
n_chal="$(q 'count(container_memory_working_set_bytes{name=~"chal-.*"})')"
if [[ "$n_ctfd" -ge 4 ]]; then ok "cAdvisor voit la stack CTFd ($n_ctfd conteneurs)"
else printf '[WARN] cAdvisor ne voit que %s/4 services CTFd — labels compose ?\n' "$n_ctfd"; fi
info "Conteneurs challenge actuellement vus : $n_chal"

# --- Tunnel SSH (optionnel) ----------------------------------------------------
if [[ -n "$TUNNEL_USERS" ]]; then
  for u in $TUNNEL_USERS; do id "$u" >/dev/null 2>&1 || fail "Utilisateur inconnu : $u"; done
  mkdir -p /run/sshd
  backup=""
  if [[ -f "$SSHD_DROPIN" ]]; then
    backup="$SSHD_DROPIN.bak.$(date +%Y%m%dT%H%M%S)"; cp -a "$SSHD_DROPIN" "$backup"
  fi
  users_csv="$(echo "$TUNNEL_USERS" | xargs | tr ' ' ',')"
  sed "s/__USERS__/$users_csv/" "$DIR/sshd/60-monitoring-tunnel.conf" > "$SSHD_DROPIN"
  chmod 644 "$SSHD_DROPIN"

  rollback() {
    if [[ -n "$backup" ]]; then cp -a "$backup" "$SSHD_DROPIN"; else rm -f "$SSHD_DROPIN"; fi
    fail "$1 — drop-in SSH annulé, sshd non rechargé"
  }
  sshd -t || rollback "sshd -t en échec"
  sshd -T | grep -qi '^allowtcpforwarding no' || rollback "le forwarding global n'est plus à 'no'"
  for u in $TUNNEL_USERS; do
    sshd -T -C "user=$u,host=probe,addr=203.0.113.1" | grep -qi '^allowtcpforwarding local' \
      || rollback "le Match ne s'applique pas à $u (ordre des drop-ins ?)"
  done
  systemctl reload ssh 2>/dev/null || systemctl reload sshd || rollback "reload sshd échoué"
  ok "Tunnel SSH autorisé (local forward vers 127.0.0.1:3000/9090) pour : $users_csv"
  info "Garder la session actuelle ouverte et tester une nouvelle connexion SSH avant de fermer."
fi

cat <<EOF

Accès (depuis ton poste) :
  ssh -N -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 <user>@<vps>
  Grafana    : http://localhost:3000  (admin / mot de passe : sudo grep GRAFANA $ENV_FILE)
  Prometheus : http://localhost:9090/alerts
Dashboard par défaut : CTF — Vue d'ensemble
EOF
