#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
IMAGE="__SLUG__:local"
NAME="chk-__SLUG__"
HOST_PORT="${HOST_PORT:-22000}"
export FLAG="${FLAG:-CCTF{local_test_only}}"
export TARGET_URL="${TARGET_URL:-http://127.0.0.1:${HOST_PORT}}"

run_py() {
  if command -v python3 >/dev/null 2>&1; then python3 "$@"
  elif command -v py >/dev/null 2>&1; then py -3 "$@"
  else python "$@"; fi
}
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[1/5] docker build"
docker build -t "$IMAGE" .

echo "[2/5] docker run (plugin-like)"
docker run -d --name "$NAME" \
  --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 256 \
  -m 512m --cpus 0.75 \
  -e "FLAG" -e "CTFD_FLAG" \
  -e CHALLENGE_ID=0 -e TEAM_ID=0 -e USER_ID=0 \
  -p "${HOST_PORT}:1337" \
  "$IMAGE"

echo "[3/5] wait"
for i in $(seq 1 60); do
  if curl -fsS "${TARGET_URL}/" >/dev/null 2>&1 || curl -fsS "${TARGET_URL}/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
  if [[ "$i" -eq 60 ]]; then echo "FAIL: not ready" >&2; docker logs "$NAME" || true; exit 1; fi
done

echo "[4/5] tests"
run_py tests/exploit_poc.py
run_py tests/security_audit.py
echo "[5/5] GREEN CHECK OK"
