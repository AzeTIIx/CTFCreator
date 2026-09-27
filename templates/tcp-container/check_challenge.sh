#!/usr/bin/env bash
# Recette locale : build + run durci (comme le plugin) + test d'exploitation.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
IMAGE="__SLUG__:local"; NAME="chk-__SLUG__"; HOST_PORT="${HOST_PORT:-22000}"
export FLAG="${FLAG:-CCTF{local_test_only}}" TARGET_PORT="$HOST_PORT"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker build -t "$IMAGE" .
docker run -d --name "$NAME" --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 256 -m 128m --cpus 0.25 -p "${HOST_PORT}:1337" "$IMAGE"
sleep 2
python3 tests/exploit_poc.py
echo "GREEN CHECK OK"
