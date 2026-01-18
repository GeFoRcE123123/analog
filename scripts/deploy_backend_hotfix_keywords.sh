#!/bin/bash
# Hotfix deploy: keyword stats + tags/ml filter fallbacks
#
# Copies updated files to Backend VM and into the running Docker container `vulnerability-backend`.
#
# Usage:
#   ./scripts/deploy_backend_hotfix_keywords.sh
#
# Env overrides:
#   BACKEND_VM=10.0.88.20 BACKEND_USER=user BACKEND_PASS=123 CONTAINER=vulnerability-backend APP_DIR=/app ./scripts/deploy_backend_hotfix_keywords.sh

set -euo pipefail

BACKEND_VM="${BACKEND_VM:-10.0.88.20}"
BACKEND_USER="${BACKEND_USER:-user}"
BACKEND_PASS="${BACKEND_PASS:-123}"
CONTAINER="${CONTAINER:-vulnerability-backend}"
APP_DIR="${APP_DIR:-/app}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

FILES=(
  "services/ml_platform_client.py"
  "models/legacy_repositories.py"
  "templates/ai/dashboard.html"
  "templates/ai/statistics.html"
)

echo "🚀 Deploy hotfix -> ${BACKEND_USER}@${BACKEND_VM} (container: ${CONTAINER})"
echo "Files:"
for f in "${FILES[@]}"; do echo " - $f"; done
echo

if ! command -v sshpass >/dev/null 2>&1; then
  echo "❌ sshpass not found. Install it locally (brew install sshpass) or run manual SSH."
  exit 1
fi

export SSHPASS="$BACKEND_PASS"

echo "1) Ping backend VM..."
ping -c 1 -W 2 "$BACKEND_VM" >/dev/null 2>&1 && echo "✅ reachable" || { echo "❌ unreachable"; exit 1; }

echo "2) Copy files to VM home folder (~/vulnerability_manager/...)"
for f in "${FILES[@]}"; do
  if [ ! -f "$f" ]; then
    echo "❌ Missing local file: $f"
    exit 1
  fi
  remote_dir="~/vulnerability_manager/$(dirname "$f")"
  sshpass -e ssh $SSH_OPTS "${BACKEND_USER}@${BACKEND_VM}" "mkdir -p ${remote_dir}"
  sshpass -e scp $SSH_OPTS "$f" "${BACKEND_USER}@${BACKEND_VM}:~/vulnerability_manager/$f"
done

echo "3) Copy files into container and restart"
for f in "${FILES[@]}"; do
  sshpass -e ssh $SSH_OPTS "${BACKEND_USER}@${BACKEND_VM}" "echo '${BACKEND_PASS}' | sudo -S docker cp ~/vulnerability_manager/$f ${CONTAINER}:${APP_DIR}/$f"
done

sshpass -e ssh $SSH_OPTS "${BACKEND_USER}@${BACKEND_VM}" "echo '${BACKEND_PASS}' | sudo -S docker restart ${CONTAINER}"

echo "4) Show last logs (20 lines)"
sshpass -e ssh $SSH_OPTS "${BACKEND_USER}@${BACKEND_VM}" "echo '${BACKEND_PASS}' | sudo -S docker logs ${CONTAINER} --tail 20"

echo
echo "✅ Done. Hard-refresh the browser and re-check:"
echo " - /ai/dashboard -> click 'Статистика по ключевым словам' (modal)"
echo " - /ai/statistics -> top keywords"
echo " - /vulnerabilities?tags=ml -> should not be empty after AI analysis"


