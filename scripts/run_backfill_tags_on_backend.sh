#!/bin/bash
# Run tag backfill inside backend docker container (real DB update).
#
# This script:
# 1) copies scripts/ai/backfill_tags_from_ai_analysis.py to Backend VM
# 2) docker cp -> vulnerability-backend:/app/scripts/ai/
# 3) runs python3 inside container
#
# Usage:
#   ./scripts/run_backfill_tags_on_backend.sh
#
# Env overrides:
#   BACKEND_VM=10.0.88.20 BACKEND_USER=user BACKEND_PASS=123 CONTAINER=vulnerability-backend APP_DIR=/app

set -euo pipefail

BACKEND_VM="${BACKEND_VM:-10.0.88.20}"
BACKEND_USER="${BACKEND_USER:-user}"
BACKEND_PASS="${BACKEND_PASS:-123}"
CONTAINER="${CONTAINER:-vulnerability-backend}"
APP_DIR="${APP_DIR:-/app}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
LOCAL_SCRIPT="scripts/ai/backfill_tags_from_ai_analysis.py"

if [ ! -f "$LOCAL_SCRIPT" ]; then
  echo "❌ Missing local script: $LOCAL_SCRIPT"
  exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
  echo "❌ sshpass not found. Install it locally (brew install sshpass) or run manual SSH."
  exit 1
fi

export SSHPASS="$BACKEND_PASS"

echo "🚀 Backfill tags -> ${BACKEND_USER}@${BACKEND_VM} (container: ${CONTAINER})"
echo "Script: ${LOCAL_SCRIPT}"
echo

echo "1) Copy script to VM (~/vulnerability_manager/${LOCAL_SCRIPT})"
sshpass -e ssh $SSH_OPTS "${BACKEND_USER}@${BACKEND_VM}" "mkdir -p ~/vulnerability_manager/scripts/ai"
sshpass -e scp $SSH_OPTS "$LOCAL_SCRIPT" "${BACKEND_USER}@${BACKEND_VM}:~/vulnerability_manager/${LOCAL_SCRIPT}"

echo "2) Copy script into container (${APP_DIR}/scripts/ai/...)"
sshpass -e ssh $SSH_OPTS "${BACKEND_USER}@${BACKEND_VM}" "echo '${BACKEND_PASS}' | sudo -S docker exec ${CONTAINER} mkdir -p ${APP_DIR}/scripts/ai"
sshpass -e ssh $SSH_OPTS "${BACKEND_USER}@${BACKEND_VM}" "echo '${BACKEND_PASS}' | sudo -S docker cp ~/vulnerability_manager/${LOCAL_SCRIPT} ${CONTAINER}:${APP_DIR}/${LOCAL_SCRIPT}"

echo "3) Run backfill inside container (this can take a few minutes)"
sshpass -e ssh $SSH_OPTS "${BACKEND_USER}@${BACKEND_VM}" "echo '${BACKEND_PASS}' | sudo -S docker exec ${CONTAINER} python3 ${APP_DIR}/${LOCAL_SCRIPT}"

echo
echo "4) Quick verification: count rows containing '\"tags\"' and '\"ml\"'"
sshpass -e ssh $SSH_OPTS "${BACKEND_USER}@${BACKEND_VM}" "echo '${BACKEND_PASS}' | sudo -S docker exec ${CONTAINER} python3 - <<'PY'\nimport json\nfrom models.database import DatabaseManager\n\ndb=DatabaseManager().connection\ncur=db.cursor()\ncur.execute(\"SELECT COUNT(*) FROM turn WHERE etc ILIKE %s\", ('%\"tags\"%',))\nprint('rows_with_tags:', cur.fetchone()[0])\ncur.execute(\"SELECT COUNT(*) FROM turn WHERE etc ILIKE %s\", ('%\"ml\"%',))\nprint('rows_with_ml_tag_like:', cur.fetchone()[0])\ncur.close()\nPY"

echo
echo "✅ Done. Re-check UI filters:"
echo " - /vulnerabilities?tags=ml"
echo " - open a vulnerability -> check 'Теги' column / modal"


