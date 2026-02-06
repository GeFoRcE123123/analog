#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck disable=SC1090
source "${SCRIPT_DIR}/../lib/common.sh"

require_guard
require_sshpass

BACKEND_IP="${BACKEND_IP:-10.0.88.20}"
BACKEND_USER="${DEPLOY_USER:-user}"
BACKEND_PASSWORD="${DEPLOY_PASSWORD:-123}"

OSINT_API_URL="${OSINT_API_URL:-http://${OSINT_HOST:-10.0.88.25}:${OSINT_API_PORT:-8010}}"
ML_PLATFORM_URL="${ML_PLATFORM_URL:-http://${ML_PLATFORM_HOST:-10.0.88.25}:${ML_PLATFORM_API_PORT:-8000}}"

REMOTE_DIR="/home/${BACKEND_USER}/vulnerability_manager/backend"
REMOTE_ENV="${REMOTE_DIR}/.env"

ping_check "${BACKEND_IP}"

ssh_run "${BACKEND_IP}" "${BACKEND_USER}" "${BACKEND_PASSWORD}" "mkdir -p ${REMOTE_DIR}"

sshpass -p "${BACKEND_PASSWORD}" ssh ${SSH_OPTIONS} "${BACKEND_USER}@${BACKEND_IP}" "cat <<'EOF' > ${REMOTE_ENV}
OSINT_API_URL=${OSINT_API_URL}
ML_PLATFORM_API_URL=${ML_PLATFORM_URL}
EOF"

ssh_run "${BACKEND_IP}" "${BACKEND_USER}" "${BACKEND_PASSWORD}" \
  "echo '${BACKEND_PASSWORD}' | sudo -S chmod 600 ${REMOTE_ENV} || true"

echo "✅ Backend .env updated: ${REMOTE_ENV}"
