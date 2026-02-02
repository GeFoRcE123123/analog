#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="${1:-}"

if [[ -z "${SERVICE_NAME}" ]]; then
  echo "Использование: $0 <service>"
  exit 1
fi

# shellcheck disable=SC1090
source "${SCRIPT_DIR}/../lib/common.sh"

require_guard
require_sshpass

SERVICE_ENV_FILE="${SCRIPT_DIR}/../services/${SERVICE_NAME}.env"
if [[ ! -f "${SERVICE_ENV_FILE}" ]]; then
  echo "❌ Не найден ${SERVICE_ENV_FILE}"
  exit 1
fi

# shellcheck disable=SC1090
source "${SERVICE_ENV_FILE}"

if [[ "${FORCE_REDEPLOY:-NO}" != "YES" ]]; then
  echo "❌ Для строгого редеплоя установите FORCE_REDEPLOY=YES"
  exit 1
fi

if [[ "${SERVICE_DEPLOY_MODE:-systemd}" == "legacy" ]]; then
  if [[ -z "${LEGACY_SCRIPT:-}" ]]; then
    echo "❌ Для legacy режима нужен LEGACY_SCRIPT в ${SERVICE_ENV_FILE}"
    exit 1
  fi
  LEGACY_PATH="${ROOT_DIR}/${LEGACY_SCRIPT}"
  if [[ ! -f "${LEGACY_PATH}" ]]; then
    echo "❌ Legacy скрипт не найден: ${LEGACY_PATH}"
    exit 1
  fi
  echo "🔁 Legacy strict redeploy: ${LEGACY_SCRIPT} ${LEGACY_ARGS:-}"
  bash "${LEGACY_PATH}" ${LEGACY_ARGS:-}
  echo "✅ ${SERVICE_NAME} strict redeploy complete (legacy)."
  exit 0
fi

ping_check "${SERVICE_HOST}"

ssh_run "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" \
  "echo '${SERVICE_PASSWORD}' | sudo -S systemctl stop ${SERVICE_NAME} || true"

rsync_push "${SERVICE_SYNC_SRC}" "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" "${SERVICE_SYNC_DEST}"

if [[ -f "${SERVICE_ENV_LOCAL}" ]]; then
  write_remote_env "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" "${SERVICE_ENV_LOCAL}" "${SERVICE_ENV_REMOTE}"
fi

ssh_run "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" \
  "echo '${SERVICE_PASSWORD}' | sudo -S systemctl daemon-reload && \
   echo '${SERVICE_PASSWORD}' | sudo -S systemctl start ${SERVICE_NAME}"

if [[ -n "${SERVICE_HEALTH_URL:-}" ]]; then
  ssh_run "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" \
    "curl -sSf ${SERVICE_HEALTH_URL} >/dev/null"
fi

echo "✅ ${SERVICE_NAME} strict redeploy complete."
