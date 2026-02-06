#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
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
  echo "🔁 Legacy deploy: ${LEGACY_SCRIPT} ${LEGACY_ARGS:-}"
  bash "${LEGACY_PATH}" ${LEGACY_ARGS:-}
  echo "✅ ${SERVICE_NAME} deployed (legacy)."
  exit 0
fi

ping_check "${SERVICE_HOST}"

ssh_run "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" \
  "echo '${SERVICE_PASSWORD}' | sudo -S mkdir -p ${SERVICE_SYNC_DEST} && \
   echo '${SERVICE_PASSWORD}' | sudo -S chown ${SERVICE_USER}:${SERVICE_USER} ${SERVICE_SYNC_DEST}"

rsync_push "${SERVICE_SYNC_SRC}" "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" "${SERVICE_SYNC_DEST}"

if [[ -f "${SERVICE_ENV_LOCAL}" ]]; then
  write_remote_env "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" "${SERVICE_ENV_LOCAL}" "${SERVICE_ENV_REMOTE}"
fi

TMP_SERVICE="/tmp/${SERVICE_NAME}.service"
render_systemd "${SCRIPT_DIR}/../templates/systemd.service" "${TMP_SERVICE}" \
  "${SERVICE_NAME}" "${SERVICE_USER}" "${SERVICE_WORKDIR}" "${SERVICE_ENV_REMOTE}" "${SERVICE_EXEC_START}"

sshpass -p "${SERVICE_PASSWORD}" scp ${SSH_OPTIONS} "${TMP_SERVICE}" "${SERVICE_USER}@${SERVICE_HOST}:${TMP_SERVICE}"
ssh_run "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" \
  "echo '${SERVICE_PASSWORD}' | sudo -S mv ${TMP_SERVICE} /etc/systemd/system/${SERVICE_NAME}.service && \
   echo '${SERVICE_PASSWORD}' | sudo -S systemctl daemon-reload && \
   echo '${SERVICE_PASSWORD}' | sudo -S systemctl enable ${SERVICE_NAME} && \
   echo '${SERVICE_PASSWORD}' | sudo -S systemctl restart ${SERVICE_NAME}"

if [[ -n "${SERVICE_HEALTH_URL:-}" ]]; then
  ssh_run "${SERVICE_HOST}" "${SERVICE_USER}" "${SERVICE_PASSWORD}" \
    "curl -sSf ${SERVICE_HEALTH_URL} >/dev/null"
fi

echo "✅ ${SERVICE_NAME} deployed."
