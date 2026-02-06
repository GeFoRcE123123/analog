#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/deploy_strict.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "❌ Не найден ${ENV_FILE}. Создайте его и повторите."
  exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"

if [[ "${DEPLOY_GUARD:-NO}" != "YES" ]]; then
  echo "❌ DEPLOY_GUARD не установлен в YES. Остановка."
  exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
  echo "❌ Требуется sshpass (brew install hudochenkov/sshpass/sshpass)"
  exit 1
fi

TARGET="${1:-all}"

ping_check() {
  local host="$1"
  if [[ "${REQUIRE_PING:-0}" == "1" ]]; then
    ping -c 1 -W 2 "${host}" >/dev/null 2>&1
  fi
}

ssh_run() {
  local host="$1"
  local user="$2"
  local pass="$3"
  local cmd="$4"
  sshpass -p "${pass}" ssh ${SSH_OPTIONS} "${user}@${host}" "${cmd}"
}

rsync_push() {
  local src="$1"
  local host="$2"
  local user="$3"
  local pass="$4"
  local dst="$5"
  sshpass -p "${pass}" rsync -az --delete --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' --exclude='cache' \
    -e "ssh ${SSH_OPTIONS}" "${src}" "${user}@${host}:${dst}"
}

deploy_stack() {
  echo "🚀 Deploy core stack via scripts/deploy.sh (${TARGET})"
  export FRONTEND_IP BACKEND_IP DATABASE_IP PARSERS_IP
  export USER="${DEPLOY_USER}"
  export PASSWORD="${DEPLOY_PASSWORD}"
  "${SCRIPT_DIR}/deploy.sh" "${TARGET}"
}

deploy_osint() {
  echo "🚀 Deploy OSINT on ${OSINT_HOST}"
  if ! ping_check "${OSINT_HOST}"; then
    echo "❌ OSINT host недоступен: ${OSINT_HOST}"
    exit 1
  fi

  ssh_run "${OSINT_HOST}" "${OSINT_USER}" "${OSINT_PASSWORD}" \
    "echo '${OSINT_PASSWORD}' | sudo -S mkdir -p /opt/vulnerability_manager && \
     echo '${OSINT_PASSWORD}' | sudo -S chown ${OSINT_USER}:${OSINT_USER} /opt/vulnerability_manager"

  rsync_push "${ROOT_DIR}/osint-neural-network" "${OSINT_HOST}" "${OSINT_USER}" "${OSINT_PASSWORD}" "/opt/vulnerability_manager/"

  ssh_run "${OSINT_HOST}" "${OSINT_USER}" "${OSINT_PASSWORD}" \
    "echo '${OSINT_PASSWORD}' | sudo -S OSINT_API_PORT='${OSINT_API_PORT}' \
     OSINT_USE_LORA='${OSINT_USE_LORA}' OSINT_BASE_MODEL='${OSINT_BASE_MODEL}' \
     bash /opt/vulnerability_manager/osint-neural-network/scripts/deploy_osint_service.sh"
}

case "${TARGET}" in
  all)
    deploy_stack
    deploy_osint
    ;;
  osint)
    deploy_osint
    ;;
  frontend|backend|database|parsers)
    deploy_stack
    ;;
  *)
    echo "Использование: $0 [all|osint|frontend|backend|database|parsers]"
    exit 1
    ;;
esac

echo "✅ Unified deploy complete."
