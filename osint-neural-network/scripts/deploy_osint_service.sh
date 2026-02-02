#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="${APP_ROOT:-/opt/vulnerability_manager}"
OSINT_DIR="${OSINT_DIR:-$APP_ROOT/osint-neural-network}"
VENV_DIR="${VENV_DIR:-$OSINT_DIR/venv}"
SERVICE_NAME="${SERVICE_NAME:-osint-neural-network}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/${SERVICE_NAME}.env"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-ubuntu}}"

OSINT_API_HOST="${OSINT_API_HOST:-0.0.0.0}"
OSINT_API_PORT="${OSINT_API_PORT:-8010}"
OSINT_MODEL_PATH="${OSINT_MODEL_PATH:-$OSINT_DIR/models/final_model}"
OSINT_BASE_MODEL="${OSINT_BASE_MODEL:-mistralai/Mistral-7B-v0.1}"
OSINT_USE_LORA="${OSINT_USE_LORA:-false}"

OSINT_DB_HOST="${OSINT_DB_HOST:-10.0.88.11}"
OSINT_DB_PORT="${OSINT_DB_PORT:-5432}"
OSINT_DB_NAME="${OSINT_DB_NAME:-vuln_db}"
OSINT_DB_USER="${OSINT_DB_USER:-admin}"
OSINT_DB_PASSWORD="${OSINT_DB_PASSWORD:-123}"

ensure_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Запустите скрипт от root: sudo $0"
    exit 1
  fi
}

ensure_repo() {
  if [[ ! -d "${OSINT_DIR}" ]]; then
    echo "Не найден каталог ${OSINT_DIR}"
    echo "Проверьте APP_ROOT/OSINT_DIR или клонируйте репозиторий."
    exit 1
  fi
}

setup_python() {
  apt update -y
  apt install -y python3 python3-venv python3-pip
  if [[ ! -d "${VENV_DIR}" ]]; then
    python3 -m venv "${VENV_DIR}"
  fi
  "${VENV_DIR}/bin/pip" install --upgrade pip
  "${VENV_DIR}/bin/pip" install -r "${OSINT_DIR}/requirements.txt"
}

write_env() {
  cat <<EOF > "${ENV_FILE}"
OSINT_API_HOST=${OSINT_API_HOST}
OSINT_API_PORT=${OSINT_API_PORT}
OSINT_MODEL_PATH=${OSINT_MODEL_PATH}
OSINT_BASE_MODEL=${OSINT_BASE_MODEL}
OSINT_USE_LORA=${OSINT_USE_LORA}
OSINT_DB_HOST=${OSINT_DB_HOST}
OSINT_DB_PORT=${OSINT_DB_PORT}
OSINT_DB_NAME=${OSINT_DB_NAME}
OSINT_DB_USER=${OSINT_DB_USER}
OSINT_DB_PASSWORD=${OSINT_DB_PASSWORD}
EOF
  chmod 600 "${ENV_FILE}"
  chown root:root "${ENV_FILE}"
}

install_service() {
  cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=OSINT Neural Network API
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${OSINT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python ${OSINT_DIR}/src/api_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
}

health_check() {
  local url="http://127.0.0.1:${OSINT_API_PORT}/health"
  echo "Проверка доступности: ${url}"
  curl -sSf "${url}" >/dev/null
}

main() {
  ensure_root
  ensure_repo
  setup_python
  write_env
  install_service
  health_check
  echo "✅ Деплой завершен. Сервис: ${SERVICE_NAME}"
  echo "ℹ️ Проверьте статус: systemctl status ${SERVICE_NAME}"
}

main "$@"
