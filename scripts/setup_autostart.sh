#!/bin/bash
# Скрипт для настройки автозапуска сервисов на всех VM
# Использование: ./setup_autostart.sh

set -e

SSH_PASS='123'
SSH_USER='user'

FRONTEND_IP='10.0.88.10'
BACKEND_IP='10.0.88.20'
DATABASE_IP='10.0.88.11'
PARSERS_IP='10.0.88.23'

echo "🔧 Настройка автозапуска сервисов"
echo "================================================"
echo ""

# Функция для установки systemd сервиса
setup_service() {
    local ip=$1
    local service_name=$2
    local service_file=$3
    local description=$4
    
    echo "📡 Настройка $description на ${ip}..."
    
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "${SSH_USER}@${ip}" << ENDSSH
        # Копируем service файл
        sudo mkdir -p /etc/systemd/system
        sudo tee /etc/systemd/system/${service_name}.service > /dev/null << 'SERVICEFILE'
$(cat "$service_file")
SERVICEFILE
        
        # Перезагружаем systemd
        sudo systemctl daemon-reload
        
        # Включаем автозапуск
        sudo systemctl enable ${service_name}.service
        
        # Запускаем сервис
        sudo systemctl start ${service_name}.service
        
        # Проверяем статус
        sudo systemctl status ${service_name}.service --no-pager -l || true
ENDSSH
    
    echo "✅ $description настроен"
    echo ""
}

# Database VM
echo "📋 Настройка Database VM (${DATABASE_IP})"
setup_service "$DATABASE_IP" "vulnerability-db" \
    "services/database/vulnerability-db.service" \
    "Database Service"

# Backend VM
echo "📋 Настройка Backend VM (${BACKEND_IP})"
setup_service "$BACKEND_IP" "vulnerability-backend" \
    "services/backend/vulnerability-backend.service" \
    "Backend Service"

# Frontend VM
echo "📋 Настройка Frontend VM (${FRONTEND_IP})"
setup_service "$FRONTEND_IP" "vulnerability-frontend" \
    "services/frontend/vulnerability-frontend.service" \
    "Frontend Service"

# Parsers VM (если доступна)
if ping -c 1 -W 2 "$PARSERS_IP" > /dev/null 2>&1; then
    echo "📋 Настройка Parsers VM (${PARSERS_IP})"
    setup_service "$PARSERS_IP" "vulnerability-parsers" \
        "services/parsers/vulnerability-parsers.service" \
        "Parsers Service"
fi

echo "✅ Автозапуск настроен на всех VM!"
echo ""
echo "📋 Проверка статуса сервисов:"
echo "   ssh ${SSH_USER}@${DATABASE_IP} 'sudo systemctl status vulnerability-db'"
echo "   ssh ${SSH_USER}@${BACKEND_IP} 'sudo systemctl status vulnerability-backend'"
echo "   ssh ${SSH_USER}@${FRONTEND_IP} 'sudo systemctl status vulnerability-frontend'"
echo ""

