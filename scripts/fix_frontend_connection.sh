#!/bin/bash
# Исправление подключения фронтенда к бэкенду

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
PASSWORD="123"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔧 ИСПРАВЛЕНИЕ ПОДКЛЮЧЕНИЯ ФРОНТЕНДА                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  Проверка конфигурации CORS..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd /home/user/vulnerability_manager
    python3 << 'PYTHON'
from config import Config
print('FRONTEND_URL:', getattr(Config, 'FRONTEND_URL', 'N/A'))
print('BACKEND_URL:', getattr(Config, 'BACKEND_URL', 'N/A'))
PYTHON
" 2>&1

echo ""
echo "2️⃣  Проверка работы API с CORS..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    curl -s -H 'Origin: http://10.0.88.10' -H 'Access-Control-Request-Method: GET' \
         -X OPTIONS http://localhost:5000/api/vulnerabilities 2>&1 | head -10
" 2>&1

echo ""
echo "3️⃣  Проверка ответа API..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    curl -s http://localhost:5000/api/vulnerabilities?page=1&per_page=3 2>&1 | \
    python3 -c 'import sys, json; d=json.load(sys.stdin); print(\"Success:\", d.get(\"success\")); print(\"Total:\", d.get(\"total_count\"))' 2>/dev/null
" 2>&1

echo ""
echo "4️⃣  Проверка доступности с фронтенда..."
sshpass -p "123" ssh -o StrictHostKeyChecking=no user@10.0.88.10 "curl -s http://10.0.88.20:5000/api/vulnerabilities?page=1&per_page=1 2>&1 | head -5" 2>&1 || echo "⚠️  Фронтенд VM недоступна или нет доступа"

echo ""
echo "✅ Диагностика завершена"

unset SSHPASS
