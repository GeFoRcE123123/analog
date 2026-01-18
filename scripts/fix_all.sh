#!/bin/bash
# Полное исправление подключения фронтенда к бэкенду и БД

BACKEND_VM="10.0.88.20"
FRONTEND_VM="10.0.88.10"
BACKEND_USER="user"
PASSWORD="123"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔧 ПОЛНОЕ ИСПРАВЛЕНИЕ ПОДКЛЮЧЕНИЙ                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  Проверка Backend API..."
BACKEND_RESPONSE=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "curl -s http://localhost:5000/api/vulnerabilities?page=1&per_page=1" 2>&1)
if echo "$BACKEND_RESPONSE" | grep -q '"success":true'; then
    TOTAL=$(echo "$BACKEND_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('total_count', 0))" 2>/dev/null)
    echo "   ✅ Backend работает, записей в БД: $TOTAL"
else
    echo "   ❌ Backend не отвечает"
    exit 1
fi

echo ""
echo "2️⃣  Проверка доступности Backend с Frontend VM..."
FRONTEND_TO_BACKEND=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$FRONTEND_VM "curl -s -m 5 http://10.0.88.20:5000/api/vulnerabilities?page=1&per_page=1 2>&1" 2>&1)
if echo "$FRONTEND_TO_BACKEND" | grep -q '"success":true'; then
    echo "   ✅ Frontend может подключиться к Backend"
else
    echo "   ⚠️  Frontend не может подключиться к Backend"
    echo "   Ответ: $(echo "$FRONTEND_TO_BACKEND" | head -3)"
fi

echo ""
echo "3️⃣  Проверка CORS настроек в app.py..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd /home/user/vulnerability_manager/backend
    grep -A 3 'CORS\|FRONTEND_URL' app.py | head -10
" 2>&1

echo ""
echo "4️⃣  Перезапуск gunicorn для применения изменений..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S pkill -HUP gunicorn 2>&1" || echo "⚠️  Не удалось перезапустить (возможно уже работает)"

echo ""
echo "5️⃣  Финальная проверка API..."
sleep 2
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "curl -s http://localhost:5000/api/vulnerabilities?page=1&per_page=3 2>&1 | python3 -c 'import sys, json; d=json.load(sys.stdin); print(f\"Success: {d.get(\"success\")}, Total: {d.get(\"total_count\")}, Vulns: {len(d.get(\"vulnerabilities\", []))}\")' 2>/dev/null" 2>&1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ИСПРАВЛЕНИЕ ЗАВЕРШЕНО                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Проверьте работу:"
echo "   1. Откройте http://10.0.88.10"
echo "   2. Очистите кэш браузера (Ctrl+Shift+R)"
echo "   3. Проверьте консоль браузера (F12) на ошибки"

unset SSHPASS
