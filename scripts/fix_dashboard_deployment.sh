#!/bin/bash
# Полная проверка и исправление деплоя дашборда

BACKEND_VM="10.0.88.20"
PASSWORD="123"
BACKEND_USER="user"

export SSHPASS="$PASSWORD"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔧 ПОЛНАЯ ПРОВЕРКА И ИСПРАВЛЕНИЕ ДЕПЛОЯ ДАШБОРДА            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

PROJECT_PATH="/home/user/vulnerability_manager"

echo "1️⃣  Проверка файлов на сервере..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && ls -lh app.py templates/dashboard.html static/css/main.css 2>&1"

echo ""
echo "2️⃣  Проверка фильтра format_number в app.py..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "grep -n 'format_number' $PROJECT_PATH/app.py | head -3"

echo ""
echo "3️⃣  Проверка использования format_number в шаблоне..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "grep -n 'format_number' $PROJECT_PATH/templates/dashboard.html | head -3"

echo ""
echo "4️⃣  Остановка всех процессов gunicorn..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S pkill -9 gunicorn 2>&1 || pkill -9 gunicorn 2>&1"
sleep 2

echo ""
echo "5️⃣  Запуск gunicorn из правильной директории..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && nohup /usr/local/bin/python3.11 /usr/local/bin/gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 600 --keep-alive 120 --access-logfile - --error-logfile - --chdir $PROJECT_PATH app:app > /tmp/gunicorn.log 2>&1 &"
sleep 3

echo ""
echo "6️⃣  Проверка запущенных процессов..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ps aux | grep '[g]unicorn' | head -2"

echo ""
echo "7️⃣  Проверка доступности сервера..."
sleep 2
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://$BACKEND_VM:5000/dashboard || echo "Сервер не отвечает"

echo ""
echo "8️⃣  Проверка форматирования чисел в ответе..."
curl -s http://$BACKEND_VM:5000/dashboard 2>&1 | grep -oE '[0-9]{1,3} [0-9]{3}' | head -3 || echo "Форматирование не найдено"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ПРОВЕРКА ЗАВЕРШЕНА                                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Откройте в браузере: http://$BACKEND_VM:5000/dashboard"
echo "💡 Если изменения не видны, очистите кэш браузера (Ctrl+Shift+R)"
echo ""

unset SSHPASS
