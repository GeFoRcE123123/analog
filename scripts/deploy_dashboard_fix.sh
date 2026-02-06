#!/bin/bash
# Деплой исправлений дашборда

BACKEND_VM="10.0.88.20"
PASSWORD="123"
BACKEND_USER="user"

export SSHPASS="$PASSWORD"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔧 ДЕПЛОЙ ИСПРАВЛЕНИЙ ДАШБОРДА                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "Пользователь: $BACKEND_USER@$BACKEND_VM"
echo ""

# Находим директорию проекта на сервере
echo "1️⃣  Поиск директории проекта на сервере..."
PROJECT_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)

if [ -z "$PROJECT_PATH" ]; then
    PROJECT_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /home/*/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
fi

if [ -z "$PROJECT_PATH" ]; then
    echo "❌ Не удалось найти директорию проекта на сервере"
    exit 1
fi

echo "   ✅ Найдена директория: $PROJECT_PATH"

echo ""
echo "2️⃣  Копирование обновленных файлов..."

# Копируем app.py (с фильтром format_number)
sshpass -e scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/backend/ 2>&1 && echo "   ✅ services/backend/app.py"

# Копируем dashboard.html
sshpass -e scp -o StrictHostKeyChecking=no templates/dashboard.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ 2>&1 && echo "   ✅ templates/dashboard.html"

# Копируем main.css
sshpass -e scp -o StrictHostKeyChecking=no static/css/main.css $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/static/css/ 2>&1 && echo "   ✅ static/css/main.css"

echo ""
echo "3️⃣  Перезапуск сервиса..."

# Проверяем, есть ли systemd сервис
SERVICE_EXISTS=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "systemctl list-unit-files | grep vulnerability-manager | wc -l" 2>&1)

if [ "$SERVICE_EXISTS" -gt "0" ]; then
    echo "   Найден systemd сервис, перезапускаем..."
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S systemctl restart vulnerability-manager-backend 2>&1 || sudo -S systemctl restart vulnerability-manager 2>&1" && echo "   ✅ Сервис перезапущен"
else
    # Пробуем перезапустить через gunicorn HUP
    PID=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ps aux | grep '[g]unicorn\|[p]ython.*app.py' | awk '{print \$2}' | head -1" 2>&1)
    if [ ! -z "$PID" ]; then
        echo "   Найден процесс (PID: $PID), отправляем HUP сигнал..."
        sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "kill -HUP $PID 2>&1" && echo "   ✅ Процесс перезагружен"
    else
        echo "   ⚠️  Процесс не найден. Flask может работать в screen/tmux."
        echo "   Проверьте вручную: ps aux | grep app.py"
    fi
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ИСПРАВЛЕНИЯ ДАШБОРДА ЗАДЕПЛОЕНЫ!                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Изменения:"
echo "   - Добавлен фильтр форматирования чисел (format_number)"
echo "   - Улучшено отображение статистики с разделителями тысяч"
echo "   - Добавлен прогресс-бар для завершенных уязвимостей"
echo "   - Улучшены стили карточек статистики"
echo ""
echo "🌐 Откройте в браузере: http://$BACKEND_VM:5000/dashboard"
echo ""

unset SSHPASS
