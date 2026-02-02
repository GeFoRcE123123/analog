#!/bin/bash
# Деплой исправлений дашборда на внешний сервер 217.25.230.15

EXTERNAL_SERVER="217.25.230.15"
PASSWORD="123"
USER="user"

export SSHPASS="$PASSWORD"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔧 ДЕПЛОЙ ИСПРАВЛЕНИЙ ДАШБОРДА (ВНЕШНИЙ СЕРВЕР)             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "Сервер: $USER@$EXTERNAL_SERVER:8080"
echo ""

# Находим директорию проекта
echo "1️⃣  Поиск директории проекта..."
PROJECT_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $USER@$EXTERNAL_SERVER "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)

if [ -z "$PROJECT_PATH" ]; then
    PROJECT_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $USER@$EXTERNAL_SERVER "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /opt/vulnerability_manager 2>/dev/null || ls -d /var/www/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
fi

if [ -z "$PROJECT_PATH" ]; then
    echo "❌ Не удалось найти директорию проекта"
    exit 1
fi

echo "   ✅ Найдена директория: $PROJECT_PATH"

echo ""
echo "2️⃣  Копирование обновленных файлов..."

# Создаем директории если нужно
sshpass -e ssh -o StrictHostKeyChecking=no $USER@$EXTERNAL_SERVER "mkdir -p $PROJECT_PATH/static/css $PROJECT_PATH/templates" 2>&1

# Копируем app.py (с фильтром format_number)
sshpass -e scp -o StrictHostKeyChecking=no services/backend/app.py $USER@$EXTERNAL_SERVER:$PROJECT_PATH/app.py 2>&1 && echo "   ✅ app.py"

# Копируем dashboard.html
sshpass -e scp -o StrictHostKeyChecking=no templates/dashboard.html $USER@$EXTERNAL_SERVER:$PROJECT_PATH/templates/dashboard.html 2>&1 && echo "   ✅ templates/dashboard.html"

# Копируем main.css
sshpass -e scp -o StrictHostKeyChecking=no static/css/main.css $USER@$EXTERNAL_SERVER:$PROJECT_PATH/static/css/main.css 2>&1 && echo "   ✅ static/css/main.css"

echo ""
echo "3️⃣  Перезапуск сервиса..."

# Пробуем найти и перезапустить gunicorn
PID=$(sshpass -e ssh -o StrictHostKeyChecking=no $USER@$EXTERNAL_SERVER "ps aux | grep '[g]unicorn\|[p]ython.*app.py' | awk '{print \$2}' | head -1" 2>&1)

if [ ! -z "$PID" ]; then
    echo "   Найден процесс (PID: $PID), отправляем HUP сигнал..."
    sshpass -e ssh -o StrictHostKeyChecking=no $USER@$EXTERNAL_SERVER "echo '$PASSWORD' | sudo -S kill -HUP $PID 2>&1 || kill -HUP $PID 2>&1" && echo "   ✅ Процесс перезагружен"
else
    echo "   ⚠️  Процесс не найден. Возможно, требуется ручной перезапуск."
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ИСПРАВЛЕНИЯ ЗАДЕПЛОЕНЫ НА ВНЕШНИЙ СЕРВЕР!                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Откройте в браузере: http://$EXTERNAL_SERVER:8080/dashboard"
echo ""

unset SSHPASS
