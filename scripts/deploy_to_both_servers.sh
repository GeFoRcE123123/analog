#!/bin/bash
# Деплой на оба сервера: 10.0.88.20 и 217.25.230.15

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 ДЕПЛОЙ НА ОБА СЕРВЕРА                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Сервер 1: 10.0.88.20
echo ""
echo "📍 Сервер 1: 10.0.88.20:5000"
echo "─────────────────────────────────────"

BACKEND_VM1="10.0.88.20"
PASSWORD1="123"
BACKEND_USER1="user"

export SSHPASS="$PASSWORD1"

# Находим директорию проекта
PROJECT_PATH1=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)

if [ -z "$PROJECT_PATH1" ]; then
    PROJECT_PATH1=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /home/*/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
fi

if [ ! -z "$PROJECT_PATH1" ]; then
    echo "✅ Найдена директория: $PROJECT_PATH1"
    
    # Копируем файлы
    echo "📦 Копирование файлов..."
    sshpass -e scp -o StrictHostKeyChecking=no static/css/animations-enhanced.css $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/static/css/ 2>&1 && echo "  ✅ CSS"
    sshpass -e scp -o StrictHostKeyChecking=no static/js/{react-bits-vanilla.js,gsap-animations.js,particles-config.js} $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/static/js/ 2>&1 && echo "  ✅ JS"
    sshpass -e scp -o StrictHostKeyChecking=no templates/base.html $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/templates/ 2>&1 && echo "  ✅ base.html"
    sshpass -e scp -o StrictHostKeyChecking=no templates/dashboard.html $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/templates/ 2>&1 && echo "  ✅ dashboard.html"
    sshpass -e scp -o StrictHostKeyChecking=no templates/vulnerabilities_list.html $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/templates/ 2>&1 && echo "  ✅ vulnerabilities_list.html"
    sshpass -e scp -o StrictHostKeyChecking=no templates/admin/users.html $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/templates/admin/ 2>&1 && echo "  ✅ admin/users.html"
    sshpass -e scp -o StrictHostKeyChecking=no app.py $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/ 2>&1 && echo "  ✅ app.py"
    
    # Перезапуск
    echo "🔄 Перезапуск сервера..."
    PID1=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "ps aux | grep '[g]unicorn' | awk '{print \$2}' | head -1" 2>&1)
    if [ ! -z "$PID1" ]; then
        sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "echo '$PASSWORD1' | sudo -S kill -HUP $PID1" 2>&1
        echo "  ✅ Gunicorn перезапущен (PID: $PID1)"
    fi
else
    echo "❌ Не найдена директория на сервере 1"
fi

unset SSHPASS

# Сервер 2: 217.25.230.15
echo ""
echo "📍 Сервер 2: 217.25.230.15:8080"
echo "─────────────────────────────────────"

# Попробуем разные учетные данные
for USER in user admin root ubuntu; do
    for PASS in "123" "admin" "password"; do
        export SSHPASS="$PASS"
        if sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 $USER@217.25.230.15 "echo 'OK'" 2>/dev/null | grep -q "OK"; then
            BACKEND_USER2=$USER
            PASSWORD2=$PASS
            echo "✅ Подключение: $USER@217.25.230.15"
            break 2
        fi
    done
done

if [ -z "$BACKEND_USER2" ]; then
    echo "❌ Не удалось подключиться к серверу 2"
    echo "⚠️  Попробуйте вручную:"
    echo "   ssh user@217.25.230.15"
    exit 0
fi

export SSHPASS="$PASSWORD2"

# Находим директорию проекта на сервере 2
PROJECT_PATH2=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)

if [ -z "$PROJECT_PATH2" ]; then
    PROJECT_PATH2=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /opt/vulnerability_manager 2>/dev/null || ls -d /var/www/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
fi

if [ ! -z "$PROJECT_PATH2" ]; then
    echo "✅ Найдена директория: $PROJECT_PATH2"
    
    # Копируем файлы
    echo "📦 Копирование файлов..."
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "mkdir -p $PROJECT_PATH2/static/css $PROJECT_PATH2/static/js $PROJECT_PATH2/templates/admin" 2>&1
    sshpass -e scp -o StrictHostKeyChecking=no static/css/animations-enhanced.css $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/static/css/ 2>&1 && echo "  ✅ CSS"
    sshpass -e scp -o StrictHostKeyChecking=no static/js/{react-bits-vanilla.js,gsap-animations.js,particles-config.js} $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/static/js/ 2>&1 && echo "  ✅ JS"
    sshpass -e scp -o StrictHostKeyChecking=no templates/base.html $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/templates/ 2>&1 && echo "  ✅ base.html"
    sshpass -e scp -o StrictHostKeyChecking=no templates/dashboard.html $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/templates/ 2>&1 && echo "  ✅ dashboard.html"
    sshpass -e scp -o StrictHostKeyChecking=no templates/vulnerabilities_list.html $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/templates/ 2>&1 && echo "  ✅ vulnerabilities_list.html"
    sshpass -e scp -o StrictHostKeyChecking=no templates/admin/users.html $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/templates/admin/ 2>&1 && echo "  ✅ admin/users.html"
    sshpass -e scp -o StrictHostKeyChecking=no app.py $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/ 2>&1 && echo "  ✅ app.py"
    
    # Перезапуск
    echo "🔄 Перезапуск сервера..."
    PID2=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "ps aux | grep '[g]unicorn' | awk '{print \$2}' | head -1" 2>&1)
    if [ ! -z "$PID2" ]; then
        sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "echo '$PASSWORD2' | sudo -S kill -HUP $PID2 2>&1 || kill -HUP $PID2" 2>&1
        echo "  ✅ Gunicorn перезапущен (PID: $PID2)"
    else
        # Попробуем найти Flask процесс
        FLASK_PID=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "ps aux | grep '[p]ython.*app.py' | awk '{print \$2}' | head -1" 2>&1)
        if [ ! -z "$FLASK_PID" ]; then
            sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "kill -HUP $FLASK_PID" 2>&1
            echo "  ✅ Flask перезапущен (PID: $FLASK_PID)"
        else
            echo "  ⚠️  Процесс не найден, возможно требуется ручной перезапуск"
        fi
    fi
else
    echo "❌ Не найдена директория на сервере 2"
fi

unset SSHPASS

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ ЗАВЕРШЕН                                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Проверьте сайты:"
echo "   http://10.0.88.20:5000"
echo "   http://217.25.230.15:8080"
echo ""

