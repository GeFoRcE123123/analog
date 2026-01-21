#!/bin/bash
# 🐳 Правильный деплой в Docker контейнер vulnerability-backend на 10.0.88.20

SERVER="10.0.88.20"
PASSWORD="123"
USER="user"
CONTAINER="vulnerability-backend"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🐳 ДЕПЛОЙ В DOCKER КОНТЕЙНЕР                                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "Сервер: $USER@$SERVER"
echo "Контейнер: $CONTAINER"
echo ""

# Проверка что мы в правильной директории
if [ ! -f "app.py" ] || [ ! -d "templates" ]; then
    echo "❌ Ошибка: Запустите скрипт из корня проекта vulnerability_manager"
    exit 1
fi

echo "1️⃣  Копирование файлов на сервер в /tmp..."
sshpass -e scp -o StrictHostKeyChecking=no templates/dashboard.html $USER@$SERVER:/tmp/ 2>&1 && echo "  ✅ dashboard.html"
sshpass -e scp -o StrictHostKeyChecking=no templates/base.html $USER@$SERVER:/tmp/ 2>&1 && echo "  ✅ base.html"
sshpass -e scp -o StrictHostKeyChecking=no templates/vulnerabilities_list.html $USER@$SERVER:/tmp/ 2>&1 && echo "  ✅ vulnerabilities_list.html"
sshpass -e scp -o StrictHostKeyChecking=no templates/admin/users.html $USER@$SERVER:/tmp/users.html 2>&1 && echo "  ✅ admin/users.html"
sshpass -e scp -o StrictHostKeyChecking=no app.py $USER@$SERVER:/tmp/ 2>&1 && echo "  ✅ app.py"
sshpass -e scp -o StrictHostKeyChecking=no static/css/animations-enhanced.css $USER@$SERVER:/tmp/ 2>&1 && echo "  ✅ animations-enhanced.css"
sshpass -e scp -o StrictHostKeyChecking=no static/js/react-bits-vanilla.js $USER@$SERVER:/tmp/ 2>&1 && echo "  ✅ react-bits-vanilla.js"
sshpass -e scp -o StrictHostKeyChecking=no static/js/gsap-animations.js $USER@$SERVER:/tmp/ 2>&1 && echo "  ✅ gsap-animations.js"
sshpass -e scp -o StrictHostKeyChecking=no static/js/particles-config.js $USER@$SERVER:/tmp/ 2>&1 && echo "  ✅ particles-config.js"
echo ""

echo "2️⃣  Копирование файлов в Docker контейнер..."
sshpass -e ssh -o StrictHostKeyChecking=no $USER@$SERVER << 'ENDSSH'
# Templates
echo '123' | sudo -S docker cp /tmp/dashboard.html vulnerability-backend:/app/templates/dashboard.html && echo "  ✅ dashboard.html → /app/templates/"
echo '123' | sudo -S docker cp /tmp/base.html vulnerability-backend:/app/templates/base.html && echo "  ✅ base.html → /app/templates/"
echo '123' | sudo -S docker cp /tmp/vulnerabilities_list.html vulnerability-backend:/app/templates/vulnerabilities_list.html && echo "  ✅ vulnerabilities_list.html → /app/templates/"
echo '123' | sudo -S docker cp /tmp/users.html vulnerability-backend:/app/templates/admin/users.html && echo "  ✅ users.html → /app/templates/admin/"

# Python
echo '123' | sudo -S docker cp /tmp/app.py vulnerability-backend:/app/app.py && echo "  ✅ app.py → /app/"

# CSS
echo '123' | sudo -S docker cp /tmp/animations-enhanced.css vulnerability-backend:/app/static/css/animations-enhanced.css && echo "  ✅ animations-enhanced.css → /app/static/css/"

# JavaScript
echo '123' | sudo -S docker cp /tmp/react-bits-vanilla.js vulnerability-backend:/app/static/js/react-bits-vanilla.js && echo "  ✅ react-bits-vanilla.js → /app/static/js/"
echo '123' | sudo -S docker cp /tmp/gsap-animations.js vulnerability-backend:/app/static/js/gsap-animations.js && echo "  ✅ gsap-animations.js → /app/static/js/"
echo '123' | sudo -S docker cp /tmp/particles-config.js vulnerability-backend:/app/static/js/particles-config.js && echo "  ✅ particles-config.js → /app/static/js/"

ENDSSH
echo ""

echo "3️⃣  Перезапуск Docker контейнера..."
sshpass -e ssh -o StrictHostKeyChecking=no $USER@$SERVER "echo '123' | sudo -S docker restart $CONTAINER" 2>&1
if [ $? -eq 0 ]; then
    echo "  ✅ Контейнер перезапущен"
else
    echo "  ❌ Ошибка перезапуска контейнера"
    exit 1
fi
echo ""

sleep 3

echo "4️⃣  Проверка статуса контейнера..."
sshpass -e ssh -o StrictHostKeyChecking=no $USER@$SERVER "echo '123' | sudo -S docker ps --filter name=$CONTAINER --format 'table {{.Names}}\t{{.Status}}'" 2>&1
echo ""

echo "5️⃣  Проверка обновленных файлов..."
sshpass -e ssh -o StrictHostKeyChecking=no $USER@$SERVER "echo '123' | sudo -S docker exec $CONTAINER ls -lh /app/templates/dashboard.html /app/static/css/animations-enhanced.css /app/static/js/react-bits-vanilla.js" 2>&1
echo ""

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ ЗАВЕРШЕН                                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Проверьте сайт: http://$SERVER:5000"
echo ""
echo "📝 Что изменилось:"
echo "   - Скрыта плашка 'Управление командой' для User"
echo "   - Скрыта колонка 'Оператор' для User"
echo "   - Скрыты админские кнопки (Редактировать, ИИ-Паспорт, Назначить) для User"
echo "   - Добавлена форма создания пользователей в админке"
echo "   - Добавлены анимации (CSS + JS)"
echo ""
echo "🧪 Тесты:"
echo "   User: должен видеть только 'Просмотр' и 'Теги'"
echo "   Admin: должен видеть все элементы + форму создания пользователей"
echo ""

unset SSHPASS

