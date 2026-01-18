#!/bin/bash
# Исправление структуры и деплой

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
PASSWORD="123"
PROJECT_PATH="/home/user/vulnerability_manager"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 ДЕПЛОЙ ИНТЕГРАЦИИ ML ПЛАТФОРМЫ                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  Исправление структуры (удаление файла services, создание директории)..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd $PROJECT_PATH
    if [ -f services ]; then
        mv services services.backup
        echo 'Файл services переименован в services.backup'
    fi
    mkdir -p services/backend templates/ai
    echo 'Директории созданы'
" 2>&1

echo ""
echo "2️⃣  Копирование файлов..."
sshpass -e scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/ 2>&1 && echo "   ✅ ml_platform_client.py"

# Обновляем app.py (добавляем импорт ml_platform_client)
echo ""
echo "3️⃣  Обновление app.py..."
sshpass -e scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/backend/app.py.new 2>&1
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd $PROJECT_PATH/backend
    if [ -f app.py.new ]; then
        cp app.py app.py.backup
        mv app.py.new app.py
        echo 'app.py обновлен (старая версия в app.py.backup)'
    fi
" 2>&1

echo ""
echo "4️⃣  Установка зависимостей..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd $PROJECT_PATH
    python3 -m pip install paramiko --break-system-packages 2>/dev/null || \
    python3 -m pip install --user paramiko 2>/dev/null || \
    pip3 install paramiko --break-system-packages 2>/dev/null || \
    echo '⚠️  pip не найден, установите paramiko вручную'
" 2>&1

echo ""
echo "5️⃣  Проверка файлов..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    echo '=== Структура проекта ==='
    ls -lh $PROJECT_PATH/services/*.py 2>/dev/null
    echo ''
    echo '=== Размер app.py ==='
    ls -lh $PROJECT_PATH/backend/app.py
    echo ''
    echo '=== Шаблоны ==='
    ls -lh $PROJECT_PATH/templates/ai/*.html 2>/dev/null | wc -l
    echo 'HTML файлов скопировано'
" 2>&1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ ЗАВЕРШЕН!                                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Следующие шаги:"
echo "   1. Перезапустите backend сервис"
echo "   2. Проверьте работу: http://10.0.88.10"
echo "   3. Перейдите в раздел 'ИИ-Анализ'"

unset SSHPASS
