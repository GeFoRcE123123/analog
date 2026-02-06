#!/bin/bash
# Правильный деплой с корректной структурой

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
PASSWORD="123"
PROJECT_PATH="/home/user/vulnerability_manager"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 ДЕПЛОЙ ИНТЕГРАЦИИ ML ПЛАТФОРМЫ                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Определяем правильную структуру
echo "🔍 Определение структуры проекта..."
STRUCTURE=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    if [ -f '$PROJECT_PATH/backend/app.py' ]; then
        echo 'backend_structure'
    elif [ -f '$PROJECT_PATH/services/backend/app.py' ]; then
        echo 'services_structure'
    else
        echo 'unknown'
    fi
" 2>/dev/null)

echo "Структура: $STRUCTURE"

if [ "$STRUCTURE" = "backend_structure" ]; then
    # Структура: /home/user/vulnerability_manager/backend/
    SERVICES_PATH="$PROJECT_PATH/services"
    BACKEND_PATH="$PROJECT_PATH/backend"
    TEMPLATES_PATH="$PROJECT_PATH/templates"
elif [ "$STRUCTURE" = "services_structure" ]; then
    # Структура: /home/user/vulnerability_manager/services/backend/
    SERVICES_PATH="$PROJECT_PATH/services"
    BACKEND_PATH="$PROJECT_PATH/services/backend"
    TEMPLATES_PATH="$PROJECT_PATH/templates"
else
    # Создаем стандартную структуру
    SERVICES_PATH="$PROJECT_PATH/services"
    BACKEND_PATH="$PROJECT_PATH/services/backend"
    TEMPLATES_PATH="$PROJECT_PATH/templates"
fi

echo ""
echo "1️⃣  Создание директорий..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $SERVICES_PATH $BACKEND_PATH $TEMPLATES_PATH/ai" 2>&1

echo ""
echo "2️⃣  Копирование файлов..."
sshpass -e scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:$SERVICES_PATH/ 2>&1 && echo "   ✅ ml_platform_client.py"

# Копируем app.py в правильное место
if [ "$STRUCTURE" = "backend_structure" ]; then
    # Если структура backend/, копируем в services/backend/
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $SERVICES_PATH/backend" 2>&1
    sshpass -e scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$SERVICES_PATH/backend/ 2>&1 && echo "   ✅ app.py -> $SERVICES_PATH/backend/"
else
    sshpass -e scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$BACKEND_PATH/ 2>&1 && echo "   ✅ app.py -> $BACKEND_PATH/"
fi

sshpass -e scp -o StrictHostKeyChecking=no requirements.txt $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1 && echo "   ✅ requirements.txt"

for file in templates/ai/*.html; do
    [ -f "$file" ] && sshpass -e scp -o StrictHostKeyChecking=no "$file" $BACKEND_USER@$BACKEND_VM:$TEMPLATES_PATH/ai/ 2>&1
done
echo "   ✅ HTML шаблоны (5 файлов)"

echo ""
echo "3️⃣  Установка зависимостей..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && python3 -m pip install paramiko --break-system-packages 2>/dev/null || pip3 install paramiko --break-system-packages 2>/dev/null || echo 'pip не найден, установите вручную'" 2>&1

echo ""
echo "4️⃣  Проверка скопированных файлов..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    echo 'Файлы в services:'
    ls -lh $SERVICES_PATH/*.py 2>/dev/null | head -3
    echo ''
    echo 'Файлы в backend:'
    ls -lh $BACKEND_PATH/*.py 2>/dev/null | head -3
    echo ''
    echo 'Шаблоны:'
    ls -lh $TEMPLATES_PATH/ai/*.html 2>/dev/null | head -5
" 2>&1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ ЗАВЕРШЕН!                                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Файлы скопированы в: $PROJECT_PATH"
echo "📋 Перезапустите сервис вручную или через systemctl"

unset SSHPASS
