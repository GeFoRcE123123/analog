#!/bin/bash
# Автоматический деплой с определением пути

BACKEND_VM="10.0.88.20"
BACKEND_USER="admin"

echo "🚀 Автоматический деплой интеграции ML платформы"
echo "================================================"

# Определение пути к проекту
echo "🔍 Определение пути к проекту..."
PROJECT_PATH=$(ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    # Попробуем найти через systemd
    sudo systemctl cat vulnerability-manager-backend 2>/dev/null | grep -i 'workingdirectory\|execstart' | grep -oP '(?<=-C\s|cd\s|WorkingDirectory=)[^\s]+' | head -1 || 
    # Попробуем стандартные пути
    for path in /opt/vulnerability_manager /home/admin/vulnerability_manager /var/www/vulnerability_manager; do
        if [ -d \"\$path\" ] && [ -f \"\$path/services/backend/app.py\" ]; then
            echo \"\$path\"
            break
        fi
    done ||
    # Если не нашли, используем первый существующий
    for path in /opt/vulnerability_manager /home/admin/vulnerability_manager; do
        if [ -d \"\$path\" ]; then
            echo \"\$path\"
            break
        fi
    done
" 2>/dev/null | head -1)

if [ -z "$PROJECT_PATH" ]; then
    PROJECT_PATH="/opt/vulnerability_manager"
    echo "⚠️  Путь не найден, используем по умолчанию: $PROJECT_PATH"
else
    echo "✅ Найден путь: $PROJECT_PATH"
fi

echo ""
echo "1️⃣  Остановка сервиса..."
ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "sudo systemctl stop vulnerability-manager-backend" 2>&1

echo ""
echo "2️⃣  Копирование файлов..."
# Создаем директории
ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/services $PROJECT_PATH/services/backend $PROJECT_PATH/templates/ai" 2>&1

# Копируем файлы
scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/ 2>&1
scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/backend/ 2>&1
scp -o StrictHostKeyChecking=no requirements.txt $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1
scp -o StrictHostKeyChecking=no templates/ai/*.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ai/ 2>&1

echo ""
echo "3️⃣  Установка зависимостей..."
ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && pip3 install paramiko --break-system-packages" 2>&1

echo ""
echo "4️⃣  Запуск сервиса..."
ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "sudo systemctl start vulnerability-manager-backend" 2>&1

echo ""
echo "5️⃣  Проверка статуса..."
ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "sudo systemctl status vulnerability-manager-backend --no-pager -l" 2>&1 | head -20

echo ""
echo "✅ Деплой завершен!"
