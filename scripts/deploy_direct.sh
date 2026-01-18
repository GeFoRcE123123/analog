#!/bin/bash
# Прямой деплой с паролем через переменную окружения

BACKEND_VM="10.0.88.20"
BACKEND_USER="admin"
PASSWORD="${DEPLOY_PASSWORD:-admin}"  # Используем переменную или admin по умолчанию
PROJECT_PATH="/opt/vulnerability_manager"

export SSHPASS="$PASSWORD"

echo "🚀 Деплой интеграции ML платформы"
echo "=================================="
echo ""

echo "1️⃣  Остановка сервиса..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S systemctl stop vulnerability-manager-backend" 2>&1

echo ""
echo "2️⃣  Создание директорий..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/services $PROJECT_PATH/services/backend $PROJECT_PATH/templates/ai" 2>&1

echo ""
echo "3️⃣  Копирование файлов..."
sshpass -e scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/ 2>&1 && echo "✅ ml_platform_client.py скопирован"
sshpass -e scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/backend/ 2>&1 && echo "✅ app.py скопирован"
sshpass -e scp -o StrictHostKeyChecking=no requirements.txt $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1 && echo "✅ requirements.txt скопирован"
sshpass -e scp -o StrictHostKeyChecking=no templates/ai/*.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ai/ 2>&1 && echo "✅ HTML шаблоны скопированы"

echo ""
echo "4️⃣  Установка зависимостей..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && pip3 install paramiko --break-system-packages" 2>&1

echo ""
echo "5️⃣  Запуск сервиса..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S systemctl start vulnerability-manager-backend" 2>&1

echo ""
echo "6️⃣  Проверка статуса..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "sudo systemctl status vulnerability-manager-backend --no-pager -l" 2>&1 | head -25

echo ""
echo "✅ Деплой завершен!"
unset SSHPASS
