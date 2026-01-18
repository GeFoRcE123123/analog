#!/bin/bash
# Деплой с использованием пароля

BACKEND_VM="10.0.88.20"
BACKEND_USER="admin"
read -sp "Введите пароль для $BACKEND_USER@$BACKEND_VM: " PASSWORD
echo ""

# Установка sshpass если нужно
if ! command -v sshpass &> /dev/null; then
    echo "⚠️  sshpass не установлен. Установите: brew install hudochenkov/sshpass/sshpass"
    echo "Или выполните деплой вручную через ssh"
    exit 1
fi

export SSHPASS="$PASSWORD"

echo "🚀 Начинаю деплой..."
echo ""

# Определение пути
echo "🔍 Определение пути к проекту..."
PROJECT_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    for path in /opt/vulnerability_manager /home/admin/vulnerability_manager /var/www/vulnerability_manager; do
        if [ -d \"\$path\" ] && [ -f \"\$path/services/backend/app.py\" ]; then
            echo \"\$path\"
            break
        fi
    done
" 2>/dev/null | head -1)

if [ -z "$PROJECT_PATH" ]; then
    PROJECT_PATH="/opt/vulnerability_manager"
    echo "⚠️  Используем путь по умолчанию: $PROJECT_PATH"
else
    echo "✅ Найден путь: $PROJECT_PATH"
fi

echo ""
echo "1️⃣  Остановка сервиса..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "sudo systemctl stop vulnerability-manager-backend" 2>&1

echo ""
echo "2️⃣  Копирование файлов..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/services $PROJECT_PATH/services/backend $PROJECT_PATH/templates/ai" 2>&1

sshpass -e scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/ 2>&1
sshpass -e scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/backend/ 2>&1
sshpass -e scp -o StrictHostKeyChecking=no requirements.txt $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1
sshpass -e scp -o StrictHostKeyChecking=no templates/ai/*.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ai/ 2>&1

echo ""
echo "3️⃣  Установка зависимостей..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && pip3 install paramiko --break-system-packages" 2>&1

echo ""
echo "4️⃣  Запуск сервиса..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "sudo systemctl start vulnerability-manager-backend" 2>&1

echo ""
echo "5️⃣  Проверка статуса..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "sudo systemctl status vulnerability-manager-backend --no-pager -l" 2>&1 | head -20

echo ""
echo "✅ Деплой завершен!"
unset SSHPASS
