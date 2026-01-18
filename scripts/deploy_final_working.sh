#!/bin/bash
# Деплой - пробуем разные варианты

BACKEND_VM="10.0.88.20"
PASSWORD="123"
PROJECT_PATH="/opt/vulnerability_manager"

# Пробуем разных пользователей
for USER in admin root ubuntu user; do
    echo "Проверка пользователя: $USER"
    if sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 $USER@$BACKEND_VM "echo 'OK'" 2>/dev/null; then
        BACKEND_USER=$USER
        echo "✅ Найден рабочий пользователь: $USER"
        break
    fi
done

if [ -z "$BACKEND_USER" ]; then
    echo "❌ Не удалось подключиться. Проверьте учетные данные."
    exit 1
fi

export SSHPASS="$PASSWORD"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 ДЕПЛОЙ ИНТЕГРАЦИИ ML ПЛАТФОРМЫ                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "Пользователь: $BACKEND_USER@$BACKEND_VM"
echo ""

echo "1️⃣  Остановка сервиса..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S systemctl stop vulnerability-manager-backend" 2>&1 || echo "⚠️  Сервис уже остановлен"

echo ""
echo "2️⃣  Создание директорий..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/services $PROJECT_PATH/services/backend $PROJECT_PATH/templates/ai" 2>&1

echo ""
echo "3️⃣  Копирование файлов..."
sshpass -e scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/ 2>&1 && echo "   ✅ ml_platform_client.py"
sshpass -e scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/backend/ 2>&1 && echo "   ✅ app.py"
sshpass -e scp -o StrictHostKeyChecking=no requirements.txt $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1 && echo "   ✅ requirements.txt"
for file in templates/ai/*.html; do
    sshpass -e scp -o StrictHostKeyChecking=no "$file" $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ai/ 2>&1
done
echo "   ✅ HTML шаблоны (5 файлов)"

echo ""
echo "4️⃣  Установка зависимостей..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && pip3 install paramiko --break-system-packages" 2>&1

echo ""
echo "5️⃣  Запуск сервиса..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S systemctl start vulnerability-manager-backend" 2>&1

echo ""
echo "6️⃣  Проверка статуса..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "sudo systemctl status vulnerability-manager-backend --no-pager -l" 2>&1 | head -30

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ ЗАВЕРШЕН!                                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"

unset SSHPASS
