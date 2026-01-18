#!/bin/bash
# Финальный деплой с правильным пользователем и путем

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
PASSWORD="123"
PROJECT_PATH="/home/user/vulnerability_manager"  # Попробуем домашнюю директорию

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 ДЕПЛОЙ ИНТЕГРАЦИИ ML ПЛАТФОРМЫ                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "Пользователь: $BACKEND_USER@$BACKEND_VM"
echo "Путь: $PROJECT_PATH"
echo ""

# Проверка и создание директории
echo "🔍 Проверка пути к проекту..."
ACTUAL_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    for path in /home/user/vulnerability_manager ~/vulnerability_manager /opt/vulnerability_manager; do
        if [ -d \"\$path\" ] && [ -f \"\$path/services/backend/app.py\" ]; then
            echo \"\$path\"
            break
        fi
    done
" 2>/dev/null | head -1)

if [ -n "$ACTUAL_PATH" ]; then
    PROJECT_PATH="$ACTUAL_PATH"
    echo "✅ Найден путь: $PROJECT_PATH"
else
    echo "⚠️  Путь не найден, создаем: $PROJECT_PATH"
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/services/backend $PROJECT_PATH/templates/ai" 2>&1
fi

echo ""
echo "1️⃣  Остановка сервиса (если есть)..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S systemctl stop vulnerability-manager-backend 2>/dev/null || echo 'Сервис не найден или уже остановлен'" 2>&1

echo ""
echo "2️⃣  Создание директорий..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/services $PROJECT_PATH/services/backend $PROJECT_PATH/templates/ai" 2>&1

echo ""
echo "3️⃣  Копирование файлов..."
sshpass -e scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/ 2>&1 && echo "   ✅ ml_platform_client.py"
sshpass -e scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/backend/ 2>&1 && echo "   ✅ app.py"
sshpass -e scp -o StrictHostKeyChecking=no requirements.txt $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1 && echo "   ✅ requirements.txt"
for file in templates/ai/*.html; do
    [ -f "$file" ] && sshpass -e scp -o StrictHostKeyChecking=no "$file" $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ai/ 2>&1
done
echo "   ✅ HTML шаблоны"

echo ""
echo "4️⃣  Установка зависимостей..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && pip3 install paramiko --break-system-packages" 2>&1

echo ""
echo "5️⃣  Запуск сервиса (если есть)..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S systemctl start vulnerability-manager-backend 2>/dev/null || echo 'Сервис не найден, возможно запускается вручную'" 2>&1

echo ""
echo "6️⃣  Проверка файлов..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls -lh $PROJECT_PATH/services/ml_platform_client.py $PROJECT_PATH/services/backend/app.py $PROJECT_PATH/requirements.txt 2>/dev/null | head -5" 2>&1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ ЗАВЕРШЕН!                                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Файлы скопированы в: $PROJECT_PATH"
echo "📋 Проверьте работу через веб-интерфейс: http://10.0.88.10"

unset SSHPASS
