#!/bin/bash
# Автоматический деплой интеграции ML платформы

set -e

BACKEND_VM="10.0.88.20"
BACKEND_USER="${1:-admin}"  # Первый аргумент - пользователь, по умолчанию admin
PROJECT_PATH="${2:-/opt/vulnerability_manager}"  # Второй аргумент - путь, по умолчанию /opt/vulnerability_manager

echo "🚀 Деплой интеграции ML платформы"
echo "=================================="
echo "Backend VM: $BACKEND_VM"
echo "User: $BACKEND_USER"
echo "Project Path: $PROJECT_PATH"
echo ""

# Проверка доступности
echo "📡 Проверка доступности..."
if ! ping -c 1 -W 2 $BACKEND_VM > /dev/null 2>&1; then
    echo "❌ Backend VM недоступна"
    exit 1
fi
echo "✅ Backend VM доступна"
echo ""

# Файлы для копирования
echo "📦 Подготовка файлов для копирования..."
FILES=(
    "services/ml_platform_client.py"
    "services/backend/app.py"
    "requirements.txt"
    "templates/ai/dashboard.html"
    "templates/ai/statistics.html"
    "templates/ai/training.html"
    "templates/ai/monitoring.html"
    "templates/ai/passports.html"
)

# Проверка наличия файлов
for file in "${FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "❌ Файл не найден: $file"
        exit 1
    fi
done
echo "✅ Все файлы найдены"
echo ""

# Выполнение команд на Backend VM
echo "🔧 Выполнение команд на Backend VM..."
echo ""

echo "1️⃣  Остановка сервиса..."
ssh $BACKEND_USER@$BACKEND_VM "sudo systemctl stop vulnerability-manager-backend" || {
    echo "⚠️  Не удалось остановить сервис (возможно, уже остановлен)"
}

echo ""
echo "2️⃣  Копирование файлов..."
for file in "${FILES[@]}"; do
    echo "   Копирование: $file"
    ssh $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/$(dirname $file)"
    scp "$file" "$BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/$file"
done

echo ""
echo "3️⃣  Установка зависимостей..."
ssh $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && pip3 install paramiko --break-system-packages"

echo ""
echo "4️⃣  Запуск сервиса..."
ssh $BACKEND_USER@$BACKEND_VM "sudo systemctl start vulnerability-manager-backend"

echo ""
echo "5️⃣  Проверка статуса..."
ssh $BACKEND_USER@$BACKEND_VM "sudo systemctl status vulnerability-manager-backend --no-pager"

echo ""
echo "✅ Деплой завершен!"
echo ""
echo "📋 Проверка:"
echo "   1. Откройте http://10.0.88.10"
echo "   2. Перейдите в раздел 'ИИ-Анализ'"
echo "   3. Очистите кэш браузера (Ctrl+Shift+R)"
echo "   4. Проверьте статус подключения к ML платформе"
