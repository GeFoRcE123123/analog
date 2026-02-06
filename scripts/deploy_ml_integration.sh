#!/bin/bash
# Скрипт автоматического деплоя интеграции ML платформы

set -e

BACKEND_VM="10.0.88.20"
BACKEND_USER="${BACKEND_USER:-admin}"  # Измените на вашего пользователя
PROJECT_PATH="${PROJECT_PATH:-/opt/vulnerability_manager}"  # Измените на путь к проекту

echo "🚀 Деплой интеграции ML платформы"
echo "=================================="
echo "Backend VM: $BACKEND_VM"
echo "User: $BACKEND_USER"
echo "Path: $PROJECT_PATH"
echo ""

# Проверка доступности VM
echo "📡 Проверка доступности Backend VM..."
if ! ping -c 1 -W 2 $BACKEND_VM > /dev/null 2>&1; then
    echo "❌ Backend VM недоступна. Проверьте подключение."
    exit 1
fi
echo "✅ Backend VM доступна"
echo ""

# Список файлов для копирования
FILES_TO_COPY=(
    "services/ml_platform_client.py"
    "services/backend/app.py"
    "requirements.txt"
    "templates/ai/dashboard.html"
    "templates/ai/statistics.html"
    "templates/ai/training.html"
    "templates/ai/monitoring.html"
    "templates/ai/passports.html"
)

echo "📦 Файлы для копирования:"
for file in "${FILES_TO_COPY[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✅ $file"
    else
        echo "  ❌ $file (не найден)"
    fi
done
echo ""

echo "⚠️  ВНИМАНИЕ: Этот скрипт требует ручного выполнения команд на Backend VM"
echo ""
echo "Выполните следующие команды на Backend VM ($BACKEND_VM):"
echo ""
echo "1. Остановить сервис:"
echo "   ssh $BACKEND_USER@$BACKEND_VM 'sudo systemctl stop vulnerability-manager-backend'"
echo ""
echo "2. Скопировать файлы (выполните вручную или используйте scp/rsync):"
for file in "${FILES_TO_COPY[@]}"; do
    if [ -f "$file" ]; then
        echo "   scp $file $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/$file"
    fi
done
echo ""
echo "3. Установить зависимости:"
echo "   ssh $BACKEND_USER@$BACKEND_VM 'cd $PROJECT_PATH && pip3 install -r requirements.txt --break-system-packages'"
echo ""
echo "4. Запустить сервис:"
echo "   ssh $BACKEND_USER@$BACKEND_VM 'sudo systemctl start vulnerability-manager-backend'"
echo ""
echo "5. Проверить статус:"
echo "   ssh $BACKEND_USER@$BACKEND_VM 'sudo systemctl status vulnerability-manager-backend'"
echo ""

