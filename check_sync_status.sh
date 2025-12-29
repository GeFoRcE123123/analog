#!/bin/bash
# Скрипт для быстрой проверки статуса синхронизации

echo "📊 Статус синхронизации CVE"
echo "============================"
echo ""

# Логи
echo "📝 Последние записи из логов:"
sshpass -p "123" ssh -o StrictHostKeyChecking=no user@10.0.88.20 "echo '123' | sudo -S docker exec vulnerability-backend tail -10 /app/logs/full_cve_sync.log 2>&1" | grep -E "Пакет|Сохранено|прогресс|✅|Обработано.*CVE" | tail -5

echo ""
echo "🔍 Для подробных логов:"
echo "ssh user@10.0.88.20"
echo "echo '123' | sudo -S docker exec vulnerability-backend tail -f /app/logs/full_cve_sync.log"

