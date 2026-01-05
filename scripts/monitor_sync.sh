#!/bin/bash
# Скрипт для мониторинга статуса синхронизации CVE

echo "📊 Мониторинг статуса синхронизации CVE"
echo "========================================"
echo ""

# Проверка статуса через API
curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt http://10.0.88.20/api/cve-sync/status 2>/dev/null | python3 -m json.tool

echo ""
echo "Для обновления статуса выполните: ./monitor_sync.sh"
echo "Или смотрите логи: ssh user@10.0.88.20 'echo \"123\" | sudo -S docker exec vulnerability-backend tail -f /app/logs/full_cve_sync.log'"

