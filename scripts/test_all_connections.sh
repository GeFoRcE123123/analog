#!/bin/bash
# Полная диагностика всех соединений системы

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
BACKEND_PASS="123"
ML_VM="10.0.88.25"
ML_USER="k8s-worker"
ML_PASS="k8s-worker"

export SSHPASS="$BACKEND_PASS"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔍 ДИАГНОСТИКА ВСЕХ СОЕДИНЕНИЙ СИСТЕМЫ                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  ПРОВЕРКА BACKEND VM (${BACKEND_USER}@${BACKEND_VM})"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Проверка доступности
echo "  📡 Проверка доступности..."
ping -c 2 $BACKEND_VM > /dev/null 2>&1 && echo "    ✅ Backend VM доступен" || echo "    ❌ Backend VM недоступен"

# Проверка SSH
echo "  🔐 Проверка SSH соединения..."
sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${BACKEND_USER}@${BACKEND_VM} "echo 'SSH OK'" 2>&1 | grep -q "SSH OK" && echo "    ✅ SSH соединение работает" || echo "    ❌ SSH соединение не работает"

# Проверка gunicorn
echo "  🐍 Проверка gunicorn..."
sshpass -e ssh -o StrictHostKeyChecking=no ${BACKEND_USER}@${BACKEND_VM} "ps aux | grep gunicorn | grep -v grep" 2>&1 | head -1 && echo "    ✅ Gunicorn запущен" || echo "    ❌ Gunicorn не запущен"

# Проверка HTTP
echo "  🌐 Проверка HTTP сервера..."
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://10.0.88.10/ 2>&1 | grep -q "200\|302" && echo "    ✅ HTTP сервер отвечает" || echo "    ❌ HTTP сервер не отвечает"

# Проверка БД подключения
echo "  🗄️  Проверка подключения к БД..."
sshpass -e ssh -o StrictHostKeyChecking=no ${BACKEND_USER}@${BACKEND_VM} "python3 -c \"
import sys
sys.path.insert(0, '/home/user/vulnerability_manager')
try:
    from models.legacy_repositories import LegacyVulnerabilityRepository
    from config import Config
    repo = LegacyVulnerabilityRepository()
    count = len(repo.get_all_vulnerabilities(limit=1))
    print('    ✅ БД подключение работает (найдено записей: ' + str(count) + ')')
except Exception as e:
    print('    ❌ Ошибка БД: ' + str(e))
\"" 2>&1

echo ""
echo "2️⃣  ПРОВЕРКА ML PLATFORM VM (${ML_USER}@${ML_VM})"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

export SSHPASS="$ML_PASS"

# Проверка доступности
echo "  📡 Проверка доступности..."
ping -c 2 $ML_VM > /dev/null 2>&1 && echo "    ✅ ML Platform VM доступен" || echo "    ❌ ML Platform VM недоступен"

# Проверка SSH
echo "  🔐 Проверка SSH соединения..."
sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${ML_USER}@${ML_VM} "echo 'SSH OK'" 2>&1 | grep -q "SSH OK" && echo "    ✅ SSH соединение работает" || echo "    ❌ SSH соединение не работает"

# Проверка ML API
echo "  🤖 Проверка ML Platform API..."
curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://${ML_VM}:8000/health 2>&1 | grep -q "200" && echo "    ✅ ML Platform API отвечает" || echo "    ❌ ML Platform API не отвечает"

# Проверка процесса
echo "  🔄 Проверка ML сервиса..."
sshpass -e ssh -o StrictHostKeyChecking=no ${ML_USER}@${ML_VM} "ps aux | grep -E 'python.*ai_service|fastapi|uvicorn' | grep -v grep" 2>&1 | head -1 && echo "    ✅ ML сервис запущен" || echo "    ❌ ML сервис не запущен"

echo ""
echo "3️⃣  ПРОВЕРКА API ENDPOINTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

export SSHPASS="$BACKEND_PASS"

# Проверка API endpoints
echo "  📊 Проверка /api/dashboard-stats..."
STATS_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://10.0.88.10/api/dashboard-stats 2>&1)
[ "$STATS_CODE" = "200" ] && echo "    ✅ /api/dashboard-stats работает" || echo "    ❌ /api/dashboard-stats не работает (код: $STATS_CODE)"

echo "  🔗 Проверка /api/ml-platform/connection..."
ML_CONN_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://10.0.88.10/api/ml-platform/connection 2>&1)
[ "$ML_CONN_CODE" = "200" ] && echo "    ✅ /api/ml-platform/connection работает" || echo "    ❌ /api/ml-platform/connection не работает (код: $ML_CONN_CODE)"

echo "  📋 Проверка /api/vulnerabilities..."
VULN_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://10.0.88.10/api/vulnerabilities?page=1&per_page=10" 2>&1)
[ "$VULN_CODE" = "200" ] && echo "    ✅ /api/vulnerabilities работает" || echo "    ❌ /api/vulnerabilities не работает (код: $VULN_CODE)"

echo ""
echo "4️⃣  ПРОВЕРКА ФАЙЛОВ И КОНФИГУРАЦИИ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Проверка ключевых файлов на backend
echo "  📄 Проверка файлов на Backend..."
sshpass -e ssh -o StrictHostKeyChecking=no ${BACKEND_USER}@${BACKEND_VM} "
files=(
    '/home/user/vulnerability_manager/services/backend/app.py'
    '/home/user/vulnerability_manager/services/ml_platform_client.py'
    '/home/user/vulnerability_manager/models/legacy_repositories.py'
    '/home/user/vulnerability_manager/config.py'
    '/home/user/vulnerability_manager/templates/ai/training.html'
)
for file in \"\${files[@]}\"; do
    if [ -f \"\$file\" ]; then
        echo \"    ✅ \$(basename \$file)\"
    else
        echo \"    ❌ \$(basename \$file) - НЕ НАЙДЕН\"
    fi
done
" 2>&1

echo ""
echo "5️⃣  ПРОВЕРКА ЛОГОВ НА ОШИБКИ"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Проверка логов gunicorn
echo "  📝 Последние ошибки в логах gunicorn..."
sshpass -e ssh -o StrictHostKeyChecking=no ${BACKEND_USER}@${BACKEND_VM} "
journalctl -u gunicorn --no-pager -n 20 2>&1 | grep -i error | tail -5 || echo '    ℹ️  Ошибок в логах не найдено'
" 2>&1 | head -10

echo ""
echo "✅ Диагностика завершена!"

unset SSHPASS
