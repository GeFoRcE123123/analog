#!/bin/bash
# Проверка каждого элемента взаимодействия

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
PASSWORD="123"
DB_VM="10.0.88.11"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔍 ПРОВЕРКА КАЖДОГО ЭЛЕМЕНТА ВЗАИМОДЕЙСТВИЯ                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  ПРОВЕРКА БД (PostgreSQL на 10.0.88.11)..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    PGPASSWORD=123 psql -h $DB_VM -U admin -d vuln_db -c 'SELECT COUNT(*) as total FROM turn;' 2>&1
" 2>&1 | grep -E "total|COUNT|rows"

echo ""
echo "2️⃣  ПРОВЕРКА: Есть ли записи с CVE ID..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    PGPASSWORD=123 psql -h $DB_VM -U admin -d vuln_db -c \"SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != '';\" 2>&1
" 2>&1 | grep -E "count|COUNT|rows"

echo ""
echo "3️⃣  ПРОВЕРКА: Примеры записей..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    PGPASSWORD=123 psql -h $DB_VM -U admin -d vuln_db -c \"SELECT id, cve, name, source FROM turn WHERE cve IS NOT NULL LIMIT 3;\" 2>&1
" 2>&1 | head -10

echo ""
echo "4️⃣  ПРОВЕРКА: Backend API работает..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    curl -s http://localhost:5000/api/vulnerabilities?page=1&per_page=1 2>&1 | python3 -c 'import sys, json; d=json.load(sys.stdin); print(f\"API работает: {d.get(\"success\")}, Всего: {d.get(\"total_count\", 0)}\")' 2>/dev/null || echo 'API не отвечает'
" 2>&1

echo ""
echo "5️⃣  ПРОВЕРКА: Логи gunicorn (последние ошибки)..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    journalctl -u gunicorn -n 50 --no-pager 2>/dev/null | grep -i 'error\|exception\|traceback' | tail -5 || echo 'Логи не найдены'
" 2>&1

echo ""
echo "6️⃣  ПРОВЕРКА: ML платформа доступна..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    curl -s -m 5 http://10.0.88.25:8000/health 2>&1 | head -3 || echo 'ML платформа недоступна'
" 2>&1

echo ""
echo "7️⃣  ПРОВЕРКА: Структура файлов на бэкенде..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    ls -lh /home/user/vulnerability_manager/services/ml_platform_client.py 2>&1 | head -1
    ls -lh /home/user/vulnerability_manager/models/legacy_repositories.py 2>&1 | head -1
    ls -lh /home/user/vulnerability_manager/backend/app.py 2>&1 | head -1
" 2>&1

unset SSHPASS
