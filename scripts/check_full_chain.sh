#!/bin/bash
# Полная проверка цепочки взаимодействия

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
PASSWORD="123"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔍 ПОЛНАЯ ПРОВЕРКА ЦЕПОЧКИ ВЗАИМОДЕЙСТВИЯ                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  Проверка БД (напрямую через SQL)..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    PGPASSWORD=123 psql -h 10.0.88.11 -U admin -d vuln_db -c 'SELECT COUNT(*) as total FROM turn;' 2>&1 | grep -A 1 total
" 2>&1

echo ""
echo "2️⃣  Проверка API endpoint (локально на бэкенде)..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    curl -s -X POST http://localhost:5000/api/ai/batch-analyze \
         -H 'Content-Type: application/json' \
         -H 'Cookie: session=test' \
         -d '{\"vulnerability_ids\": []}' 2>&1 | head -20
" 2>&1

echo ""
echo "3️⃣  Проверка метода get_all_vulnerabilities через Python..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd /home/user/vulnerability_manager
    python3 << 'PYTHON'
import sys
import os
sys.path.insert(0, '/home/user/vulnerability_manager')

# Прямой импорт без models.__init__
from models.legacy_repositories import LegacyVulnerabilityRepository
from models.database import DatabaseManager

try:
    db = DatabaseManager()
    repo = LegacyVulnerabilityRepository(db.connection)
    
    # Тест с лимитом 10
    vulns = repo.get_all_vulnerabilities(limit=10)
    print(f'✅ get_all_vulnerabilities(limit=10): {len(vulns)} уязвимостей')
    
    if len(vulns) > 0:
        v = vulns[0]
        print(f'   Первая: ID={v.id}, CVE={getattr(v, \"cve_id\", \"N/A\")}, Title={v.title[:50]}')
    else:
        print('   ⚠️  Уязвимостей не найдено')
        
except Exception as e:
    print(f'❌ Ошибка: {e}')
    import traceback
    traceback.print_exc()
PYTHON
" 2>&1

echo ""
echo "4️⃣  Проверка ML платформы клиента..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd /home/user/vulnerability_manager
    python3 << 'PYTHON'
import sys
sys.path.insert(0, '/home/user/vulnerability_manager')
from services.ml_platform_client import MLPlatformClient

client = MLPlatformClient()
print(f'ML API URL: {client.ml_api_url}')
print(f'Max batch: {client.max_analysis_batch}')

# Тест получения уязвимостей
try:
    result = client.start_ai_analysis(vulnerability_ids=None)
    print(f'Результат start_ai_analysis:')
    print(f'  Success: {result.get(\"success\")}')
    print(f'  Error: {result.get(\"error\", \"N/A\")}')
    if result.get('hint'):
        print(f'  Hint: {result.get(\"hint\")}')
except Exception as e:
    print(f'❌ Ошибка: {e}')
    import traceback
    traceback.print_exc()
PYTHON
" 2>&1

unset SSHPASS
