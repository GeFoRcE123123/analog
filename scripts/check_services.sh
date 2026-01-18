#!/bin/bash
# Проверка состояния сервисов

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
PASSWORD="123"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔍 ДИАГНОСТИКА СЕРВИСОВ                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  Проверка процессов Python/Flask..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ps aux | grep -E 'python|flask|gunicorn' | grep -v grep" 2>&1

echo ""
echo "2️⃣  Проверка портов..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ss -tlnp 2>/dev/null | grep -E '5000|5432|80' || netstat -tlnp 2>/dev/null | grep -E '5000|5432|80'" 2>&1

echo ""
echo "3️⃣  Проверка подключения к БД..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd /home/user/vulnerability_manager
    python3 << 'PYTHON'
import sys
sys.path.insert(0, '/home/user/vulnerability_manager')
try:
    from models.database import DatabaseManager
    db = DatabaseManager()
    if db.connection:
        print('✅ БД подключена')
        with db.connection.cursor() as cursor:
            cursor.execute('SELECT version()')
            print('PostgreSQL версия:', cursor.fetchone()[0])
    else:
        print('❌ БД не подключена')
except Exception as e:
    print('❌ Ошибка подключения к БД:', str(e))
PYTHON
" 2>&1

echo ""
echo "4️⃣  Проверка конфигурации..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd /home/user/vulnerability_manager
    python3 << 'PYTHON'
import sys
sys.path.insert(0, '/home/user/vulnerability_manager')
try:
    from config import Config
    print('DB Host:', Config.DATABASE_CONFIG.host)
    print('DB Port:', Config.DATABASE_CONFIG.port)
    print('DB Name:', Config.DATABASE_CONFIG.database)
    print('Backend URL:', getattr(Config, 'BACKEND_URL', 'N/A'))
except Exception as e:
    print('❌ Ошибка чтения конфига:', str(e))
PYTHON
" 2>&1

echo ""
echo "5️⃣  Проверка последних ошибок в app.py..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd /home/user/vulnerability_manager/backend
    if [ -f app.py ]; then
        tail -50 app.py | grep -A 5 -B 5 'import\|from\|DatabaseManager' | head -20
    fi
" 2>&1

unset SSHPASS
