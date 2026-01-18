#!/bin/bash
# Скрипт для проверки статуса Red Hat парсера

echo "🔍 СТАТУС RED HAT ПАРСЕРА"
echo "=========================="
echo ""

# Проверка процесса
echo "📊 Процесс:"
ps aux | grep -E "python3.*redhat|redhat_parser" | grep -v grep || echo "  ⚠️ Процесс не найден"
echo ""

# Последние строки лога
echo "📋 Последние строки лога:"
tail -10 redhat_parser.log 2>/dev/null || echo "  ⚠️ Лог файл не найден"
echo ""

# Количество записей в БД
echo "💾 Записи в БД:"
python3 << 'PYTHON'
from models.database import DatabaseManager
db = DatabaseManager()
with db.connection.cursor() as cursor:
    cursor.execute("SELECT COUNT(*) FROM turn WHERE source = 'RedHat'")
    count = cursor.fetchone()[0]
    print(f"  Red Hat CVE: {count:,}")
PYTHON
echo ""

# Размер лог файла
if [ -f redhat_parser.log ]; then
    size=$(du -h redhat_parser.log | cut -f1)
    echo "📁 Размер лог файла: $size"
fi

