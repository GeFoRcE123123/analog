#!/bin/bash
# Быстрые команды для миграции таблицы turn
# Использование: скопируйте команды и выполните на VM

echo "=== Миграция таблицы turn с NVD полями ==="
echo ""

# 1. Проверка текущего состояния
echo "1. Текущее количество колонок:"
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) as total_columns FROM information_schema.columns WHERE table_name='turn';"

# 2. Выполнение миграции
echo ""
echo "2. Выполнение миграции..."
docker exec vulnerability_db psql -U admin -d vuln_db -f /tmp/recreate.sql

# 3. Проверка результата
echo ""
echo "3. Новое количество колонок:"
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) as total_columns FROM information_schema.columns WHERE table_name='turn';"

echo ""
echo "4. Новые NVD поля:"
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT column_name FROM information_schema.columns WHERE table_name='turn' AND column_name IN ('cvss_v2_vector', 'cvss_v3_vector', 'epss_score', 'cwe_ids', 'nvd_references', 'has_kev') ORDER BY column_name;"

echo ""
echo "=== Миграция завершена ==="

