#!/bin/bash
# Скрипт для пересоздания таблицы turn с NVD полями на VM Database

VM_IP="10.0.88.11"
VM_USER="user"
VM_PASS="123"
SQL_FILE="services/database/recreate_turn_table.sql"

echo "🚀 Пересоздание таблицы turn с NVD полями на VM $VM_IP"

# Копируем SQL файл на VM
echo "📤 Копирование SQL файла на VM..."
sshpass -p "$VM_PASS" scp -o StrictHostKeyChecking=no "$SQL_FILE" "${VM_USER}@${VM_IP}:/tmp/"

if [ $? -ne 0 ]; then
    echo "❌ Ошибка копирования файла"
    exit 1
fi

# Выполняем SQL скрипт в контейнере
echo "🔧 Выполнение SQL скрипта в контейнере..."
sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no "${VM_USER}@${VM_IP}" << 'ENDSSH'
    docker cp /tmp/recreate_turn_table.sql vulnerability_db:/tmp/
    docker exec vulnerability_db psql -U admin -d vuln_db -f /tmp/recreate_turn_table.sql
    echo ""
    echo "✅ Проверка созданных колонок:"
    docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT column_name, data_type FROM information_schema.columns WHERE table_name='turn' AND (column_name LIKE '%cvss%' OR column_name LIKE '%epss%' OR column_name LIKE '%cwe%' OR column_name LIKE '%nvd%' OR column_name LIKE '%kev%' OR column_name IN ('affected_products', 'vendor_comments', 'cpe_configurations', 'source_identifier', 'cve_json5_data')) ORDER BY column_name;"
    echo ""
    echo "✅ Подсчет всех колонок:"
    docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) as total_columns FROM information_schema.columns WHERE table_name='turn';"
ENDSSH

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Таблица turn успешно пересоздана с NVD полями!"
else
    echo ""
    echo "❌ Ошибка при пересоздании таблицы"
    exit 1
fi

