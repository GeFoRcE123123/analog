#!/bin/bash
# Скрипт для применения миграции на VM Database (10.0.88.11)

VM_IP="10.0.88.11"
VM_USER="user"
VM_PASS="123"
SCRIPT_NAME="apply_migration.py"

echo "🚀 Применение миграции NVD полей на VM $VM_IP"

# Копируем скрипт на VM
echo "📤 Копирование скрипта миграции на VM..."
sshpass -p "$VM_PASS" scp -o StrictHostKeyChecking=no "$SCRIPT_NAME" "${VM_USER}@${VM_IP}:/tmp/"

if [ $? -ne 0 ]; then
    echo "❌ Ошибка копирования файла"
    exit 1
fi

# Выполняем миграцию внутри Docker контейнера
echo "🔧 Выполнение миграции в контейнере..."
sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no "${VM_USER}@${VM_IP}" << 'ENDSSH'
    # Проверяем наличие Python в контейнере
    if docker exec vulnerability_db python3 --version > /dev/null 2>&1; then
        echo "✅ Python найден в контейнере"
        # Копируем скрипт в контейнер
        docker cp /tmp/apply_migration.py vulnerability_db:/tmp/
        # Устанавливаем psycopg2 если нужно
        docker exec vulnerability_db sh -c "pip3 install psycopg2-binary 2>/dev/null || pip install psycopg2-binary 2>/dev/null || echo 'psycopg2 уже установлен'"
        # Выполняем скрипт
        docker exec vulnerability_db python3 /tmp/apply_migration.py
    else
        echo "⚠️ Python не найден, используем прямой SQL через psql"
        docker exec -i vulnerability_db psql -U admin -d vuln_db << 'SQL'
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v2_vector TEXT;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v3_vector TEXT;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v4_vector TEXT;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_version VARCHAR(10) DEFAULT '3.1';
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v2_metrics JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v3_metrics JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v4_metrics JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS epss_score DECIMAL(5,4);
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS epss_percentile DECIMAL(5,2);
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cwe_ids TEXT[];
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS affected_products JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_references JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS vendor_comments JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cpe_configurations JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_weaknesses JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS source_identifier VARCHAR(200);
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_status VARCHAR(50);
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_published TIMESTAMP;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_last_modified TIMESTAMP;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_descriptions JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_metrics JSONB;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS has_kev BOOLEAN DEFAULT FALSE;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS has_cert_alerts BOOLEAN DEFAULT FALSE;
            ALTER TABLE turn ADD COLUMN IF NOT EXISTS cve_json5_data JSONB;
            
            CREATE INDEX IF NOT EXISTS idx_turn_cwe_ids ON turn USING GIN(cwe_ids);
            CREATE INDEX IF NOT EXISTS idx_turn_epss_score ON turn(epss_score);
            CREATE INDEX IF NOT EXISTS idx_turn_source_identifier ON turn(source_identifier);
            CREATE INDEX IF NOT EXISTS idx_turn_nvd_status ON turn(nvd_status);
            CREATE INDEX IF NOT EXISTS idx_turn_has_kev ON turn(has_kev);
            CREATE INDEX IF NOT EXISTS idx_turn_nvd_published ON turn(nvd_published);
            CREATE INDEX IF NOT EXISTS idx_turn_affected_products_gin ON turn USING GIN(affected_products);
            CREATE INDEX IF NOT EXISTS idx_turn_nvd_references_gin ON turn USING GIN(nvd_references);
            CREATE INDEX IF NOT EXISTS idx_turn_nvd_weaknesses_gin ON turn USING GIN(nvd_weaknesses);
            CREATE INDEX IF NOT EXISTS idx_turn_cpe_configurations_gin ON turn USING GIN(cpe_configurations);
SQL
        echo "✅ Миграция выполнена через psql"
    fi
ENDSSH

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Миграция успешно применена!"
else
    echo ""
    echo "❌ Ошибка при применении миграции"
    exit 1
fi

