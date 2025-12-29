#!/bin/bash
# Скрипт для выполнения на VM Database (10.0.88.11)
# Использование: скопировать на VM и выполнить там

echo "Применение миграции NVD полей..."

docker exec vulnerability_db psql -U admin -d vuln_db << 'SQL'
-- CVSS векторы
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v2_vector TEXT;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v3_vector TEXT;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v4_vector TEXT;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_version VARCHAR(10) DEFAULT '3.1';
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v2_metrics JSONB;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v3_metrics JSONB;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v4_metrics JSONB;

-- EPSS
ALTER TABLE turn ADD COLUMN IF NOT EXISTS epss_score DECIMAL(5,4);
ALTER TABLE turn ADD COLUMN IF NOT EXISTS epss_percentile DECIMAL(5,2);

-- CWE
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cwe_ids TEXT[];

-- JSONB поля
ALTER TABLE turn ADD COLUMN IF NOT EXISTS affected_products JSONB;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_references JSONB;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS vendor_comments JSONB;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cpe_configurations JSONB;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_weaknesses JSONB;

-- Метаданные NVD
ALTER TABLE turn ADD COLUMN IF NOT EXISTS source_identifier VARCHAR(200);
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_status VARCHAR(50);
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_published TIMESTAMP;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_last_modified TIMESTAMP;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_descriptions JSONB;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_metrics JSONB;

-- Флаги
ALTER TABLE turn ADD COLUMN IF NOT EXISTS has_kev BOOLEAN DEFAULT FALSE;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS has_cert_alerts BOOLEAN DEFAULT FALSE;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cve_json5_data JSONB;

-- Индексы
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

-- Проверка
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name='turn' 
AND column_name IN ('cvss_v2_vector', 'cvss_v3_vector', 'epss_score', 'cwe_ids', 'nvd_references', 'has_kev', 'source_identifier', 'nvd_published', 'nvd_metrics', 'cve_json5_data')
ORDER BY column_name;
SQL

echo "Миграция завершена!"

