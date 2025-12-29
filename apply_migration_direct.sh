#!/bin/bash
# Прямое выполнение миграции на VM

VM_IP="10.0.88.11"
VM_USER="user"
VM_PASS="123"

echo "Применение миграции NVD полей..."

# Выполняем команды по одной через SSH
sshpass -p "$VM_PASS" ssh -o StrictHostKeyChecking=no "${VM_USER}@${VM_IP}" "
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v2_vector TEXT;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v3_vector TEXT;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v4_vector TEXT;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_version VARCHAR(10) DEFAULT '3.1';\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS epss_score DECIMAL(5,4);\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS epss_percentile DECIMAL(5,2);\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS cwe_ids TEXT[];\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS affected_products JSONB;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_references JSONB;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS vendor_comments JSONB;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS cpe_configurations JSONB;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_weaknesses JSONB;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS source_identifier VARCHAR(200);\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_status VARCHAR(50);\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_published TIMESTAMP;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_last_modified TIMESTAMP;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_descriptions JSONB;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_metrics JSONB;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS has_kev BOOLEAN DEFAULT FALSE;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS has_cert_alerts BOOLEAN DEFAULT FALSE;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"ALTER TABLE turn ADD COLUMN IF NOT EXISTS cve_json5_data JSONB;\"
docker exec vulnerability_db psql -U admin -d vuln_db -c \"SELECT COUNT(*) as columns_added FROM information_schema.columns WHERE table_name='turn' AND column_name IN ('cvss_v2_vector', 'cvss_v3_vector', 'epss_score', 'cwe_ids', 'nvd_references', 'has_kev');\"
"

