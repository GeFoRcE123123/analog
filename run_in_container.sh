#!/bin/bash
# Скрипт для выполнения внутри контейнера vulnerability_db
# Использование: docker exec -i vulnerability_db bash < run_in_container.sh

psql -U admin -d vuln_db << 'EOSQL'
DROP TABLE IF EXISTS turn CASCADE;

CREATE TABLE turn (
    id SERIAL PRIMARY KEY,
    source TEXT,
    link TEXT,
    cve TEXT UNIQUE,
    joining_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    name TEXT,
    cvss REAL,
    price_one REAL,
    priority REAL,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    etc TEXT,
    status BOOLEAN DEFAULT TRUE,
    cvss_v2_vector TEXT,
    cvss_v3_vector TEXT,
    cvss_v4_vector TEXT,
    cvss_version VARCHAR(10) DEFAULT '3.1',
    cvss_v2_metrics JSONB,
    cvss_v3_metrics JSONB,
    cvss_v4_metrics JSONB,
    epss_score DECIMAL(5,4),
    epss_percentile DECIMAL(5,2),
    cwe_ids TEXT[],
    affected_products JSONB,
    nvd_references JSONB,
    vendor_comments JSONB,
    cpe_configurations JSONB,
    nvd_weaknesses JSONB,
    source_identifier VARCHAR(200),
    nvd_status VARCHAR(50),
    nvd_published TIMESTAMP,
    nvd_last_modified TIMESTAMP,
    nvd_descriptions JSONB,
    nvd_metrics JSONB,
    has_kev BOOLEAN DEFAULT FALSE,
    has_cert_alerts BOOLEAN DEFAULT FALSE,
    cve_json5_data JSONB
);

CREATE INDEX idx_turn_cve ON turn(cve);
CREATE INDEX idx_turn_source ON turn(source);
CREATE INDEX idx_turn_status ON turn(status);
CREATE INDEX idx_turn_cvss ON turn(cvss);
CREATE INDEX idx_turn_joining_date ON turn(joining_date);
CREATE INDEX idx_turn_cwe_ids ON turn USING GIN(cwe_ids);
CREATE INDEX idx_turn_epss_score ON turn(epss_score);
CREATE INDEX idx_turn_source_identifier ON turn(source_identifier);
CREATE INDEX idx_turn_nvd_status ON turn(nvd_status);
CREATE INDEX idx_turn_has_kev ON turn(has_kev);
CREATE INDEX idx_turn_nvd_published ON turn(nvd_published);
CREATE INDEX idx_turn_affected_products_gin ON turn USING GIN(affected_products);
CREATE INDEX idx_turn_nvd_references_gin ON turn USING GIN(nvd_references);
CREATE INDEX idx_turn_nvd_weaknesses_gin ON turn USING GIN(nvd_weaknesses);
CREATE INDEX idx_turn_cpe_configurations_gin ON turn USING GIN(cpe_configurations);

SELECT 'SUCCESS: Table recreated with ' || COUNT(*) || ' columns' FROM information_schema.columns WHERE table_name='turn';
EOSQL

