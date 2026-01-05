-- ============================================================
-- Простые команды для полного пересоздания таблицы turn с NVD полями
-- Выполнить через: docker exec -it vulnerability_db psql -U admin -d vuln_db
-- ============================================================

-- 1. Удаляем старую таблицу
DROP TABLE IF EXISTS turn CASCADE;

-- 2. Создаем новую таблицу со всеми полями
CREATE TABLE turn (
    -- Основные поля
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
    
    -- NVD поля: CVSS векторы
    cvss_v2_vector TEXT,
    cvss_v3_vector TEXT,
    cvss_v4_vector TEXT,
    cvss_version VARCHAR(10) DEFAULT '3.1',
    cvss_v2_metrics JSONB,
    cvss_v3_metrics JSONB,
    cvss_v4_metrics JSONB,
    
    -- EPSS
    epss_score DECIMAL(5,4),
    epss_percentile DECIMAL(5,2),
    
    -- CWE
    cwe_ids TEXT[],
    
    -- JSONB поля
    affected_products JSONB,
    nvd_references JSONB,
    vendor_comments JSONB,
    cpe_configurations JSONB,
    nvd_weaknesses JSONB,
    
    -- Метаданные NVD
    source_identifier VARCHAR(200),
    nvd_status VARCHAR(50),
    nvd_published TIMESTAMP,
    nvd_last_modified TIMESTAMP,
    nvd_descriptions JSONB,
    nvd_metrics JSONB,
    
    -- Флаги
    has_kev BOOLEAN DEFAULT FALSE,
    has_cert_alerts BOOLEAN DEFAULT FALSE,
    cve_json5_data JSONB
);

-- 3. Создаем индексы (IF NOT EXISTS для избежания ошибок)
CREATE INDEX IF NOT EXISTS idx_turn_cve ON turn(cve);
CREATE INDEX IF NOT EXISTS idx_turn_source ON turn(source);
CREATE INDEX IF NOT EXISTS idx_turn_status ON turn(status);
CREATE INDEX IF NOT EXISTS idx_turn_cvss ON turn(cvss);
CREATE INDEX IF NOT EXISTS idx_turn_joining_date ON turn(joining_date);
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

-- 4. Проверка
SELECT 'Таблица создана! Всего колонок: ' || COUNT(*) FROM information_schema.columns WHERE table_name='turn';

