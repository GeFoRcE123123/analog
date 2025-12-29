-- ============================================================
-- Пересоздание таблицы turn с полными NVD полями
-- ============================================================

-- Удаляем старую таблицу (если есть данные, они будут потеряны!)
DROP TABLE IF EXISTS turn CASCADE;

-- Создаем новую таблицу с всеми полями
CREATE TABLE turn (
    -- Основные поля (legacy)
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
    
    -- CVSS векторы для разных версий
    cvss_v2_vector TEXT,
    cvss_v3_vector TEXT,
    cvss_v4_vector TEXT,
    cvss_version VARCHAR(10) DEFAULT '3.1',
    
    -- Детальные CVSS метрики (JSONB для хранения всех данных)
    cvss_v2_metrics JSONB,
    cvss_v3_metrics JSONB,
    cvss_v4_metrics JSONB,
    
    -- EPSS (Exploit Prediction Scoring System) - оценка вероятности эксплуатации
    epss_score DECIMAL(5,4),
    epss_percentile DECIMAL(5,2),
    
    -- CWE коды (массив)
    cwe_ids TEXT[],
    
    -- Затронутые продукты (CPE и информация о продуктах) - JSONB
    affected_products JSONB,
    
    -- Ссылки с тегами (references) - JSONB
    nvd_references JSONB,
    
    -- Комментарии вендоров - JSONB
    vendor_comments JSONB,
    
    -- Конфигурации CPE - JSONB
    cpe_configurations JSONB,
    
    -- Weaknesses (слабости) - JSONB
    nvd_weaknesses JSONB,
    
    -- Источник данных (source identifier)
    source_identifier VARCHAR(200),
    
    -- Статус уязвимости в NVD (PUBLISHED, REJECTED, etc.)
    nvd_status VARCHAR(50),
    
    -- Дата публикации в NVD
    nvd_published TIMESTAMP,
    
    -- Дата последнего изменения в NVD
    nvd_last_modified TIMESTAMP,
    
    -- Описания на разных языках - JSONB
    nvd_descriptions JSONB,
    
    -- Все метрики в одном JSONB поле (для полноты данных)
    nvd_metrics JSONB,
    
    -- Флаги и дополнительные данные
    has_kev BOOLEAN DEFAULT FALSE,
    has_cert_alerts BOOLEAN DEFAULT FALSE,
    
    -- Дополнительные поля из CVE JSON 5.x (если используются)
    cve_json5_data JSONB
);

-- Восстанавливаем индексы для основных полей
CREATE INDEX IF NOT EXISTS idx_turn_cve ON turn(cve);
CREATE INDEX IF NOT EXISTS idx_turn_source ON turn(source);
CREATE INDEX IF NOT EXISTS idx_turn_status ON turn(status);
CREATE INDEX IF NOT EXISTS idx_turn_cvss ON turn(cvss);
CREATE INDEX IF NOT EXISTS idx_turn_joining_date ON turn(joining_date);

-- Индексы для новых NVD полей
CREATE INDEX IF NOT EXISTS idx_turn_cwe_ids ON turn USING GIN(cwe_ids);
CREATE INDEX IF NOT EXISTS idx_turn_epss_score ON turn(epss_score);
CREATE INDEX IF NOT EXISTS idx_turn_source_identifier ON turn(source_identifier);
CREATE INDEX IF NOT EXISTS idx_turn_nvd_status ON turn(nvd_status);
CREATE INDEX IF NOT EXISTS idx_turn_has_kev ON turn(has_kev);
CREATE INDEX IF NOT EXISTS idx_turn_nvd_published ON turn(nvd_published);

-- GIN индексы для JSONB полей (для быстрого поиска)
CREATE INDEX IF NOT EXISTS idx_turn_affected_products_gin ON turn USING GIN(affected_products);
CREATE INDEX IF NOT EXISTS idx_turn_nvd_references_gin ON turn USING GIN(nvd_references);
CREATE INDEX IF NOT EXISTS idx_turn_nvd_weaknesses_gin ON turn USING GIN(nvd_weaknesses);
CREATE INDEX IF NOT EXISTS idx_turn_cpe_configurations_gin ON turn USING GIN(cpe_configurations);

-- Комментарии к полям
COMMENT ON COLUMN turn.cvss_v2_vector IS 'CVSS v2.0 vector string';
COMMENT ON COLUMN turn.cvss_v3_vector IS 'CVSS v3.0/v3.1 vector string';
COMMENT ON COLUMN turn.cvss_v4_vector IS 'CVSS v4.0 vector string';
COMMENT ON COLUMN turn.cvss_version IS 'Версия CVSS (2.0, 3.0, 3.1, 4.0)';
COMMENT ON COLUMN turn.epss_score IS 'EPSS score (0.0-1.0) - вероятность эксплуатации';
COMMENT ON COLUMN turn.epss_percentile IS 'EPSS percentile (0-100)';
COMMENT ON COLUMN turn.cwe_ids IS 'Массив CWE кодов слабостей';
COMMENT ON COLUMN turn.affected_products IS 'JSONB: Затронутые продукты с версиями и CPE';
COMMENT ON COLUMN turn.nvd_references IS 'JSONB: Ссылки на внешние ресурсы с тегами';
COMMENT ON COLUMN turn.vendor_comments IS 'JSONB: Комментарии от вендоров';
COMMENT ON COLUMN turn.cpe_configurations IS 'JSONB: Конфигурации CPE (затронутые продукты)';
COMMENT ON COLUMN turn.nvd_weaknesses IS 'JSONB: Слабости (CWE) из NVD';
COMMENT ON COLUMN turn.source_identifier IS 'Идентификатор источника в NVD';
COMMENT ON COLUMN turn.nvd_status IS 'Статус уязвимости в NVD (PUBLISHED, REJECTED, etc.)';
COMMENT ON COLUMN turn.nvd_published IS 'Дата публикации в NVD';
COMMENT ON COLUMN turn.nvd_last_modified IS 'Дата последнего изменения в NVD';
COMMENT ON COLUMN turn.nvd_descriptions IS 'JSONB: Описания на разных языках';
COMMENT ON COLUMN turn.nvd_metrics IS 'JSONB: Все метрики CVSS';
COMMENT ON COLUMN turn.has_kev IS 'Флаг: есть ли в CISA KEV (Known Exploited Vulnerabilities)';
COMMENT ON COLUMN turn.has_cert_alerts IS 'Флаг: есть ли CERT alerts';
COMMENT ON COLUMN turn.cve_json5_data IS 'JSONB: Полные данные из CVE JSON 5.x формата';

