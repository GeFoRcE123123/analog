-- ============================================================
-- Миграция: Добавление уникальных полей NVD в таблицу turn
-- ============================================================

-- CVSS векторы для разных версий
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v2_vector TEXT;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v3_vector TEXT;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v4_vector TEXT;

-- CVSS версии (для определения какой вектор использовать)
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_version VARCHAR(10) DEFAULT '3.1';

-- Детальные CVSS метрики (JSONB для хранения всех данных)
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v2_metrics JSONB;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v3_metrics JSONB;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cvss_v4_metrics JSONB;

-- EPSS (Exploit Prediction Scoring System) - оценка вероятности эксплуатации
ALTER TABLE turn ADD COLUMN IF NOT EXISTS epss_score DECIMAL(5,4);
ALTER TABLE turn ADD COLUMN IF NOT EXISTS epss_percentile DECIMAL(5,2);

-- CWE коды (массив)
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cwe_ids TEXT[];

-- Затронутые продукты (CPE и информация о продуктах) - JSONB
ALTER TABLE turn ADD COLUMN IF NOT EXISTS affected_products JSONB;

-- Ссылки с тегами (references) - JSONB
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_references JSONB;

-- Комментарии вендоров - JSONB
ALTER TABLE turn ADD COLUMN IF NOT EXISTS vendor_comments JSONB;

-- Конфигурации CPE - JSONB
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cpe_configurations JSONB;

-- Weaknesses (слабости) - JSONB
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_weaknesses JSONB;

-- Источник данных (source identifier)
ALTER TABLE turn ADD COLUMN IF NOT EXISTS source_identifier VARCHAR(200);

-- Статус уязвимости в NVD (PUBLISHED, REJECTED, etc.)
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_status VARCHAR(50);

-- Дата публикации в NVD
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_published TIMESTAMP;

-- Дата последнего изменения в NVD
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_last_modified TIMESTAMP;

-- Описания на разных языках - JSONB
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_descriptions JSONB;

-- Все метрики в одном JSONB поле (для полноты данных)
ALTER TABLE turn ADD COLUMN IF NOT EXISTS nvd_metrics JSONB;

-- Флаги и дополнительные данные
ALTER TABLE turn ADD COLUMN IF NOT EXISTS has_kev BOOLEAN DEFAULT FALSE;
ALTER TABLE turn ADD COLUMN IF NOT EXISTS has_cert_alerts BOOLEAN DEFAULT FALSE;

-- Дополнительные поля из CVE JSON 5.x (если используются)
ALTER TABLE turn ADD COLUMN IF NOT EXISTS cve_json5_data JSONB;

-- Индексы для новых полей
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

