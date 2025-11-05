-- Создание таблицы операторов
CREATE TABLE IF NOT EXISTS operators (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    email VARCHAR(200) UNIQUE NOT NULL,
    experience_level DECIMAL(5,2) DEFAULT 50.0,
    current_metric DECIMAL(5,2) DEFAULT 50.0,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Создание таблицы уязвимостей
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(50),
    status VARCHAR(50) DEFAULT 'new',
    assigned_operator INTEGER REFERENCES operators(id) ON DELETE SET NULL,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_date TIMESTAMP,
    approved BOOLEAN DEFAULT FALSE,
    modifications INTEGER DEFAULT 0,
    cvss_score DECIMAL(3,1) DEFAULT 0.0,
    risk_level VARCHAR(50) DEFAULT 'medium',
    category VARCHAR(100) DEFAULT 'web'
);

-- Индексы для улучшения производительности
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_assigned_operator ON vulnerabilities(assigned_operator);
CREATE INDEX IF NOT EXISTS idx_operators_email ON operators(email);


-- Добавляем колонки для NVD в существующую таблицу vulnerabilities
ALTER TABLE vulnerabilities
ADD COLUMN IF NOT EXISTS cve_id VARCHAR(50) UNIQUE,
ADD COLUMN IF NOT EXISTS source_identifier VARCHAR(255),
ADD COLUMN IF NOT EXISTS published TIMESTAMP,
ADD COLUMN IF NOT EXISTS last_modified TIMESTAMP,
ADD COLUMN IF NOT EXISTS vuln_status VARCHAR(50),
ADD COLUMN IF NOT EXISTS descriptions JSONB,
ADD COLUMN IF NOT EXISTS metrics JSONB,
ADD COLUMN IF NOT EXISTS weaknesses JSONB,
ADD COLUMN IF NOT EXISTS configurations JSONB,
ADD COLUMN IF NOT EXISTS "references" JSONB,
ADD COLUMN IF NOT EXISTS vendor_comments JSONB,
ADD COLUMN IF NOT EXISTS is_ai_related BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS ai_confidence DECIMAL(3,2) DEFAULT 0.0,
ADD COLUMN IF NOT EXISTS has_kev BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS has_cert_alerts BOOLEAN DEFAULT FALSE;


-- Создаем таблицу для AI уязвимостей
CREATE TABLE IF NOT EXISTS ai_vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) UNIQUE NOT NULL,
    ai_confidence DECIMAL(3,2) DEFAULT 0.0,
    ai_keywords_found JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
);

-- Индексы для улучшения производительности
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_is_ai_related ON vulnerabilities(is_ai_related);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published ON vulnerabilities(published);
CREATE INDEX IF NOT EXISTS idx_ai_vulnerabilities_confidence ON ai_vulnerabilities(ai_confidence);