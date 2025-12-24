-- Инициализация базы данных для Vulnerability Manager
-- Database VM: 10.0.88.11

-- Создание базы данных (если не существует)
-- CREATE DATABASE vuln_db;

-- Подключение к базе данных
-- \c vuln_db;

-- Включение расширений
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- ТАБЛИЦЫ ДЛЯ АВТОРИЗАЦИИ
-- ============================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) CHECK (role IN ('admin', 'user')) DEFAULT 'user',
    full_name VARCHAR(100),
    department VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    is_locked BOOLEAN DEFAULT FALSE,
    locked_until TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ТАБЛИЦЫ ДЛЯ УЯЗВИМОСТЕЙ (MODERN SCHEMA)
-- ============================================

CREATE TABLE IF NOT EXISTS operators (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    email VARCHAR(200) UNIQUE NOT NULL,
    experience_level DECIMAL(5,2) DEFAULT 50.0,
    current_metric DECIMAL(5,2) DEFAULT 50.0,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

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
    category VARCHAR(100) DEFAULT 'web',
    -- NVD поля
    cve_id VARCHAR(50) UNIQUE,
    source_identifier VARCHAR(100),
    published TIMESTAMP,
    last_modified TIMESTAMP,
    vuln_status VARCHAR(50),
    descriptions JSONB,
    metrics JSONB,
    weaknesses JSONB,
    configurations JSONB,
    "references" JSONB,
    vendor_comments JSONB,
    is_ai_related BOOLEAN DEFAULT FALSE,
    ai_confidence DECIMAL(3,2) DEFAULT 0.0,
    
    -- ИИ-анализ результатов
    ai_keywords_found TEXT[],
    ai_categories TEXT[],
    ai_reasoning TEXT,
    has_kev BOOLEAN DEFAULT FALSE,
    has_cert_alerts BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS user_vulnerability_assignments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    assigned_by INTEGER REFERENCES users(id),
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) CHECK (status IN ('pending', 'in_progress', 'completed', 'rejected')) DEFAULT 'pending',
    due_date TIMESTAMP,
    completed_at TIMESTAMP,
    notes TEXT,
    UNIQUE(user_id, vulnerability_id)
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================
-- ТАБЛИЦЫ ДЛЯ LEGACY SCHEMA
-- ============================================

CREATE TABLE IF NOT EXISTS turn (
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
    status BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS cvelist (
    cve TEXT PRIMARY KEY,
    ff_eng TEXT,
    ff_rus TEXT
);

CREATE TABLE IF NOT EXISTS cwelist (
    cwe TEXT PRIMARY KEY,
    interpretation TEXT,
    wayexploitation TEXT
);

CREATE TABLE IF NOT EXISTS map_table (
    cve TEXT PRIMARY KEY,
    cvss TEXT,
    cwe TEXT,
    exploit BOOLEAN DEFAULT FALSE,
    patch BOOLEAN DEFAULT FALSE,
    attack_compl TEXT
);

CREATE TABLE IF NOT EXISTS operators_legacy (
    operator TEXT PRIMARY KEY,
    level REAL DEFAULT 50.0
);

CREATE TABLE IF NOT EXISTS actids (
    cve TEXT,
    uid UUID DEFAULT uuid_generate_v4(),
    active BOOLEAN DEFAULT TRUE,
    oper TEXT,
    PRIMARY KEY (cve, oper)
);

-- Таблица истории парсинга (parsing_history)
CREATE TABLE IF NOT EXISTS parsing_history (
    id SERIAL PRIMARY KEY,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sources TEXT[],
    total_parsed INTEGER DEFAULT 0,
    total_saved INTEGER DEFAULT 0,
    total_errors INTEGER DEFAULT 0,
    by_source JSONB,
    settings JSONB,
    status VARCHAR(50) DEFAULT 'completed',
    error_message TEXT,
    duration_seconds INTEGER
);

CREATE INDEX IF NOT EXISTS idx_parsing_history_scan_date ON parsing_history(scan_date DESC);

-- ============================================
-- ТАБЛИЦЫ ДЛЯ ИИ-СИСТЕМЫ
-- ============================================

-- Результаты ИИ-анализа
CREATE TABLE IF NOT EXISTS ai_analysis_results (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES turn(id),
    is_ai_related BOOLEAN,
    confidence FLOAT,
    keywords_found TEXT[],
    categories TEXT[],
    reasoning TEXT,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    model_version VARCHAR(50)
);

-- Ключевые слова для обучения
CREATE TABLE IF NOT EXISTS ai_keywords (
    id SERIAL PRIMARY KEY,
    keyword TEXT UNIQUE NOT NULL,
    category VARCHAR(50),
    weight FLOAT DEFAULT 1.0,
    source VARCHAR(50) DEFAULT 'manual', -- 'manual', 'learned', 'extracted'
    usage_count INTEGER DEFAULT 0,
    accuracy FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Данные для обучения модели
CREATE TABLE IF NOT EXISTS ai_training_data (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES turn(id),
    is_ai_related BOOLEAN NOT NULL,
    confirmed_by INTEGER REFERENCES users(id),
    confirmed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    context_text TEXT,
    extracted_keywords TEXT[],
    used_for_training BOOLEAN DEFAULT FALSE
);

-- Мониторинг сайтов
CREATE TABLE IF NOT EXISTS ai_monitoring_sites (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    site_name VARCHAR(255),
    parser_config JSONB,
    enabled BOOLEAN DEFAULT TRUE,
    last_check TIMESTAMP,
    check_interval INTEGER DEFAULT 3600, -- секунды
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Паспорта уязвимостей
CREATE TABLE IF NOT EXISTS ai_vulnerability_passports (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES turn(id) UNIQUE,
    passport_data JSONB NOT NULL,
    generated_by_ai BOOLEAN DEFAULT TRUE,
    model_version VARCHAR(50),
    confidence FLOAT,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Метрики модели
CREATE TABLE IF NOT EXISTS ai_model_metrics (
    id SERIAL PRIMARY KEY,
    model_name VARCHAR(100),
    model_version VARCHAR(50),
    accuracy FLOAT,
    precision FLOAT,
    recall FLOAT,
    f1_score FLOAT,
    training_samples INTEGER,
    trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для ИИ-таблиц
CREATE INDEX IF NOT EXISTS idx_ai_analysis_vuln ON ai_analysis_results(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_ai_analysis_ai_related ON ai_analysis_results(is_ai_related);
CREATE INDEX IF NOT EXISTS idx_ai_keywords_category ON ai_keywords(category);
CREATE INDEX IF NOT EXISTS idx_ai_training_vuln ON ai_training_data(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_ai_training_used ON ai_training_data(used_for_training);
CREATE INDEX IF NOT EXISTS idx_ai_monitoring_enabled ON ai_monitoring_sites(enabled);
CREATE INDEX IF NOT EXISTS idx_ai_passports_vuln ON ai_vulnerability_passports(vulnerability_id);

-- ============================================
-- ИНДЕКСЫ
-- ============================================

-- Индексы для users
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Индексы для vulnerabilities
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source ON vulnerabilities(source_identifier);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_assigned_operator ON vulnerabilities(assigned_operator);

-- Индексы для operators
CREATE INDEX IF NOT EXISTS idx_operators_email ON operators(email);

-- Индексы для assignments
CREATE INDEX IF NOT EXISTS idx_assignments_user ON user_vulnerability_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_assignments_vuln ON user_vulnerability_assignments(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_assignments_status ON user_vulnerability_assignments(status);

-- Индексы для login_attempts
CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_at ON login_attempts(attempted_at);

-- Индексы для legacy таблиц
CREATE INDEX IF NOT EXISTS idx_turn_cve ON turn(cve);
CREATE INDEX IF NOT EXISTS idx_turn_status ON turn(status);
CREATE INDEX IF NOT EXISTS idx_cvelist_cve ON cvelist(cve);
CREATE INDEX IF NOT EXISTS idx_map_table_cve ON map_table(cve);
CREATE INDEX IF NOT EXISTS idx_actids_cve ON actids(cve);
CREATE INDEX IF NOT EXISTS idx_actids_oper ON actids(oper);

-- ============================================
-- НАЧАЛЬНЫЕ ДАННЫЕ (опционально)
-- ============================================

-- Создание администратора по умолчанию (пароль: admin123)
-- Хеш пароля должен быть сгенерирован через bcrypt
-- INSERT INTO users (username, email, password_hash, role, full_name) 
-- VALUES ('admin', 'admin@example.com', '$2b$12$...', 'admin', 'Administrator')
-- ON CONFLICT (email) DO NOTHING;

