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

