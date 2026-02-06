-- ============================================
-- НОВАЯ СХЕМА БД - ОПТИМИЗИРОВАННАЯ ВЕРСИЯ
-- ============================================

-- Таблица операторов (operators)
CREATE TABLE IF NOT EXISTS operators (
    operator TEXT PRIMARY KEY,
    level REAL DEFAULT 50.0
);

-- Таблица пользователей (users_log)
CREATE TABLE IF NOT EXISTS users_log (
    name TEXT PRIMARY KEY,
    pass TEXT NOT NULL,
    last_date TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Основная таблица уязвимостей (turn)
CREATE TABLE IF NOT EXISTS turn (
    id SERIAL PRIMARY KEY,
    source TEXT,
    link TEXT,
    cve TEXT UNIQUE,
    joining_date TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    name TEXT,
    cvss REAL DEFAULT 0.0,
    price_one REAL DEFAULT 0.0,
    priority REAL DEFAULT 0.0,
    start_date TIMESTAMP WITHOUT TIME ZONE,
    end_date TIMESTAMP WITHOUT TIME ZONE,
    etc TEXT,
    status BOOLEAN DEFAULT FALSE
);

-- Таблица активных уязвимостей (actids)
CREATE TABLE IF NOT EXISTS actids (
    cve TEXT PRIMARY KEY,
    uid UUID DEFAULT gen_random_uuid(),
    active BOOLEAN DEFAULT TRUE,
    oper TEXT
);

-- Таблица CVE списка (cvelist)
CREATE TABLE IF NOT EXISTS cvelist (
    cve TEXT PRIMARY KEY,
    ff_eng TEXT,
    ff_rus TEXT
);

-- Таблица CWE списка (cwelist)
CREATE TABLE IF NOT EXISTS cwelist (
    cwe TEXT PRIMARY KEY,
    interpretation TEXT,
    wayexploitation TEXT
);

-- Таблица связей CPE с BDU (cpe_to_bdu)
CREATE TABLE IF NOT EXISTS cpe_to_bdu (
    cpe TEXT,
    bdu TEXT,
    PRIMARY KEY (cpe, bdu)
);

-- Таблица компонентов (complist)
CREATE TABLE IF NOT EXISTS complist (
    comp_eng TEXT PRIMARY KEY,
    comp_rus TEXT
);

-- Альтернативная таблица компонентов (complist_)
CREATE TABLE IF NOT EXISTS complist_ (
    comp_eng TEXT PRIMARY KEY,
    comp_rus TEXT
);

-- Таблица программного обеспечения (softlist)
CREATE TABLE IF NOT EXISTS softlist (
    soft TEXT PRIMARY KEY,
    description TEXT
);

-- Таблица векторов атаки (vialist)
CREATE TABLE IF NOT EXISTS vialist (
    via TEXT PRIMARY KEY,
    interpretation TEXT
);

-- Альтернативная таблица векторов (vialist_)
CREATE TABLE IF NOT EXISTS vialist_ (
    via TEXT PRIMARY KEY
);

-- Таблица словаря (dictionary)
CREATE TABLE IF NOT EXISTS dictionary (
    word TEXT PRIMARY KEY,
    price REAL DEFAULT 0.0
);

-- Облегченный словарь (dictionary_lights)
CREATE TABLE IF NOT EXISTS dictionary_lights (
    word TEXT PRIMARY KEY,
    price REAL DEFAULT 0.0
);

-- Таблица тегов (tags)
CREATE TABLE IF NOT EXISTS tags (
    tag TEXT PRIMARY KEY,
    tagprice REAL DEFAULT 0.0
);

-- Таблица связей тегов с CVE (tagcve)
CREATE TABLE IF NOT EXISTS tagcve (
    tag TEXT REFERENCES tags(tag) ON DELETE CASCADE,
    cve TEXT,
    PRIMARY KEY (tag, cve)
);

-- Таблица словосочетаний (wordlist)
CREATE TABLE IF NOT EXISTS wordlist (
    collocation TEXT PRIMARY KEY,
    interpretation TEXT
);

-- Таблица маппинга (map_table)
CREATE TABLE IF NOT EXISTS map_table (
    cve TEXT PRIMARY KEY,
    cvss TEXT,
    cwe TEXT,
    exploit BOOLEAN DEFAULT FALSE,
    patch BOOLEAN DEFAULT FALSE,
    attack_compl TEXT
);

-- Таблица маппинга CVE к программам (map_table_cve)
CREATE TABLE IF NOT EXISTS map_table_cve (
    cve TEXT,
    name_po TEXT,
    PRIMARY KEY (cve, name_po)
);

-- Альтернативная таблица маппинга CVE (map_table_cve_2)
CREATE TABLE IF NOT EXISTS map_table_cve_2 (
    cve TEXT,
    name_po TEXT,
    PRIMARY KEY (cve, name_po)
);

-- ============================================
-- ИНДЕКСЫ ДЛЯ ОПТИМИЗАЦИИ
-- ============================================

CREATE INDEX IF NOT EXISTS idx_turn_cve ON turn(cve);
CREATE INDEX IF NOT EXISTS idx_turn_source ON turn(source);
CREATE INDEX IF NOT EXISTS idx_turn_status ON turn(status);
CREATE INDEX IF NOT EXISTS idx_turn_cvss ON turn(cvss);
CREATE INDEX IF NOT EXISTS idx_turn_joining_date ON turn(joining_date);

CREATE INDEX IF NOT EXISTS idx_actids_oper ON actids(oper);
CREATE INDEX IF NOT EXISTS idx_actids_active ON actids(active);

CREATE INDEX IF NOT EXISTS idx_map_table_cvss ON map_table(cvss);
CREATE INDEX IF NOT EXISTS idx_map_table_cwe ON map_table(cwe);
CREATE INDEX IF NOT EXISTS idx_map_table_exploit ON map_table(exploit);

CREATE INDEX IF NOT EXISTS idx_tagcve_cve ON tagcve(cve);
CREATE INDEX IF NOT EXISTS idx_tagcve_tag ON tagcve(tag);

-- ============================================
-- ВРЕМЕННАЯ ТАБЛИЦА ДЛЯ МИГРАЦИИ СТАРЫХ ДАННЫХ
-- ============================================

-- Создаем временную таблицу для хранения старых данных
CREATE TABLE IF NOT EXISTS legacy_vulnerabilities (
    id SERIAL PRIMARY KEY,
    title VARCHAR(500),
    description TEXT,
    severity VARCHAR(50),
    status VARCHAR(50),
    assigned_operator INTEGER,
    created_date TIMESTAMP,
    completed_date TIMESTAMP,
    approved BOOLEAN,
    modifications INTEGER,
    cvss_score DECIMAL(3,1),
    risk_level VARCHAR(50),
    category VARCHAR(100),
    cve_id VARCHAR(50),
    source_identifier VARCHAR(255),
    published TIMESTAMP,
    last_modified TIMESTAMP,
    vuln_status VARCHAR(50),
    descriptions JSONB,
    metrics JSONB,
    weaknesses JSONB,
    configurations JSONB,
    "references" JSONB,
    vendor_comments JSONB,
    is_ai_related BOOLEAN,
    ai_confidence DECIMAL(3,2),
    has_kev BOOLEAN,
    has_cert_alerts BOOLEAN
);

CREATE TABLE IF NOT EXISTS legacy_operators (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200),
    email VARCHAR(200),
    experience_level DECIMAL(5,2),
    current_metric DECIMAL(5,2),
    last_activity TIMESTAMP
);