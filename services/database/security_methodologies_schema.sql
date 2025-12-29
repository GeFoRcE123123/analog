-- ============================================================
-- Схема БД для интеграции методологий безопасности
-- ============================================================

-- Методологии безопасности
CREATE TABLE IF NOT EXISTS security_methodologies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,  -- OSSTMM, NIST SP 800-115, OWASP WSTG, etc.
    version VARCHAR(50),
    description TEXT,
    focus_area VARCHAR(100),  -- operational, web, mobile, compliance
    documentation_url TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Категории тестов в методологиях
CREATE TABLE IF NOT EXISTS methodology_categories (
    id SERIAL PRIMARY KEY,
    methodology_id INTEGER REFERENCES security_methodologies(id) ON DELETE CASCADE,
    category_code VARCHAR(50),  -- WSTG-01, MAS-01, OSSTMM-ISEC, etc.
    category_name VARCHAR(200),
    description TEXT,
    parent_category_id INTEGER REFERENCES methodology_categories(id) ON DELETE SET NULL,
    order_index INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Тесты/чек-листы
CREATE TABLE IF NOT EXISTS security_tests (
    id SERIAL PRIMARY KEY,
    category_id INTEGER REFERENCES methodology_categories(id) ON DELETE CASCADE,
    test_code VARCHAR(50),  -- WSTG-01-001, MAS-01-001, etc.
    test_name VARCHAR(200) NOT NULL,
    description TEXT,
    test_type VARCHAR(50),  -- automated, manual, hybrid
    severity VARCHAR(20),  -- critical, high, medium, low, info
    prerequisites TEXT,
    test_steps JSONB,  -- Массив шагов теста
    expected_results TEXT,
    remediation_guidance TEXT,
    references TEXT[],  -- Ссылки на документацию
    cwe_ids INTEGER[],  -- Связанные CWE коды
    owasp_category VARCHAR(100),  -- OWASP Top 10 категория
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Проекты тестирования
CREATE TABLE IF NOT EXISTS security_test_projects (
    id SERIAL PRIMARY KEY,
    project_name VARCHAR(200) NOT NULL,
    methodology_id INTEGER REFERENCES security_methodologies(id),
    target_type VARCHAR(50),  -- web, mobile, network, infrastructure
    target_description TEXT,
    target_urls TEXT[],  -- Список URL для тестирования
    scope TEXT,
    out_of_scope TEXT,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    status VARCHAR(50) DEFAULT 'planned',  -- planned, in_progress, completed, cancelled
    assigned_to INTEGER REFERENCES users(id),
    created_by INTEGER REFERENCES users(id),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Результаты тестов
CREATE TABLE IF NOT EXISTS security_test_results (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES security_test_projects(id) ON DELETE CASCADE,
    test_id INTEGER REFERENCES security_tests(id),
    status VARCHAR(50) DEFAULT 'not_tested',  -- not_tested, passed, failed, error, skipped, na
    severity VARCHAR(20),  -- actual severity found
    findings TEXT,  -- Описание найденных проблем
    evidence JSONB,  -- Скриншоты, логи, файлы (массив объектов)
    risk_score DECIMAL(3,1),  -- 0.0 - 10.0
    cvss_score DECIMAL(3,1),  -- CVSS оценка если применимо
    remediation_status VARCHAR(50) DEFAULT 'not_started',  -- not_started, in_progress, fixed, verified
    remediation_notes TEXT,
    remediation_priority VARCHAR(20),  -- immediate, high, medium, low
    tested_by INTEGER REFERENCES users(id),
    tested_at TIMESTAMP,
    verified_by INTEGER REFERENCES users(id),
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Связь результатов тестов с уязвимостями
CREATE TABLE IF NOT EXISTS test_result_vulnerabilities (
    id SERIAL PRIMARY KEY,
    test_result_id INTEGER REFERENCES security_test_results(id) ON DELETE CASCADE,
    vulnerability_id INTEGER REFERENCES turn(id) ON DELETE CASCADE,
    relationship_type VARCHAR(50),  -- found_by, related_to, duplicate_of
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(test_result_id, vulnerability_id)
);

-- Шаблоны отчетов
CREATE TABLE IF NOT EXISTS security_test_reports (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES security_test_projects(id) ON DELETE CASCADE,
    report_type VARCHAR(50),  -- executive, technical, compliance
    report_format VARCHAR(50),  -- pdf, html, docx, json
    content JSONB,  -- Структурированный контент отчета
    file_path TEXT,  -- Путь к сгенерированному файлу
    generated_by INTEGER REFERENCES users(id),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Метрики и статистика
CREATE TABLE IF NOT EXISTS security_test_metrics (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES security_test_projects(id) ON DELETE CASCADE,
    methodology_id INTEGER REFERENCES security_methodologies(id),
    total_tests INTEGER DEFAULT 0,
    tests_passed INTEGER DEFAULT 0,
    tests_failed INTEGER DEFAULT 0,
    tests_skipped INTEGER DEFAULT 0,
    tests_na INTEGER DEFAULT 0,  -- Not Applicable
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0,
    info_findings INTEGER DEFAULT 0,
    compliance_score DECIMAL(5,2),  -- Процент соответствия (0-100)
    risk_score DECIMAL(3,1),  -- Общий риск (0-10)
    average_cvss DECIMAL(3,1),  -- Средний CVSS
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для производительности
CREATE INDEX IF NOT EXISTS idx_methodology_categories_methodology_id ON methodology_categories(methodology_id);
CREATE INDEX IF NOT EXISTS idx_security_tests_category_id ON security_tests(category_id);
CREATE INDEX IF NOT EXISTS idx_security_test_projects_methodology_id ON security_test_projects(methodology_id);
CREATE INDEX IF NOT EXISTS idx_security_test_projects_status ON security_test_projects(status);
CREATE INDEX IF NOT EXISTS idx_security_test_results_project_id ON security_test_results(project_id);
CREATE INDEX IF NOT EXISTS idx_security_test_results_test_id ON security_test_results(test_id);
CREATE INDEX IF NOT EXISTS idx_security_test_results_status ON security_test_results(status);
CREATE INDEX IF NOT EXISTS idx_test_result_vulnerabilities_test_result_id ON test_result_vulnerabilities(test_result_id);
CREATE INDEX IF NOT EXISTS idx_test_result_vulnerabilities_vulnerability_id ON test_result_vulnerabilities(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_security_test_metrics_project_id ON security_test_metrics(project_id);

-- Триггеры для обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_security_methodologies_updated_at BEFORE UPDATE ON security_methodologies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_tests_updated_at BEFORE UPDATE ON security_tests
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_test_projects_updated_at BEFORE UPDATE ON security_test_projects
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_test_results_updated_at BEFORE UPDATE ON security_test_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

