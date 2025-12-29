# Интеграция методологий безопасности в систему управления уязвимостями

## 📋 Анализ методологий

### 1. OSSTMM (Open Source Security Testing Methodology Manual)
**Фокус**: Операционная безопасность
**Основные этапы**:
- Information Security (ISEC)
- Process Security (PROC)
- Internet Technology Security (ITEC)
- Communications Security (COMS)
- Wireless Security (WLAN)
- Physical Security (PHYS)

**Ключевые рекомендации**:
- Структурированный подход к тестированию
- Метрики безопасности (Ravs - Risk Assessment Values)
- Классификация по типам тестов (Blind, Double Blind, Gray Box, Tandem, Reversal)

### 2. NIST SP 800-115
**Фокус**: Комплексный подход к тестированию безопасности
**Основные этапы**:
- Planning (Планирование)
- Discovery (Обнаружение)
- Attack (Атака)
- Reporting (Отчетность)

**Ключевые рекомендации**:
- Четкое планирование тестов
- Документирование всех этапов
- Оценка рисков
- Рекомендации по устранению

### 3. OWASP WSTG (Web Security Testing Guide)
**Фокус**: Веб-приложения
**Основные категории**:
- Information Gathering (01-06)
- Configuration and Deployment Management Testing (02)
- Identity Management Testing (03)
- Authentication Testing (04)
- Authorization Testing (05)
- Session Management Testing (06)
- Input Validation Testing (07)
- Error Handling (08)
- Cryptography (09)
- Business Logic Testing (10)
- Client Side Testing (11)

**Ключевые рекомендации**:
- Структурированные чек-листы
- Автоматизированное и ручное тестирование
- Приоритизация по рискам

### 4. OWASP MASTG (Mobile Application Security Testing Guide)
**Фокус**: Мобильные приложения
**Основные категории**:
- Mobile App Security (MAS)
- Reverse Engineering (MRE)
- Tampering and Reverse Engineering (MSTG-CODE)
- Cryptography (MSTG-CRYPTO)
- Authentication and Session Management (MSTG-AUTH)
- Network Communication (MSTG-NETWORK)
- Platform Interaction (MSTG-PLATFORM)
- Code Quality and Build Settings (MSTG-CODE)
- Data Storage (MSTG-STORAGE)

**Ключевые рекомендации**:
- Платформо-специфичные тесты (iOS/Android)
- Статический и динамический анализ
- Тестирование API

### 5. PCI DSS Pentest Methodology
**Фокус**: Соответствие PCI DSS требованиям
**Основные требования**:
- Requirement 11.3: Penetration Testing
- Requirement 11.4: Intrusion Detection
- Network Segmentation Testing
- Application Layer Testing
- Network Layer Testing
- Social Engineering Testing

**Ключевые рекомендации**:
- Ежегодное тестирование
- Квалифицированные тестировщики
- Документирование результатов
- Исправление уязвимостей

## 🏗️ Архитектура интеграции

### Структура базы данных

```sql
-- Методологии безопасности
CREATE TABLE security_methodologies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,  -- OSSTMM, NIST SP 800-115, OWASP WSTG, etc.
    version VARCHAR(50),
    description TEXT,
    focus_area VARCHAR(100),  -- operational, web, mobile, compliance
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Категории тестов в методологиях
CREATE TABLE methodology_categories (
    id SERIAL PRIMARY KEY,
    methodology_id INTEGER REFERENCES security_methodologies(id),
    category_code VARCHAR(50),  -- WSTG-01, MAS-01, etc.
    category_name VARCHAR(200),
    description TEXT,
    parent_category_id INTEGER REFERENCES methodology_categories(id),
    order_index INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Тесты/чек-листы
CREATE TABLE security_tests (
    id SERIAL PRIMARY KEY,
    category_id INTEGER REFERENCES methodology_categories(id),
    test_code VARCHAR(50),  -- WSTG-01-001, MAS-01-001, etc.
    test_name VARCHAR(200),
    description TEXT,
    test_type VARCHAR(50),  -- automated, manual, hybrid
    severity VARCHAR(20),  -- critical, high, medium, low, info
    prerequisites TEXT,
    test_steps TEXT[],  -- Массив шагов теста
    expected_results TEXT,
    remediation_guidance TEXT,
    references TEXT[],  -- Ссылки на документацию
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Проекты тестирования
CREATE TABLE security_test_projects (
    id SERIAL PRIMARY KEY,
    project_name VARCHAR(200) NOT NULL,
    methodology_id INTEGER REFERENCES security_methodologies(id),
    target_type VARCHAR(50),  -- web, mobile, network, infrastructure
    target_description TEXT,
    scope TEXT,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    status VARCHAR(50),  -- planned, in_progress, completed, cancelled
    assigned_to INTEGER REFERENCES users(id),
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Результаты тестов
CREATE TABLE security_test_results (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES security_test_projects(id),
    test_id INTEGER REFERENCES security_tests(id),
    status VARCHAR(50),  -- not_tested, passed, failed, error, skipped
    severity VARCHAR(20),  -- actual severity found
    findings TEXT,  -- Описание найденных проблем
    evidence TEXT[],  -- Скриншоты, логи, файлы
    risk_score DECIMAL(3,1),  -- 0.0 - 10.0
    remediation_status VARCHAR(50),  -- not_started, in_progress, fixed, verified
    remediation_notes TEXT,
    tested_by INTEGER REFERENCES users(id),
    tested_at TIMESTAMP,
    verified_by INTEGER REFERENCES users(id),
    verified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Связь результатов тестов с уязвимостями
CREATE TABLE test_result_vulnerabilities (
    id SERIAL PRIMARY KEY,
    test_result_id INTEGER REFERENCES security_test_results(id),
    vulnerability_id INTEGER REFERENCES turn(id),
    relationship_type VARCHAR(50),  -- found_by, related_to, duplicate_of
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Шаблоны отчетов
CREATE TABLE security_test_reports (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES security_test_projects(id),
    report_type VARCHAR(50),  -- executive, technical, compliance
    report_format VARCHAR(50),  -- pdf, html, docx
    content JSONB,  -- Структурированный контент отчета
    generated_by INTEGER REFERENCES users(id),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Метрики и статистика
CREATE TABLE security_test_metrics (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES security_test_projects(id),
    methodology_id INTEGER REFERENCES security_methodologies(id),
    total_tests INTEGER DEFAULT 0,
    tests_passed INTEGER DEFAULT 0,
    tests_failed INTEGER DEFAULT 0,
    tests_skipped INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0,
    info_findings INTEGER DEFAULT 0,
    compliance_score DECIMAL(5,2),  -- Процент соответствия
    risk_score DECIMAL(3,1),  -- Общий риск
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🔧 Компоненты системы

### 1. Сервис методологий (`services/security_methodology_service.py`)
- Загрузка методологий из конфигурации
- Управление категориями и тестами
- Валидация тестов

### 2. Сервис тестирования (`services/security_testing_service.py`)
- Создание проектов тестирования
- Выполнение тестов
- Сбор результатов
- Генерация отчетов

### 3. Сервис соответствия (`services/compliance_service.py`)
- Проверка соответствия стандартам
- Расчет метрик соответствия
- Генерация compliance отчетов

### 4. Интеграция с уязвимостями
- Автоматическое создание уязвимостей из результатов тестов
- Связывание тестов с существующими уязвимостями
- Приоритизация на основе результатов тестов

## 📊 UI компоненты

### 1. Страница методологий (`/security/methodologies`)
- Список доступных методологий
- Просмотр категорий и тестов
- Фильтрация и поиск

### 2. Страница проектов (`/security/projects`)
- Список проектов тестирования
- Создание нового проекта
- Управление проектами

### 3. Страница тестов (`/security/tests`)
- Выполнение тестов
- Просмотр результатов
- Управление статусами

### 4. Страница отчетов (`/security/reports`)
- Генерация отчетов
- Просмотр истории отчетов
- Экспорт отчетов

### 5. Dashboard соответствия (`/security/compliance`)
- Метрики соответствия
- Графики и статистика
- Тренды

## 🔗 API Endpoints

```
GET    /api/security/methodologies              - Список методологий
GET    /api/security/methodologies/:id          - Детали методологии
GET    /api/security/methodologies/:id/categories - Категории методологии
GET    /api/security/methodologies/:id/tests     - Тесты методологии

GET    /api/security/projects                    - Список проектов
POST   /api/security/projects                    - Создать проект
GET    /api/security/projects/:id                - Детали проекта
PUT    /api/security/projects/:id                - Обновить проект
DELETE /api/security/projects/:id                - Удалить проект

GET    /api/security/projects/:id/tests          - Тесты проекта
POST   /api/security/projects/:id/tests/:test_id/execute - Выполнить тест
GET    /api/security/projects/:id/results        - Результаты проекта
POST   /api/security/projects/:id/results        - Сохранить результат

GET    /api/security/projects/:id/reports        - Отчеты проекта
POST   /api/security/projects/:id/reports/generate - Сгенерировать отчет

GET    /api/security/compliance/:project_id       - Метрики соответствия
GET    /api/security/compliance/trends            - Тренды соответствия
```

## 🚀 План внедрения

### Этап 1: Базовая структура (1-2 недели)
1. Создание таблиц БД
2. Базовые сервисы
3. API endpoints
4. Загрузка базовых методологий (OWASP WSTG)

### Этап 2: UI и интеграция (1-2 недели)
1. Страницы управления методологиями
2. Страницы проектов и тестов
3. Интеграция с системой уязвимостей
4. Базовые отчеты

### Этап 3: Расширение методологий (2-3 недели)
1. Загрузка OSSTMM
2. Загрузка NIST SP 800-115
3. Загрузка OWASP MASTG
4. Загрузка PCI DSS

### Этап 4: Автоматизация и отчетность (2-3 недели)
1. Автоматизированные тесты
2. Генерация отчетов
3. Метрики и аналитика
4. Интеграция с CI/CD

## 💡 Ключевые преимущества

1. **Структурированный подход**: Четкая организация тестов по методологиям
2. **Соответствие стандартам**: Автоматическая проверка соответствия
3. **Интеграция**: Связь тестов с системой уязвимостей
4. **Отчетность**: Автоматическая генерация отчетов
5. **Метрики**: Отслеживание прогресса и трендов
6. **Масштабируемость**: Легкое добавление новых методологий

