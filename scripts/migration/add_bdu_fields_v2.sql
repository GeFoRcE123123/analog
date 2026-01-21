-- ============================================
-- МИГРАЦИЯ: Добавление полей БДУ ФСТЭК
-- Версия: 2.0 (на основе реального XML БДУ)
-- Дата: 2026-01-22
-- Описание: Добавление 20+ полей для хранения данных БДУ
-- ============================================

BEGIN;

-- ============================================
-- 1. ИДЕНТИФИКАЦИЯ (BDU Identification)
-- ============================================

-- BDU ID (уникальный идентификатор БДУ)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_id VARCHAR(50) UNIQUE;

-- Название уязвимости из БДУ
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_name TEXT;

-- ============================================
-- 2. ИНФОРМАЦИЯ О ПО (Vulnerable Software)
-- ============================================

-- Вендор ПО
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vendor VARCHAR(300);

-- Название продукта
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS product_name VARCHAR(300);

-- Версия ПО (уязвимая)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS affected_versions TEXT;

-- Платформа (32-bit, 64-bit, etc.)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS platform VARCHAR(100);

-- Тип ПО (JSONB для множественных типов)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS software_types JSONB;

-- Регистрационный номер
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS registry_number VARCHAR(100);

-- Полная структура vulnerable_software из XML (JSONB)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vulnerable_software JSONB;

-- ============================================
-- 3. ОКРУЖЕНИЕ (Environment)
-- ============================================

-- Операционная система (JSONB для множественных ОС)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS environment JSONB;

-- ============================================
-- 4. ТЕХНИЧЕСКИЕ ДЕТАЛИ (Technical Details)
-- ============================================

-- CWE классификация (JSONB массив)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cwes JSONB;

-- Класс уязвимости (из БДУ)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vul_class VARCHAR(200);

-- Служебные операционные процессы (опционально)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS sl_oper_procs JSONB;

-- ============================================
-- 5. ДАТЫ (Dates)
-- ============================================

-- Дата обнаружения
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS identify_date DATE;

-- Дата публикации в БДУ
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS publication_date DATE;

-- Дата последнего обновления в БДУ
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS last_upd_date DATE;

-- ============================================
-- 6. ОЦЕНКА РИСКОВ (Risk Assessment)
-- ============================================

-- CVSS 2.0 (структура)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss2_vector VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss2_score DECIMAL(3,1);

-- CVSS 3.0 (структура)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss3_vector VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cvss3_score DECIMAL(3,1);

-- Уровень опасности (текстовое описание из БДУ)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_severity TEXT;

-- ============================================
-- 7. СТАТУСЫ И УСТРАНЕНИЕ (Status & Remediation)
-- ============================================

-- Статус уязвимости (подтверждена производителем и т.д.)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vul_status VARCHAR(200);

-- Наличие эксплоита
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS exploit_status VARCHAR(200);

-- Статус устранения
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS fix_status VARCHAR(200);

-- Решение/способ устранения
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS solution TEXT;

-- ============================================
-- 8. ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ (Additional Info)
-- ============================================

-- Источники (массив)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS sources TEXT;

-- Другие идентификаторы (JSONB с CVE, OSVDB, Bugtraq и т.д.)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS other_identifiers JSONB;

-- Информация об инциденте
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vul_incident VARCHAR(200);

-- Состояние уязвимости
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vul_state VARCHAR(100);

-- Способ устранения (категория)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vul_elimination VARCHAR(200);

-- ============================================
-- 9. ИНДЕКСЫ ДЛЯ ОПТИМИЗАЦИИ (Indexes)
-- ============================================

-- Индекс по BDU ID
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_bdu_id ON vulnerabilities(bdu_id);

-- Индекс по вендору
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vendor ON vulnerabilities(vendor);

-- Индекс по продукту
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_product_name ON vulnerabilities(product_name);

-- Индекс по статусу эксплоита
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_exploit_status ON vulnerabilities(exploit_status);

-- Индекс по дате публикации БДУ
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_publication_date ON vulnerabilities(publication_date);

-- Индекс по классу уязвимости
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vul_class ON vulnerabilities(vul_class);

-- GIN индекс для JSONB полей (быстрый поиск)
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cwes_gin ON vulnerabilities USING GIN (cwes);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vulnerable_software_gin ON vulnerabilities USING GIN (vulnerable_software);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_environment_gin ON vulnerabilities USING GIN (environment);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_other_identifiers_gin ON vulnerabilities USING GIN (other_identifiers);

-- Составной индекс для частых запросов
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vendor_product ON vulnerabilities(vendor, product_name);

-- ============================================
-- 10. ПРОВЕРКИ (Constraints)
-- ============================================

-- CVSS 2.0 score должен быть от 0 до 10
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'check_cvss2_score') THEN
        ALTER TABLE vulnerabilities ADD CONSTRAINT check_cvss2_score 
            CHECK (cvss2_score IS NULL OR (cvss2_score >= 0 AND cvss2_score <= 10));
    END IF;
END $$;

-- CVSS 3.0 score должен быть от 0 до 10
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'check_cvss3_score') THEN
        ALTER TABLE vulnerabilities ADD CONSTRAINT check_cvss3_score 
            CHECK (cvss3_score IS NULL OR (cvss3_score >= 0 AND cvss3_score <= 10));
    END IF;
END $$;

-- ============================================
-- 11. КОММЕНТАРИИ ДЛЯ ПОЛЕЙ (Documentation)
-- ============================================

COMMENT ON COLUMN vulnerabilities.bdu_id IS 'Уникальный идентификатор БДУ (например, BDU:2026-00669)';
COMMENT ON COLUMN vulnerabilities.bdu_name IS 'Название уязвимости из БДУ ФСТЭК';
COMMENT ON COLUMN vulnerabilities.vendor IS 'Вендор уязвимого ПО';
COMMENT ON COLUMN vulnerabilities.product_name IS 'Название уязвимого продукта';
COMMENT ON COLUMN vulnerabilities.affected_versions IS 'Уязвимые версии ПО';
COMMENT ON COLUMN vulnerabilities.platform IS 'Платформа (32-bit, 64-bit, ARM и т.д.)';
COMMENT ON COLUMN vulnerabilities.software_types IS 'JSONB массив типов ПО';
COMMENT ON COLUMN vulnerabilities.registry_number IS 'Регистрационный номер в реестре';
COMMENT ON COLUMN vulnerabilities.vulnerable_software IS 'JSONB полная структура vulnerable_software из БДУ';
COMMENT ON COLUMN vulnerabilities.environment IS 'JSONB информация об окружении (ОС)';
COMMENT ON COLUMN vulnerabilities.cwes IS 'JSONB массив CWE классификаций';
COMMENT ON COLUMN vulnerabilities.vul_class IS 'Класс уязвимости (Уязвимость кода, Уязвимость архитектуры и т.д.)';
COMMENT ON COLUMN vulnerabilities.identify_date IS 'Дата обнаружения уязвимости';
COMMENT ON COLUMN vulnerabilities.publication_date IS 'Дата публикации в БДУ ФСТЭК';
COMMENT ON COLUMN vulnerabilities.last_upd_date IS 'Дата последнего обновления в БДУ';
COMMENT ON COLUMN vulnerabilities.cvss2_vector IS 'CVSS 2.0 вектор атаки';
COMMENT ON COLUMN vulnerabilities.cvss2_score IS 'CVSS 2.0 оценка (0-10)';
COMMENT ON COLUMN vulnerabilities.cvss3_vector IS 'CVSS 3.0 вектор атаки';
COMMENT ON COLUMN vulnerabilities.cvss3_score IS 'CVSS 3.0 оценка (0-10)';
COMMENT ON COLUMN vulnerabilities.bdu_severity IS 'Уровень опасности (текстовое описание из БДУ)';
COMMENT ON COLUMN vulnerabilities.vul_status IS 'Статус уязвимости (Подтверждена производителем и т.д.)';
COMMENT ON COLUMN vulnerabilities.exploit_status IS 'Наличие эксплоита (Существует, Данные уточняются и т.д.)';
COMMENT ON COLUMN vulnerabilities.fix_status IS 'Статус устранения (Уязвимость устранена, Информация отсутствует и т.д.)';
COMMENT ON COLUMN vulnerabilities.solution IS 'Способ устранения уязвимости';
COMMENT ON COLUMN vulnerabilities.sources IS 'Источники информации об уязвимости';
COMMENT ON COLUMN vulnerabilities.other_identifiers IS 'JSONB других идентификаторов (CVE, OSVDB, Bugtraq и т.д.)';
COMMENT ON COLUMN vulnerabilities.vul_incident IS 'Информация об инциденте';
COMMENT ON COLUMN vulnerabilities.vul_state IS 'Состояние уязвимости (Опубликована и т.д.)';
COMMENT ON COLUMN vulnerabilities.vul_elimination IS 'Способ устранения (категория)';

-- ============================================
-- 12. СТАТИСТИКА ПО ДОБАВЛЕННЫМ ПОЛЯМ
-- ============================================

DO $$
DECLARE
    total_count INTEGER;
    bdu_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO total_count FROM vulnerabilities;
    SELECT COUNT(*) INTO bdu_count FROM vulnerabilities WHERE bdu_id IS NOT NULL;
    
    RAISE NOTICE '✅ Миграция завершена успешно!';
    RAISE NOTICE '📊 Всего записей в БД: %', total_count;
    RAISE NOTICE '📊 Записей с BDU ID: %', bdu_count;
    RAISE NOTICE '📊 Добавлено 30+ новых полей для БДУ ФСТЭК';
    RAISE NOTICE '📊 Создано 11 индексов для оптимизации';
END $$;

COMMIT;

