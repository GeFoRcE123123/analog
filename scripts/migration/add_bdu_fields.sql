-- =====================================================
-- Миграция БД: Добавление полей БДУ ФСТЭК
-- =====================================================
-- Дата: 2026-01-22
-- Описание: Добавление структурированных полей для поддержки
--           паспорта уязвимости БДУ ФСТЭК
-- Версия: 1.0
-- =====================================================

-- Начало транзакции
BEGIN;

-- =====================================================
-- БЛОК 1: Идентификация БДУ
-- =====================================================
ALTER TABLE vulnerabilities 
    ADD COLUMN IF NOT EXISTS bdu_id VARCHAR(50),
    ADD COLUMN IF NOT EXISTS bdu_published_date TIMESTAMP,
    ADD COLUMN IF NOT EXISTS bdu_status VARCHAR(100);

-- =====================================================
-- БЛОК 2: Информация о программном обеспечении
-- =====================================================
ALTER TABLE vulnerabilities 
    ADD COLUMN IF NOT EXISTS vendor VARCHAR(255),
    ADD COLUMN IF NOT EXISTS product_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS affected_versions TEXT,
    ADD COLUMN IF NOT EXISTS software_type VARCHAR(100),
    ADD COLUMN IF NOT EXISTS operating_systems TEXT[],
    ADD COLUMN IF NOT EXISTS hardware_platforms TEXT[];

-- =====================================================
-- БЛОК 3: Техническая информация
-- =====================================================
ALTER TABLE vulnerabilities 
    ADD COLUMN IF NOT EXISTS date_discovered DATE,
    ADD COLUMN IF NOT EXISTS vulnerability_class VARCHAR(100),
    ADD COLUMN IF NOT EXISTS error_type_russian TEXT;

-- =====================================================
-- БЛОК 4: Эксплуатация уязвимости
-- =====================================================
ALTER TABLE vulnerabilities 
    ADD COLUMN IF NOT EXISTS exploit_available BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS exploit_type VARCHAR(50),
    ADD COLUMN IF NOT EXISTS exploitation_method TEXT;

-- =====================================================
-- БЛОК 5: Устранение уязвимости
-- =====================================================
ALTER TABLE vulnerabilities 
    ADD COLUMN IF NOT EXISTS remediation_method VARCHAR(100),
    ADD COLUMN IF NOT EXISTS remediation_info TEXT,
    ADD COLUMN IF NOT EXISTS remediation_date DATE;

-- =====================================================
-- БЛОК 6: Дополнительные данные
-- =====================================================
ALTER TABLE vulnerabilities 
    ADD COLUMN IF NOT EXISTS bdu_raw_data JSONB;

-- =====================================================
-- ИНДЕКСЫ: Оптимизация поиска
-- =====================================================

-- Уникальный индекс для BDU ID
CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerabilities_bdu_id_unique 
    ON vulnerabilities(bdu_id) 
    WHERE bdu_id IS NOT NULL;

-- Индекс для поиска по вендору
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vendor 
    ON vulnerabilities(vendor) 
    WHERE vendor IS NOT NULL;

-- Индекс для поиска по продукту
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_product 
    ON vulnerabilities(product_name) 
    WHERE product_name IS NOT NULL;

-- Индекс для фильтра по эксплойтам
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_exploit_available 
    ON vulnerabilities(exploit_available) 
    WHERE exploit_available = TRUE;

-- Индекс для поиска по дате выявления
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_date_discovered 
    ON vulnerabilities(date_discovered) 
    WHERE date_discovered IS NOT NULL;

-- Индекс для поиска по типу ПО
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_software_type 
    ON vulnerabilities(software_type) 
    WHERE software_type IS NOT NULL;

-- GIN индекс для массива ОС (для быстрого поиска по элементам массива)
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_os_gin 
    ON vulnerabilities USING GIN(operating_systems) 
    WHERE operating_systems IS NOT NULL;

-- GIN индекс для массива платформ
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_platforms_gin 
    ON vulnerabilities USING GIN(hardware_platforms) 
    WHERE hardware_platforms IS NOT NULL;

-- Составной индекс для частых запросов
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vendor_exploit 
    ON vulnerabilities(vendor, exploit_available) 
    WHERE vendor IS NOT NULL;

-- =====================================================
-- КОММЕНТАРИИ К ПОЛЯМ (документация схемы)
-- =====================================================

COMMENT ON COLUMN vulnerabilities.bdu_id IS 
    'Идентификатор БДУ ФСТЭК (формат: BDU:YYYY-XXXXX)';

COMMENT ON COLUMN vulnerabilities.bdu_published_date IS 
    'Дата публикации записи в БДУ ФСТЭК';

COMMENT ON COLUMN vulnerabilities.bdu_status IS 
    'Статус уязвимости по данным БДУ (подтверждена производителем / не подтверждена)';

COMMENT ON COLUMN vulnerabilities.vendor IS 
    'Производитель/разработчик уязвимого программного обеспечения';

COMMENT ON COLUMN vulnerabilities.product_name IS 
    'Название уязвимого программного продукта';

COMMENT ON COLUMN vulnerabilities.affected_versions IS 
    'Затронутые версии программного обеспечения';

COMMENT ON COLUMN vulnerabilities.software_type IS 
    'Тип программного обеспечения (прикладное, системное, микропрограммное)';

COMMENT ON COLUMN vulnerabilities.operating_systems IS 
    'Массив поддерживаемых операционных систем';

COMMENT ON COLUMN vulnerabilities.hardware_platforms IS 
    'Массив аппаратных платформ (x86, ARM, и т.д.)';

COMMENT ON COLUMN vulnerabilities.date_discovered IS 
    'Дата выявления уязвимости (отличается от created_date - даты добавления в систему)';

COMMENT ON COLUMN vulnerabilities.vulnerability_class IS 
    'Класс уязвимости (уязвимость кода, конфигурации и т.д.)';

COMMENT ON COLUMN vulnerabilities.error_type_russian IS 
    'Тип ошибки на русском языке (из БДУ ФСТЭК)';

COMMENT ON COLUMN vulnerabilities.exploit_available IS 
    'Доступен ли публичный эксплойт для данной уязвимости (критичный индикатор)';

COMMENT ON COLUMN vulnerabilities.exploit_type IS 
    'Тип эксплуатации: remote (удаленная), local (локальная), physical (физический доступ)';

COMMENT ON COLUMN vulnerabilities.exploitation_method IS 
    'Описание способа эксплуатации уязвимости';

COMMENT ON COLUMN vulnerabilities.remediation_method IS 
    'Способ устранения (обновление ПО, изменение конфигурации и т.д.)';

COMMENT ON COLUMN vulnerabilities.remediation_info IS 
    'Детальная информация об устранении уязвимости, ссылки на патчи';

COMMENT ON COLUMN vulnerabilities.remediation_date IS 
    'Дата устранения уязвимости производителем';

COMMENT ON COLUMN vulnerabilities.bdu_raw_data IS 
    'Полные необработанные данные из БДУ ФСТЭК в формате JSON (для архива)';

-- =====================================================
-- ПРОВЕРКА ДАННЫХ: Check constraints
-- =====================================================

-- Формат BDU ID должен соответствовать паттерну BDU:YYYY-XXXXX
ALTER TABLE vulnerabilities 
    ADD CONSTRAINT check_bdu_id_format 
    CHECK (bdu_id IS NULL OR bdu_id ~ '^BDU:\d{4}-\d{5,6}$');

-- Тип эксплуатации - только допустимые значения
ALTER TABLE vulnerabilities 
    ADD CONSTRAINT check_exploit_type 
    CHECK (exploit_type IS NULL OR exploit_type IN ('remote', 'local', 'physical', 'network'));

-- Дата выявления не может быть в будущем
ALTER TABLE vulnerabilities 
    ADD CONSTRAINT check_date_discovered 
    CHECK (date_discovered IS NULL OR date_discovered <= CURRENT_DATE);

-- Дата устранения не может быть раньше даты выявления
ALTER TABLE vulnerabilities 
    ADD CONSTRAINT check_remediation_date 
    CHECK (remediation_date IS NULL OR date_discovered IS NULL OR remediation_date >= date_discovered);

-- =====================================================
-- ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ
-- =====================================================

-- Обновление статистики для оптимизатора запросов
ANALYZE vulnerabilities;

-- Логирование миграции
DO $$
BEGIN
    RAISE NOTICE '✅ Миграция БДУ ФСТЭК успешно завершена';
    RAISE NOTICE '📊 Добавлено полей: 17';
    RAISE NOTICE '🔍 Создано индексов: 10';
    RAISE NOTICE '✓ Check constraints: 4';
    RAISE NOTICE '📅 Дата миграции: %', NOW();
END $$;

-- Завершение транзакции
COMMIT;

-- =====================================================
-- ОТКАТ МИГРАЦИИ (если нужно вернуться назад)
-- =====================================================
-- Раскомментируйте следующие строки для отката:

/*
BEGIN;

-- Удаление индексов
DROP INDEX IF EXISTS idx_vulnerabilities_bdu_id_unique;
DROP INDEX IF EXISTS idx_vulnerabilities_vendor;
DROP INDEX IF EXISTS idx_vulnerabilities_product;
DROP INDEX IF EXISTS idx_vulnerabilities_exploit_available;
DROP INDEX IF EXISTS idx_vulnerabilities_date_discovered;
DROP INDEX IF EXISTS idx_vulnerabilities_software_type;
DROP INDEX IF EXISTS idx_vulnerabilities_os_gin;
DROP INDEX IF EXISTS idx_vulnerabilities_platforms_gin;
DROP INDEX IF EXISTS idx_vulnerabilities_vendor_exploit;

-- Удаление constraints
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS check_bdu_id_format;
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS check_exploit_type;
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS check_date_discovered;
ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS check_remediation_date;

-- Удаление полей
ALTER TABLE vulnerabilities 
    DROP COLUMN IF EXISTS bdu_id,
    DROP COLUMN IF EXISTS bdu_published_date,
    DROP COLUMN IF EXISTS bdu_status,
    DROP COLUMN IF EXISTS vendor,
    DROP COLUMN IF EXISTS product_name,
    DROP COLUMN IF EXISTS affected_versions,
    DROP COLUMN IF EXISTS software_type,
    DROP COLUMN IF EXISTS operating_systems,
    DROP COLUMN IF EXISTS hardware_platforms,
    DROP COLUMN IF EXISTS date_discovered,
    DROP COLUMN IF EXISTS vulnerability_class,
    DROP COLUMN IF EXISTS error_type_russian,
    DROP COLUMN IF EXISTS exploit_available,
    DROP COLUMN IF EXISTS exploit_type,
    DROP COLUMN IF EXISTS exploitation_method,
    DROP COLUMN IF EXISTS remediation_method,
    DROP COLUMN IF EXISTS remediation_info,
    DROP COLUMN IF EXISTS remediation_date,
    DROP COLUMN IF EXISTS bdu_raw_data;

COMMIT;

-- Логирование отката
DO $$
BEGIN
    RAISE NOTICE '⚠️  Миграция БДУ ФСТЭК откачена';
    RAISE NOTICE '📅 Дата отката: %', NOW();
END $$;
*/

-- =====================================================
-- СТАТИСТИКА ПО МИГРАЦИИ
-- =====================================================

-- Проверка количества записей с БДУ данными (после заполнения)
-- SELECT 
--     COUNT(*) as total_vulnerabilities,
--     COUNT(bdu_id) as with_bdu_id,
--     COUNT(vendor) as with_vendor,
--     COUNT(CASE WHEN exploit_available = TRUE THEN 1 END) as with_exploit
-- FROM vulnerabilities;

-- =====================================================
-- КОНЕЦ МИГРАЦИИ
-- =====================================================

