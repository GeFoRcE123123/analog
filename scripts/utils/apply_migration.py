#!/usr/bin/env python3
"""
Скрипт для применения миграции NVD полей на VM
"""
import psycopg2
import sys

# Параметры подключения к БД
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'vuln_db',
    'user': 'admin',
    'password': '123'
}

MIGRATION_SQL = """
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
"""

INDEXES_SQL = """
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
"""


def apply_migration():
    """Применение миграции"""
    try:
        print("🔌 Подключение к базе данных...")
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        cursor = conn.cursor()
        print("✅ Подключение установлено")
        
        print("\n📝 Добавление колонок...")
        cursor.execute(MIGRATION_SQL)
        print("✅ Колонки добавлены")
        
        print("\n📊 Создание индексов...")
        cursor.execute(INDEXES_SQL)
        print("✅ Индексы созданы")
        
        # Проверка
        print("\n🔍 Проверка добавленных колонок...")
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='turn' 
            AND column_name IN ('cvss_v2_vector', 'cvss_v3_vector', 'epss_score', 'cwe_ids', 'nvd_references', 'has_kev')
            ORDER BY column_name;
        """)
        columns = cursor.fetchall()
        print(f"✅ Найдено {len(columns)} новых колонок:")
        for col in columns:
            print(f"   - {col[0]}")
        
        cursor.close()
        conn.close()
        print("\n✅ Миграция успешно применена!")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при применении миграции: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = apply_migration()
    sys.exit(0 if success else 1)

