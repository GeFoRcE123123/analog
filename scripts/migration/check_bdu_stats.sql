-- =====================================================
-- Проверка статистики БДУ полей после миграции
-- =====================================================
-- Использование: psql -U user -d db -f check_bdu_stats.sql
-- =====================================================

\echo '==================================================='
\echo '📊 СТАТИСТИКА БДУ ФСТЭК ПОЛЕЙ'
\echo '==================================================='
\echo ''

-- Общая статистика заполненности
\echo '1️⃣  ОБЩАЯ СТАТИСТИКА ЗАПОЛНЕННОСТИ'
\echo '---------------------------------------------------'

SELECT 
    COUNT(*) as "Всего уязвимостей",
    COUNT(bdu_id) as "С BDU ID",
    ROUND(COUNT(bdu_id)::numeric / NULLIF(COUNT(*), 0) * 100, 2) as "% BDU ID",
    COUNT(vendor) as "С вендором",
    ROUND(COUNT(vendor)::numeric / NULLIF(COUNT(*), 0) * 100, 2) as "% вендор",
    COUNT(product_name) as "С продуктом",
    ROUND(COUNT(product_name)::numeric / NULLIF(COUNT(*), 0) * 100, 2) as "% продукт",
    COUNT(CASE WHEN exploit_available = TRUE THEN 1 END) as "С эксплойтом",
    ROUND(COUNT(CASE WHEN exploit_available = TRUE THEN 1 END)::numeric / NULLIF(COUNT(*), 0) * 100, 2) as "% эксплойт",
    COUNT(date_discovered) as "С датой выявления",
    COUNT(remediation_date) as "С датой устранения"
FROM vulnerabilities;

\echo ''
\echo '---------------------------------------------------'
\echo ''

-- Топ-10 вендоров
\echo '2️⃣  ТОП-10 ВЕНДОРОВ ПО КОЛИЧЕСТВУ УЯЗВИМОСТЕЙ'
\echo '---------------------------------------------------'

SELECT 
    vendor as "Вендор",
    COUNT(*) as "Количество",
    COUNT(CASE WHEN exploit_available = TRUE THEN 1 END) as "С эксплойтом",
    ROUND(AVG(cvss_score), 2) as "Средний CVSS"
FROM vulnerabilities
WHERE vendor IS NOT NULL
GROUP BY vendor
ORDER BY COUNT(*) DESC
LIMIT 10;

\echo ''
\echo '---------------------------------------------------'
\echo ''

-- Топ-10 продуктов
\echo '3️⃣  ТОП-10 ПРОДУКТОВ ПО КОЛИЧЕСТВУ УЯЗВИМОСТЕЙ'
\echo '---------------------------------------------------'

SELECT 
    product_name as "Продукт",
    vendor as "Вендор",
    COUNT(*) as "Количество",
    COUNT(CASE WHEN exploit_available = TRUE THEN 1 END) as "С эксплойтом"
FROM vulnerabilities
WHERE product_name IS NOT NULL
GROUP BY product_name, vendor
ORDER BY COUNT(*) DESC
LIMIT 10;

\echo ''
\echo '---------------------------------------------------'
\echo ''

-- Статистика по эксплойтам
\echo '4️⃣  СТАТИСТИКА ПО ЭКСПЛОЙТАМ'
\echo '---------------------------------------------------'

SELECT 
    exploit_type as "Тип эксплуатации",
    COUNT(*) as "Количество",
    ROUND(AVG(cvss_score), 2) as "Средний CVSS",
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as "Критических"
FROM vulnerabilities
WHERE exploit_available = TRUE
GROUP BY exploit_type
ORDER BY COUNT(*) DESC;

\echo ''
\echo '---------------------------------------------------'
\echo ''

-- Источники данных
\echo '5️⃣  ИСТОЧНИКИ ДАННЫХ'
\echo '---------------------------------------------------'

SELECT 
    CASE 
        WHEN bdu_id IS NOT NULL AND cve_id IS NOT NULL THEN 'БДУ + NVD'
        WHEN bdu_id IS NOT NULL THEN 'Только БДУ'
        WHEN cve_id IS NOT NULL THEN 'Только NVD'
        ELSE 'Другие источники'
    END as "Источник",
    COUNT(*) as "Количество",
    ROUND(COUNT(*)::numeric / (SELECT COUNT(*) FROM vulnerabilities) * 100, 2) as "Процент"
FROM vulnerabilities
GROUP BY 
    CASE 
        WHEN bdu_id IS NOT NULL AND cve_id IS NOT NULL THEN 'БДУ + NVD'
        WHEN bdu_id IS NOT NULL THEN 'Только БДУ'
        WHEN cve_id IS NOT NULL THEN 'Только NVD'
        ELSE 'Другие источники'
    END
ORDER BY COUNT(*) DESC;

\echo ''
\echo '---------------------------------------------------'
\echo ''

-- Статистика по датам
\echo '6️⃣  СТАТИСТИКА ПО ДАТАМ'
\echo '---------------------------------------------------'

SELECT 
    EXTRACT(YEAR FROM date_discovered) as "Год выявления",
    COUNT(*) as "Количество",
    COUNT(CASE WHEN exploit_available = TRUE THEN 1 END) as "С эксплойтом",
    COUNT(remediation_date) as "Устранено"
FROM vulnerabilities
WHERE date_discovered IS NOT NULL
GROUP BY EXTRACT(YEAR FROM date_discovered)
ORDER BY "Год выявления" DESC
LIMIT 10;

\echo ''
\echo '---------------------------------------------------'
\echo ''

-- Критические уязвимости с эксплойтами
\echo '7️⃣  ⚠️  КРИТИЧЕСКИЕ УЯЗВИМОСТИ С ЭКСПЛОЙТАМИ (TOP 20)'
\echo '---------------------------------------------------'

SELECT 
    COALESCE(bdu_id, cve_id, 'ID-' || id::text) as "ID",
    LEFT(title, 50) as "Название",
    vendor as "Вендор",
    cvss_score as "CVSS",
    exploit_type as "Тип"
FROM vulnerabilities
WHERE exploit_available = TRUE 
  AND (severity = 'critical' OR cvss_score >= 9.0)
ORDER BY cvss_score DESC, date_discovered DESC
LIMIT 20;

\echo ''
\echo '---------------------------------------------------'
\echo ''

-- Индексы
\echo '8️⃣  ИСПОЛЬЗОВАНИЕ ИНДЕКСОВ (БДУ)'
\echo '---------------------------------------------------'

SELECT 
    indexname as "Имя индекса",
    idx_scan as "Использований",
    idx_tup_read as "Строк прочитано",
    idx_tup_fetch as "Строк получено",
    pg_size_pretty(pg_relation_size(indexrelid)) as "Размер"
FROM pg_stat_user_indexes
WHERE tablename = 'vulnerabilities'
  AND indexname LIKE '%bdu%' OR indexname LIKE '%vendor%' OR indexname LIKE '%exploit%'
ORDER BY idx_scan DESC;

\echo ''
\echo '---------------------------------------------------'
\echo ''

-- Размер таблицы
\echo '9️⃣  РАЗМЕР ТАБЛИЦЫ VULNERABILITIES'
\echo '---------------------------------------------------'

SELECT 
    pg_size_pretty(pg_total_relation_size('vulnerabilities')) as "Общий размер",
    pg_size_pretty(pg_relation_size('vulnerabilities')) as "Размер данных",
    pg_size_pretty(pg_indexes_size('vulnerabilities')) as "Размер индексов",
    (SELECT COUNT(*) FROM vulnerabilities) as "Количество записей";

\echo ''
\echo '---------------------------------------------------'
\echo ''

-- Уязвимости без БДУ данных (требуют обработки)
\echo '🔟 УЯЗВИМОСТИ БЕЗ БДУ ДАННЫХ (для обработки)'
\echo '---------------------------------------------------'

SELECT 
    COUNT(*) as "Всего без BDU ID",
    COUNT(CASE WHEN description LIKE '%BDU%' OR title LIKE '%BDU%' THEN 1 END) as "Упоминание BDU в тексте",
    COUNT(CASE WHEN vendor IS NULL THEN 1 END) as "Без вендора",
    COUNT(CASE WHEN date_discovered IS NULL THEN 1 END) as "Без даты выявления"
FROM vulnerabilities
WHERE bdu_id IS NULL;

\echo ''
\echo '==================================================='
\echo '✅ ПРОВЕРКА ЗАВЕРШЕНА'
\echo '==================================================='
\echo ''

-- Рекомендации
\echo 'РЕКОМЕНДАЦИИ:'
\echo ''
\echo '1. Если % заполнения BDU ID < 50%:'
\echo '   → Запустить backfill скрипт'
\echo ''
\echo '2. Если много уязвимостей с эксплойтами:'
\echo '   → Проверить критические уязвимости (секция 7)'
\echo ''
\echo '3. Если индексы не используются:'
\echo '   → Выполнить ANALYZE vulnerabilities;'
\echo ''
\echo '4. Если размер таблицы большой:'
\echo '   → Рассмотреть архивирование старых записей'
\echo ''

