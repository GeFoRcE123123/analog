# Простая инструкция - выполнить команды вручную

## Проблема
Команды через pipe зависают. Нужно выполнить напрямую.

## Решение: Выполнить команды вручную через интерактивный psql

### Шаг 1: Подключитесь к VM и войдите в контейнер
```bash
sshpass -p "123" ssh user@10.0.88.11
docker exec -it vulnerability_db psql -U admin -d vuln_db
```

### Шаг 2: Скопируйте и выполните эти команды (одну за другой):

```sql
-- Удалить таблицу
DROP TABLE IF EXISTS turn CASCADE;
```

```sql
-- Создать таблицу (скопируйте всю команду целиком)
CREATE TABLE turn (
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
    status BOOLEAN DEFAULT TRUE,
    cvss_v2_vector TEXT,
    cvss_v3_vector TEXT,
    cvss_v4_vector TEXT,
    cvss_version VARCHAR(10) DEFAULT '3.1',
    cvss_v2_metrics JSONB,
    cvss_v3_metrics JSONB,
    cvss_v4_metrics JSONB,
    epss_score DECIMAL(5,4),
    epss_percentile DECIMAL(5,2),
    cwe_ids TEXT[],
    affected_products JSONB,
    nvd_references JSONB,
    vendor_comments JSONB,
    cpe_configurations JSONB,
    nvd_weaknesses JSONB,
    source_identifier VARCHAR(200),
    nvd_status VARCHAR(50),
    nvd_published TIMESTAMP,
    nvd_last_modified TIMESTAMP,
    nvd_descriptions JSONB,
    nvd_metrics JSONB,
    has_kev BOOLEAN DEFAULT FALSE,
    has_cert_alerts BOOLEAN DEFAULT FALSE,
    cve_json5_data JSONB
);
```

```sql
-- Создать индексы (выполните все команды подряд)
CREATE INDEX idx_turn_cve ON turn(cve);
CREATE INDEX idx_turn_source ON turn(source);
CREATE INDEX idx_turn_status ON turn(status);
CREATE INDEX idx_turn_cvss ON turn(cvss);
CREATE INDEX idx_turn_joining_date ON turn(joining_date);
CREATE INDEX idx_turn_cwe_ids ON turn USING GIN(cwe_ids);
CREATE INDEX idx_turn_epss_score ON turn(epss_score);
CREATE INDEX idx_turn_source_identifier ON turn(source_identifier);
CREATE INDEX idx_turn_nvd_status ON turn(nvd_status);
CREATE INDEX idx_turn_has_kev ON turn(has_kev);
CREATE INDEX idx_turn_nvd_published ON turn(nvd_published);
CREATE INDEX idx_turn_affected_products_gin ON turn USING GIN(affected_products);
CREATE INDEX idx_turn_nvd_references_gin ON turn USING GIN(nvd_references);
CREATE INDEX idx_turn_nvd_weaknesses_gin ON turn USING GIN(nvd_weaknesses);
CREATE INDEX idx_turn_cpe_configurations_gin ON turn USING GIN(cpe_configurations);
```

```sql
-- Проверить результат
SELECT COUNT(*) as total_columns FROM information_schema.columns WHERE table_name='turn';
SELECT column_name FROM information_schema.columns WHERE table_name='turn' AND column_name IN ('cvss_v2_vector', 'epss_score', 'cwe_ids', 'nvd_references', 'has_kev') ORDER BY column_name;
```

### Шаг 3: Выход из psql
```sql
\q
```

## Альтернатива 1: Использовать bash скрипт (рекомендуется)

1. Скопируйте скрипт на VM:
```bash
sshpass -p "123" scp execute_on_vm.sh user@10.0.88.11:/tmp/
```

2. Подключитесь к VM и выполните скрипт напрямую (БЕЗ SSH pipe):
```bash
sshpass -p "123" ssh user@10.0.88.11
chmod +x /tmp/execute_on_vm.sh
/tmp/execute_on_vm.sh
```

Этот способ НЕ зависает, так как скрипт выполняется прямо на VM без pipe!

## Альтернатива 2: Использовать SQL файл через docker cp

1. Скопируйте файл на VM:
```bash
sshpass -p "123" scp recreate_database_simple.sql user@10.0.88.11:/tmp/
```

2. Подключитесь к VM и выполните:
```bash
sshpass -p "123" ssh user@10.0.88.11
docker cp /tmp/recreate_database_simple.sql vulnerability_db:/tmp/
docker exec -it vulnerability_db psql -U admin -d vuln_db
```

3. Внутри psql:
```sql
\i /tmp/recreate_database_simple.sql
```

