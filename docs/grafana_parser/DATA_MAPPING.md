# 🗺️ Маппинг данных Grafana → БД

**Сопоставление полей и интеграция с БДУ структурой**

---

## 📊 Сравнительная таблица: Grafana vs БДУ vs БД

| **Данные Grafana** | **Эквивалент БДУ ФСТЭК** | **Поле в БД** | **Тип** | **Примечания** |
|-------------------|-------------------------|---------------|---------|----------------|
| CVE ID | Идентификатор CVE | `cve_id` | VARCHAR(50) | Основной идентификатор |
| Advisory Title | Название уязвимости | `title` | VARCHAR(500) | Краткое описание |
| Summary | Описание уязвимости | `description` | TEXT | Полное описание |
| Product | Название ПО | `product_name` | VARCHAR(255) | ✅ БДУ поле |
| - | Вендор | `vendor` | VARCHAR(255) | ✅ "Grafana Labs" |
| CVSS Score | Базовая оценка CVSS | `cvss_score` | DECIMAL(3,1) | Числовое значение |
| Severity | Уровень опасности | `severity` | VARCHAR(50) | CRITICAL/HIGH/MEDIUM/LOW |
| CVSS Vector | Базовый вектор CVSS | `metrics.cvss_v3.vectorString` | JSONB | Полный вектор |
| Published Date | Дата публикации | `published_date` | TIMESTAMP | Дата публикации в Grafana |
| Updated Date | Дата обновления | `last_modified_date` | TIMESTAMP | Последнее изменение |
| Fixed Versions | Информация об устранении | `affected_versions` | TEXT | ✅ БДУ поле |
| Fixed Versions | Информация об устранении | `remediation_info` | TEXT | ✅ БДУ поле |
| Credits | Благодарности | `vendor_comments.credits` | JSONB | Кто нашел уязвимость |
| Advisory URL | Ссылка на источник | `references[].url` | JSONB | Vendor advisory |
| - | Тип ПО | `software_type` | VARCHAR(100) | ✅ Определяется автоматически |

---

## 🔄 Детальный маппинг полей

### 1. Идентификация

#### 1.1 CVE ID
**Источник:** Grafana table → CVE column  
**Назначение:** `cve_id`

```python
# Пример данных
grafana_data = {
    "cve_id": "CVE-2025-41118"
}

# Маппинг
db_data = {
    "cve_id": grafana_data["cve_id"]  # Прямое копирование
}
```

**Валидация:**
```python
import re

def validate_cve_id(cve_id):
    """
    Проверка формата CVE ID
    """
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id))
```

---

#### 1.2 Title (Advisory Title)
**Источник:** Grafana table → Advisory Title column  
**Назначение:** `title`

```python
# Пример данных
grafana_data = {
    "advisory_title": "Exposure of Storage Secret in Pyroscope"
}

# Маппинг
db_data = {
    "title": grafana_data["advisory_title"]
}
```

**Обработка:**
- Удаление лишних пробелов
- Ограничение длины до 500 символов
- Сохранение оригинального регистра

---

### 2. Информация о продукте (БДУ поля)

#### 2.1 Vendor
**Источник:** Константа (все уязвимости от Grafana Labs)  
**Назначение:** `vendor` ✅ БДУ поле

```python
db_data = {
    "vendor": "Grafana Labs"  # Константа для всех Grafana advisory
}
```

**Особенности:**
- Всегда "Grafana Labs" для advisory с grafana.com
- Позволяет фильтровать уязвимости по вендору
- Интеграция с БДУ структурой

---

#### 2.2 Product Name
**Источник:** Grafana table → Product column  
**Назначение:** `product_name` ✅ БДУ поле

```python
# Примеры данных
grafana_data = {
    "product": "Pyroscope"
    # или "Grafana"
    # или "Grafana Enterprise"
    # или "Grafana Databricks Datasource Plugin"
}

# Маппинг
db_data = {
    "product_name": grafana_data["product"]
}
```

**Нормализация:**
```python
def normalize_product_name(product):
    """
    Нормализация названия продукта
    """
    # Удаление лишних пробелов
    product = ' '.join(product.split())
    
    # Сокращения (опционально)
    replacements = {
        "Grafana Databricks Datasource Plugin": "Grafana Databricks Plugin",
        "Grafana Snowflake Datasource Plugin": "Grafana Snowflake Plugin"
    }
    
    return replacements.get(product, product)
```

---

#### 2.3 Software Type
**Источник:** Определяется автоматически по product_name  
**Назначение:** `software_type` ✅ БДУ поле

```python
def detect_software_type(product_name):
    """
    Определение типа ПО
    
    Возможные значения:
    - "Прикладное ПО"
    - "Плагин"
    - "Библиотека"
    """
    product_lower = product_name.lower()
    
    if 'plugin' in product_lower:
        return 'Плагин'
    elif 'renderer' in product_lower:
        return 'Компонент'
    elif any(keyword in product_lower for keyword in ['grafana', 'loki', 'tempo', 'mimir', 'pyroscope']):
        return 'Прикладное ПО'
    else:
        return 'Прикладное ПО'

# Примеры
detect_software_type("Grafana")                              # → "Прикладное ПО"
detect_software_type("Grafana Databricks Datasource Plugin") # → "Плагин"
detect_software_type("Grafana Image Renderer Plugin")        # → "Плагин"
detect_software_type("Pyroscope")                            # → "Прикладное ПО"
```

---

#### 2.4 Affected Versions
**Источник:** Grafana detail page → Fixed Versions  
**Назначение:** `affected_versions` ✅ БДУ поле

```python
# Пример данных
grafana_data = {
    "fixed_versions": [
        ">=1.15.2 <1.16.0",
        ">=1.16.1"
    ]
}

# Маппинг
def format_affected_versions(fixed_versions):
    """
    Преобразование информации о исправленных версиях
    в описание затронутых версий
    """
    if not fixed_versions:
        return "Информация о версиях отсутствует"
    
    # Инверсия: из "исправлено в" → "уязвимы до"
    affected = []
    
    for version_range in fixed_versions:
        if isinstance(version_range, str):
            # ">=1.15.2 <1.16.0" → "Уязвимы: <1.15.2 и >=1.16.0 <1.16.1"
            # Упрощенный вариант: просто перечислить исправленные
            affected.append(f"Исправлено в {version_range}")
    
    return "; ".join(affected)

db_data = {
    "affected_versions": format_affected_versions(grafana_data["fixed_versions"])
}

# Результат:
# "Исправлено в >=1.15.2 <1.16.0; Исправлено в >=1.16.1"
```

---

### 3. Оценка опасности

#### 3.1 CVSS Score
**Источник:** Grafana table → Severity (CVSS) column  
**Назначение:** `cvss_score`

```python
# Пример данных
grafana_data = {
    "severity_text": "● Critical (9.1)"
}

# Парсинг
import re

def parse_cvss_score(severity_text):
    """
    Извлечение CVSS score из текста
    
    Вход: "● Critical (9.1)"
    Выход: 9.1
    """
    match = re.search(r'\((\d+\.\d+)\)', severity_text)
    if match:
        return float(match.group(1))
    return None

db_data = {
    "cvss_score": parse_cvss_score(grafana_data["severity_text"])
}
```

---

#### 3.2 Severity Level
**Источник:** Grafana table → Severity (CVSS) column  
**Назначение:** `severity`

```python
# Пример данных
grafana_data = {
    "severity_text": "● Critical (9.1)"
}

# Парсинг
def parse_severity_level(severity_text):
    """
    Извлечение уровня опасности
    
    Вход: "● Critical (9.1)"
    Выход: "CRITICAL"
    """
    severity_map = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW'
    }
    
    for key, value in severity_map.items():
        if key in severity_text.lower():
            return value
    
    return 'UNKNOWN'

db_data = {
    "severity": parse_severity_level(grafana_data["severity_text"])
}
```

---

#### 3.3 CVSS Vector
**Источник:** Grafana detail page → CVSS Vector field  
**Назначение:** `metrics.cvss_v3`

```python
# Пример данных
grafana_data = {
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cvss_score": 9.1
}

# Парсинг
def parse_cvss_vector(vector_string, score):
    """
    Парсинг CVSS вектора в структуру БД
    """
    parts = vector_string.split('/')
    version = parts[0].split(':')[1]  # "3.1"
    
    metrics = {}
    for part in parts[1:]:
        key, value = part.split(':')
        metrics[key] = value
    
    # Маппинг на полные названия
    return {
        "version": version,
        "vectorString": vector_string,
        "baseScore": score,
        "baseSeverity": calculate_severity(score),
        "attackVector": expand_av(metrics.get('AV')),
        "attackComplexity": expand_ac(metrics.get('AC')),
        "privilegesRequired": expand_pr(metrics.get('PR')),
        "userInteraction": expand_ui(metrics.get('UI')),
        "scope": expand_s(metrics.get('S')),
        "confidentialityImpact": expand_c(metrics.get('C')),
        "integrityImpact": expand_i(metrics.get('I')),
        "availabilityImpact": expand_a(metrics.get('A'))
    }

def expand_av(value):
    """Attack Vector"""
    mapping = {
        'N': 'NETWORK',
        'A': 'ADJACENT_NETWORK',
        'L': 'LOCAL',
        'P': 'PHYSICAL'
    }
    return mapping.get(value, value)

def expand_ac(value):
    """Attack Complexity"""
    mapping = {
        'L': 'LOW',
        'H': 'HIGH'
    }
    return mapping.get(value, value)

def expand_pr(value):
    """Privileges Required"""
    mapping = {
        'N': 'NONE',
        'L': 'LOW',
        'H': 'HIGH'
    }
    return mapping.get(value, value)

def expand_ui(value):
    """User Interaction"""
    mapping = {
        'N': 'NONE',
        'R': 'REQUIRED'
    }
    return mapping.get(value, value)

def expand_s(value):
    """Scope"""
    mapping = {
        'U': 'UNCHANGED',
        'C': 'CHANGED'
    }
    return mapping.get(value, value)

def expand_c(value):
    """Confidentiality Impact"""
    return expand_impact(value)

def expand_i(value):
    """Integrity Impact"""
    return expand_impact(value)

def expand_a(value):
    """Availability Impact"""
    return expand_impact(value)

def expand_impact(value):
    """Generic Impact"""
    mapping = {
        'N': 'NONE',
        'L': 'LOW',
        'H': 'HIGH'
    }
    return mapping.get(value, value)

def calculate_severity(score):
    """
    Определение severity по score
    """
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    else:
        return 'LOW'

# Маппинг
db_data = {
    "metrics": {
        "cvss_v3": parse_cvss_vector(
            grafana_data["cvss_vector"],
            grafana_data["cvss_score"]
        )
    }
}
```

---

### 4. Даты

#### 4.1 Published Date
**Источник:** Grafana detail page → Published field  
**Назначение:** `published_date`

```python
from datetime import datetime

# Пример данных
grafana_data = {
    "published_date": "2026-01-02"
}

# Парсинг
def parse_date(date_string):
    """
    Парсинг даты из различных форматов
    
    Поддерживаемые форматы:
    - "2026-01-02" (ISO)
    - "January 2, 2026"
    - "02/01/2026"
    """
    if not date_string or date_string == '—':
        return None
    
    # ISO формат
    try:
        return datetime.strptime(date_string, '%Y-%m-%d')
    except ValueError:
        pass
    
    # Другие форматы...
    # TODO: Добавить по необходимости
    
    return None

db_data = {
    "published_date": parse_date(grafana_data["published_date"])
}
```

---

#### 4.2 Updated Date
**Источник:** Grafana table → Updated column  
**Назначение:** `last_modified_date`

```python
# Пример данных
grafana_data = {
    "updated_date": "2025-09-24"  # или "—"
}

# Маппинг
db_data = {
    "last_modified_date": parse_date(grafana_data["updated_date"])
}
```

---

### 5. Описание и детали

#### 5.1 Summary
**Источник:** Grafana detail page → Summary section  
**Назначение:** `description`

```python
# Пример данных
grafana_data = {
    "summary": "Pyroscope is an open-source continuous profiling database. The database supports various storage backends, including Tencent Cloud Object Storage (COS).\n\nIf the database is configured to use Tencent COS as the storage backend, an attacker could extract the secret_key configuration value from the Pyroscope API."
}

# Маппинг
db_data = {
    "description": grafana_data["summary"]
}
```

**Обработка:**
- Сохранение форматирования (переносы строк)
- Удаление лишних пробелов
- Ограничение длины (если необходимо)

---

### 6. Устранение (БДУ поля)

#### 6.1 Remediation Method
**Источник:** Определяется автоматически  
**Назначение:** `remediation_method` ✅ БДУ поле

```python
db_data = {
    "remediation_method": "Обновление ПО"  # Константа для Grafana advisory
}
```

**Возможные значения:**
- "Обновление ПО" (основной вариант)
- "Изменение конфигурации"
- "Применение патча"

---

#### 6.2 Remediation Info
**Источник:** Комбинация Summary + Fixed Versions  
**Назначение:** `remediation_info` ✅ БДУ поле

```python
def format_remediation_info(grafana_data):
    """
    Формирование информации об устранении
    """
    parts = []
    
    # 1. Описание уязвимости
    if grafana_data.get('summary'):
        parts.append("## Описание уязвимости")
        parts.append(grafana_data['summary'])
        parts.append("")
    
    # 2. Исправленные версии
    if grafana_data.get('fixed_versions'):
        parts.append("## Исправленные версии")
        for version in grafana_data['fixed_versions']:
            parts.append(f"- {version}")
        parts.append("")
    
    # 3. Рекомендации
    parts.append("## Рекомендации")
    parts.append("Рекомендуется обновить продукт до последней версии.")
    parts.append("")
    
    # 4. Ссылка на advisory
    cve_id = grafana_data.get('cve_id', '').lower()
    parts.append("## Дополнительная информация")
    parts.append(f"Официальный advisory: https://grafana.com/security/security-advisories/{cve_id}/")
    
    return '\n'.join(parts)

db_data = {
    "remediation_info": format_remediation_info(grafana_data)
}
```

**Пример результата:**
```markdown
## Описание уязвимости
Pyroscope is an open-source continuous profiling database...

## Исправленные версии
- >=1.15.2 <1.16.0
- >=1.16.1

## Рекомендации
Рекомендуется обновить продукт до последней версии.

## Дополнительная информация
Официальный advisory: https://grafana.com/security/security-advisories/cve-2025-41118/
```

---

#### 6.3 Remediation Date
**Источник:** Published Date (дата публикации патча)  
**Назначение:** `remediation_date` ✅ БДУ поле

```python
db_data = {
    "remediation_date": parse_date(grafana_data["published_date"])
}
```

**Логика:**
- Для Grafana advisory дата публикации = дата выпуска патча
- Если есть отдельная дата устранения - использовать её

---

### 7. Ссылки и источники

#### 7.1 References
**Источник:** Advisory URL  
**Назначение:** `references`

```python
def build_references(grafana_data):
    """
    Формирование массива ссылок
    """
    cve_id = grafana_data['cve_id'].lower()
    
    references = [
        {
            "url": f"https://grafana.com/security/security-advisories/{cve_id}/",
            "type": "vendor_advisory",
            "source": "Grafana Labs"
        }
    ]
    
    # Добавить ссылку на bug bounty (если есть credits)
    if grafana_data.get('credits'):
        references.append({
            "url": "https://grafana.com/security/bug-bounty/",
            "type": "bug_bounty",
            "source": "Grafana Labs"
        })
    
    return references

db_data = {
    "references": build_references(grafana_data)
}
```

---

#### 7.2 Vendor Comments (Credits)
**Источник:** Grafana detail page → Credits section  
**Назначение:** `vendor_comments`

```python
# Пример данных
grafana_data = {
    "credits": "Thanks to Théo Cusnir for reporting this vulnerability to us via our bug bounty program."
}

# Маппинг
db_data = {
    "vendor_comments": {
        "credits": grafana_data.get("credits", ""),
        "source": "Grafana Labs Security Advisory"
    }
}
```

---

### 8. Метаданные

#### 8.1 Source
**Источник:** Константа  
**Назначение:** `source`

```python
db_data = {
    "source": "grafana"  # Идентификатор источника
}
```

**Возможные значения source в системе:**
- `"nvd"` - National Vulnerability Database
- `"bdu_fstec"` - БДУ ФСТЭК
- `"grafana"` - Grafana Security Advisories
- `"github"` - GitHub Security Advisories

---

## 🔀 Полный пример маппинга

### Входные данные (Grafana)

```python
grafana_advisory = {
    # Из таблицы списка
    "cve_id": "CVE-2025-41118",
    "severity_text": "● Critical (9.1)",
    "product": "Pyroscope",
    "advisory_title": "Exposure of Storage Secret in Pyroscope",
    "advisory_url": "/security/security-advisories/cve-2025-41118/",
    "updated_date": "—",
    
    # Из детальной страницы
    "published_date": "2026-01-02",
    "cvss_score": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "fixed_versions": [
        ">=1.15.2 <1.16.0",
        ">=1.16.1"
    ],
    "summary": "Pyroscope is an open-source continuous profiling database. The database supports various storage backends, including Tencent Cloud Object Storage (COS).\n\nIf the database is configured to use Tencent COS as the storage backend, an attacker could extract the secret_key configuration value from the Pyroscope API.\n\nTo exploit this vulnerability, an attacker needs direct access to the Pyroscope API. We highly recommend limiting the public internet exposure of all our databases, such that they are only accessible by trusted users or internal systems.\n\nThis vulnerability is fixed in versions:\n- 1.15.x: 1.15.2 and above.\n- 1.16.x: 1.16.1 and above.\n- 1.17.x: 1.17.0 and above (i.e. all versions).",
    "credits": "Thanks to Théo Cusnir for reporting this vulnerability to us via our bug bounty program."
}
```

### Выходные данные (БД)

```python
db_vulnerability = {
    # Основные поля
    "cve_id": "CVE-2025-41118",
    "title": "Exposure of Storage Secret in Pyroscope",
    "description": "Pyroscope is an open-source continuous profiling database...",
    
    # БДУ поля: Информация о ПО
    "vendor": "Grafana Labs",
    "product_name": "Pyroscope",
    "affected_versions": "Исправлено в >=1.15.2 <1.16.0; Исправлено в >=1.16.1",
    "software_type": "Прикладное ПО",
    "operating_systems": None,  # Не указано в Grafana advisory
    "hardware_platforms": None,
    
    # Оценка опасности
    "cvss_score": 9.1,
    "severity": "CRITICAL",
    "risk_level": "CRITICAL",
    "metrics": {
        "cvss_v3": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "baseScore": 9.1,
            "baseSeverity": "CRITICAL",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "NONE"
        }
    },
    
    # Даты
    "published_date": datetime(2026, 1, 2),
    "last_modified_date": None,
    "created_date": datetime.now(),  # Дата добавления в систему
    
    # БДУ поля: Устранение
    "remediation_method": "Обновление ПО",
    "remediation_info": "## Описание уязвимости\nPyroscope is...\n\n## Исправленные версии\n...",
    "remediation_date": datetime(2026, 1, 2),
    
    # БДУ поля: Эксплуатация
    "exploit_available": False,  # Не указано в Grafana
    "exploit_type": None,
    "exploitation_method": "To exploit this vulnerability, an attacker needs direct access to the Pyroscope API.",
    
    # Ссылки
    "references": [
        {
            "url": "https://grafana.com/security/security-advisories/cve-2025-41118/",
            "type": "vendor_advisory",
            "source": "Grafana Labs"
        },
        {
            "url": "https://grafana.com/security/bug-bounty/",
            "type": "bug_bounty",
            "source": "Grafana Labs"
        }
    ],
    
    # Комментарии вендора
    "vendor_comments": {
        "credits": "Thanks to Théo Cusnir for reporting this vulnerability to us via our bug bounty program.",
        "source": "Grafana Labs Security Advisory"
    },
    
    # Метаданные
    "source": "grafana",
    "vuln_status": "PUBLISHED"
}
```

---

## 📋 Сравнение с БДУ ФСТЭК

### Поля, которые заполняются из Grafana (как в БДУ)

✅ **Полностью поддерживаются:**
- `vendor` - "Grafana Labs"
- `product_name` - из Product
- `affected_versions` - из Fixed Versions
- `software_type` - определяется автоматически
- `remediation_method` - "Обновление ПО"
- `remediation_info` - форматированное описание
- `remediation_date` - дата публикации патча

⚠️ **Частично поддерживаются:**
- `exploitation_method` - если есть в описании
- `cvss_score` и `metrics` - полная поддержка CVSS 3.x

❌ **Не доступны в Grafana advisory:**
- `bdu_id` - нет российского идентификатора
- `operating_systems` - обычно не указывается
- `hardware_platforms` - не указывается
- `exploit_available` - не указывается явно
- `exploit_type` - не указывается
- `date_discovered` - используется published_date

---

## 🔄 Интеграция с NVD данными

### Сценарий: CVE есть и в Grafana, и в NVD

```python
def merge_grafana_with_nvd(nvd_data, grafana_data):
    """
    Объединение данных из NVD и Grafana
    
    Приоритет:
    1. Vendor-specific данные (Grafana) - выше приоритет
    2. NVD данные - как дополнение
    """
    merged = nvd_data.copy()
    
    # Grafana данные имеют приоритет для:
    # - vendor и product_name
    merged['vendor'] = grafana_data.get('vendor', nvd_data.get('vendor'))
    merged['product_name'] = grafana_data.get('product_name', nvd_data.get('product_name'))
    
    # - remediation_info (более актуальная информация от вендора)
    if grafana_data.get('remediation_info'):
        merged['remediation_info'] = grafana_data['remediation_info']
    
    # - affected_versions (точная информация от вендора)
    if grafana_data.get('affected_versions'):
        merged['affected_versions'] = grafana_data['affected_versions']
    
    # NVD данные дополняют:
    # - CWE (weakness types)
    if nvd_data.get('weaknesses') and not grafana_data.get('weaknesses'):
        merged['weaknesses'] = nvd_data['weaknesses']
    
    # - CPE (configurations)
    if nvd_data.get('configurations'):
        merged['configurations'] = nvd_data['configurations']
    
    # - Дополнительные ссылки
    nvd_refs = nvd_data.get('references', [])
    grafana_refs = grafana_data.get('references', [])
    merged['references'] = grafana_refs + [r for r in nvd_refs if r not in grafana_refs]
    
    # Метаданные источников
    merged['sources'] = ['nvd', 'grafana']
    
    return merged
```

---

## ✅ Чек-лист маппинга

### Обязательные поля:
- [ ] `cve_id` - CVE идентификатор
- [ ] `title` - название уязвимости
- [ ] `description` - описание
- [ ] `cvss_score` - оценка CVSS
- [ ] `severity` - уровень опасности
- [ ] `published_date` - дата публикации

### БДУ поля (рекомендуемые):
- [ ] `vendor` - "Grafana Labs"
- [ ] `product_name` - название продукта
- [ ] `affected_versions` - затронутые версии
- [ ] `software_type` - тип ПО
- [ ] `remediation_method` - способ устранения
- [ ] `remediation_info` - информация об устранении
- [ ] `remediation_date` - дата устранения

### Дополнительные поля:
- [ ] `metrics.cvss_v3` - детальные метрики CVSS
- [ ] `references` - ссылки на источники
- [ ] `vendor_comments` - комментарии вендора
- [ ] `source` - идентификатор источника

---

## 🎯 Итоговая статистика покрытия

### Поля БД, заполняемые из Grafana:

| **Категория** | **Заполняется** | **Всего полей** | **% покрытия** |
|---------------|----------------|----------------|----------------|
| Основные | 6/6 | 6 | 100% |
| БДУ: ПО | 4/6 | 6 | 67% |
| БДУ: Оценка | 3/3 | 3 | 100% |
| БДУ: Устранение | 3/7 | 7 | 43% |
| Даты | 2/3 | 3 | 67% |
| Ссылки | 2/2 | 2 | 100% |
| **ИТОГО** | **20/27** | **27** | **74%** |

**Вывод:** Grafana Security Advisories покрывают 74% полей БДУ структуры, что является хорошим показателем для vendor-specific источника.

---

**Следующий документ:** [IMPLEMENTATION.md](IMPLEMENTATION.md)

