# Анализ структуры паспорта уязвимости БДУ ФСТЭК 2026

**Дата анализа:** 22 января 2026  
**Анализируемый пример:** [BDU:2026-00669](https://bdu.fstec.ru/vul/2026-00669)  
**Текущая версия системы:** Vulnerability Management System

---

## 1. СТРУКТУРА ПАСПОРТА БДУ ФСТЭК

### 1.1 Идентификационный блок
**Поля в БДУ ФСТЭК:**
- **Идентификатор BDU** (формат: BDU:YYYY-XXXXX) - уникальный номер уязвимости
- **Название уязвимости** - краткое наименование с описанием последствий
- **Идентификаторы других систем** - CVE, OSVDB, другие ID

**Текущее состояние в системе:**
- ✅ `cve_id` (VARCHAR(50)) - есть
- ⚠️ `bdu_id` - **ОТСУТСТВУЕТ** (нужно добавить!)
- ✅ `title` (VARCHAR(500)) - есть

**Проблемы:**
- Нет отдельного поля для BDU идентификатора
- BDU ID сейчас парсится в title или description
- Невозможен быстрый поиск по BDU идентификатору

---

### 1.2 Информация об уязвимом ПО

**Поля в БДУ ФСТЭК:**
- **Вендор/разработчик** - производитель ПО
- **Наименование ПО** - название продукта
- **Версия ПО** - затронутые версии
- **Тип ПО** - прикладное, системное, микропрограммное и т.д.
- **Операционные системы** - список поддерживаемых ОС
- **Аппаратная платформа** - x86, ARM и т.д.

**Текущее состояние в системе:**
- ❌ `vendor` - **ОТСУТСТВУЕТ**
- ❌ `product_name` - **ОТСУТСТВУЕТ**
- ❌ `affected_versions` - **ОТСУТСТВУЕТ**
- ❌ `software_type` - **ОТСУТСТВУЕТ**
- ❌ `operating_systems` - **ОТСУТСТВУЕТ**
- ❌ `hardware_platforms` - **ОТСУТСТВУЕТ**
- ⚠️ Частично в `configurations` (JSONB) - но это для NVD CPE

**Проблемы:**
- Вся информация о ПО сейчас в текстовом description
- Невозможна структурированная фильтрация по вендору/продукту
- Нет возможности группировки по типу ПО

---

### 1.3 Техническая информация об уязвимости

**Поля в БДУ ФСТЭК:**
- **Тип ошибки** - описание класса уязвимости
- **Идентификатор типа ошибки (CWE)** - номер CWE
- **Класс уязвимости** - категория (уязвимость кода, конфигурации и т.д.)
- **Дата выявления** - когда обнаружена

**Текущее состояние в системе:**
- ✅ `weaknesses` (JSONB) - есть для NVD CWE
- ⚠️ `created_date` (TIMESTAMP) - используется как дата создания в системе, не дата выявления
- ❌ `date_discovered` - **ОТСУТСТВУЕТ**
- ❌ `vulnerability_class` - **ОТСУТСТВУЕТ**
- ❌ `error_type_ru` - **ОТСУТСТВУЕТ** (русское описание типа ошибки)

**Проблемы:**
- Дата выявления != дата добавления в систему
- Нет русскоязычных полей для типов ошибок (БДУ на русском)
- Класс уязвимости не отражен как отдельное поле

---

### 1.4 Оценка опасности

**Поля в БДУ ФСТЭК:**
- **Базовый вектор CVSS 2.0** - полный вектор
- **Базовая оценка CVSS 2.0** - числовое значение
- **Базовый вектор CVSS 3.0/3.1** - полный вектор
- **Базовая оценка CVSS 3.0/3.1** - числовое значение
- **Базовый вектор CVSS 4.0** - полный вектор (новое!)
- **Базовая оценка CVSS 4.0** - числовое значение (новое!)
- **Уровень опасности** - критический/высокий/средний/низкий

**Текущее состояние в системе:**
- ✅ `metrics` (JSONB) - есть структура для cvss_v2, cvss_v3, cvss_v4
- ✅ `cvss_score` (DECIMAL(3,1)) - есть
- ✅ `severity` (VARCHAR(50)) - есть
- ✅ `risk_level` (VARCHAR(50)) - есть

**Проблемы:**
- Хорошо реализовано! Но нужно проверить:
  - Парсятся ли русские названия уровней опасности БДУ
  - Поддерживается ли CVSS 4.0 (новый стандарт)

---

### 1.5 Устранение и статус

**Поля в БДУ ФСТЭК:**
- **Статус уязвимости** - подтверждена производителем / не подтверждена
- **Наличие эксплойта** - есть/нет
- **Возможность эксплуатации** - удаленная/локальная
- **Способ эксплуатации** - описание метода
- **Способ устранения** - обновление ПО / изменение конфигурации
- **Информация об устранении** - детали патча
- **Дата устранения** - когда исправлено

**Текущее состояние в системе:**
- ⚠️ `vuln_status` (VARCHAR(50)) - есть, но для NVD статуса
- ❌ `bdu_status` - **ОТСУТСТВУЕТ** (статус по БДУ)
- ❌ `exploit_available` - **ОТСУТСТВУЕТ**
- ❌ `exploit_type` - **ОТСУТСТВУЕТ** (remote/local)
- ❌ `exploitation_method` - **ОТСУТСТВУЕТ**
- ❌ `remediation_method` - **ОТСУТСТВУЕТ**
- ❌ `remediation_info` - **ОТСУТСТВУЕТ**
- ❌ `remediation_date` - **ОТСУТСТВУЕТ**
- ⚠️ Частично в `references` (JSONB)

**Проблемы:**
- Критически важная информация для российских организаций
- Нет структурированных полей для работы с эксплойтами
- Нет информации о методах устранения
- Невозможна фильтрация по наличию эксплойта

---

### 1.6 Дополнительная информация

**Поля в БДУ ФСТЭК:**
- **Ссылки на источники** - URL к бюллетеням безопасности
- **Рекомендации** - ссылки на патчи и обновления
- **Дополнительные материалы** - сопутствующая документация

**Текущее состояние в системе:**
- ✅ `references` (JSONB) - есть
- ✅ `vendor_comments` (JSONB) - есть
- ⚠️ Структура может не соответствовать БДУ формату

---

## 2. СРАВНИТЕЛЬНАЯ ТАБЛИЦА: ТЕКУЩЕЕ VS ТРЕБУЕМОЕ

| **Область** | **Поле БДУ** | **Текущее поле в БД** | **Статус** | **Приоритет** |
|-------------|--------------|----------------------|------------|---------------|
| **Идентификация** | Идентификатор BDU | - | ❌ Отсутствует | 🔴 КРИТИЧЕСКИЙ |
| | CVE ID | `cve_id` | ✅ Есть | - |
| | Название | `title` | ✅ Есть | - |
| **ПО** | Вендор | - | ❌ Отсутствует | 🟡 ВЫСОКИЙ |
| | Название ПО | - | ❌ Отсутствует | 🟡 ВЫСОКИЙ |
| | Версия ПО | - | ❌ Отсутствует | 🟡 ВЫСОКИЙ |
| | Тип ПО | - | ❌ Отсутствует | 🟢 СРЕДНИЙ |
| | ОС | - | ❌ Отсутствует | 🟢 СРЕДНИЙ |
| | Платформа | - | ❌ Отсутствует | 🟢 СРЕДНИЙ |
| **Техническая инфо** | Дата выявления | `created_date` (неверно) | ⚠️ Частично | 🟡 ВЫСОКИЙ |
| | Класс уязвимости | - | ❌ Отсутствует | 🟢 СРЕДНИЙ |
| | Тип ошибки (рус) | - | ❌ Отсутствует | 🟢 СРЕДНИЙ |
| | CWE | `weaknesses` | ✅ Есть | - |
| **Оценка** | CVSS 2.0 | `metrics.cvss_v2` | ✅ Есть | - |
| | CVSS 3.x | `metrics.cvss_v3` | ✅ Есть | - |
| | CVSS 4.0 | `metrics.cvss_v4` | ✅ Есть | - |
| | Уровень опасности | `severity` | ✅ Есть | - |
| **Устранение** | Статус БДУ | - | ❌ Отсутствует | 🔴 КРИТИЧЕСКИЙ |
| | Наличие эксплойта | - | ❌ Отсутствует | 🔴 КРИТИЧЕСКИЙ |
| | Тип эксплуатации | - | ❌ Отсутствует | 🟡 ВЫСОКИЙ |
| | Способ эксплуатации | - | ❌ Отсутствует | 🟢 СРЕДНИЙ |
| | Способ устранения | - | ❌ Отсутствует | 🟡 ВЫСОКИЙ |
| | Инфо об устранении | - | ❌ Отсутствует | 🟡 ВЫСОКИЙ |
| | Дата устранения | - | ❌ Отсутствует | 🟢 СРЕДНИЙ |
| **Ссылки** | Источники | `references` | ✅ Есть | - |

---

## 3. НЕОБХОДИМЫЕ ИЗМЕНЕНИЯ В БАЗЕ ДАННЫХ

### 3.1 Новые поля для таблицы `vulnerabilities`

```sql
-- Блок БДУ ФСТЭК
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_id VARCHAR(50) UNIQUE; -- BDU:YYYY-XXXXX
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_published_date TIMESTAMP; -- Дата публикации в БДУ

-- Информация о ПО
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vendor VARCHAR(255); -- Вендор/производитель
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS product_name VARCHAR(255); -- Название продукта
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS affected_versions TEXT; -- Затронутые версии (может быть список)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS software_type VARCHAR(100); -- Тип ПО
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS operating_systems TEXT[]; -- Массив ОС
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS hardware_platforms TEXT[]; -- Массив платформ

-- Техническая информация
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS date_discovered DATE; -- Дата выявления (не добавления!)
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vulnerability_class VARCHAR(100); -- Класс уязвимости
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS error_type_russian TEXT; -- Тип ошибки на русском

-- Блок устранения и эксплуатации
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_status VARCHAR(100); -- Статус по БДУ
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS exploit_available BOOLEAN DEFAULT FALSE; -- Наличие эксплойта
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS exploit_type VARCHAR(50); -- remote/local/physical
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS exploitation_method TEXT; -- Способ эксплуатации
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediation_method VARCHAR(100); -- Способ устранения
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediation_info TEXT; -- Информация об устранении
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediation_date DATE; -- Дата устранения

-- Дополнительная информация БДУ
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_raw_data JSONB; -- Полные данные БДУ для архива

-- Индексы для быстрого поиска
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_bdu_id ON vulnerabilities(bdu_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vendor ON vulnerabilities(vendor);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_product ON vulnerabilities(product_name);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_exploit ON vulnerabilities(exploit_available);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_date_discovered ON vulnerabilities(date_discovered);
```

### 3.2 Обновление модели данных

**Файл: `models/entities.py`**

Добавить новые поля в класс `Vulnerability`:

```python
# БДУ ФСТЭК поля
bdu_id: Optional[str] = None
bdu_published_date: Optional[datetime] = None
bdu_status: Optional[str] = None

# Информация о ПО
vendor: Optional[str] = None
product_name: Optional[str] = None
affected_versions: Optional[str] = None
software_type: Optional[str] = None
operating_systems: List[str] = None
hardware_platforms: List[str] = None

# Техническая информация
date_discovered: Optional[date] = None
vulnerability_class: Optional[str] = None
error_type_russian: Optional[str] = None

# Эксплуатация и устранение
exploit_available: bool = False
exploit_type: Optional[str] = None
exploitation_method: Optional[str] = None
remediation_method: Optional[str] = None
remediation_info: Optional[str] = None
remediation_date: Optional[date] = None

# Полные данные БДУ
bdu_raw_data: Optional[Dict] = None
```

---

## 4. ИЗМЕНЕНИЯ В ПАРСЕРЕ БДУ

### 4.1 Обновление `scripts/import_bdu_from_excel.py`

**Текущие проблемы:**
- BDU ID парсится только в title
- Нет извлечения структурированных данных о ПО
- Нет парсинга информации об эксплойтах
- Нет информации о методах устранения

**Необходимые изменения:**

1. **Извлечение BDU ID в отдельное поле:**
```python
bdu_id = str(row.get(col_bdu_id, "")).strip()
# Нормализация формата
if bdu_id and not bdu_id.startswith('BDU:'):
    bdu_id = f'BDU:{bdu_id}'
```

2. **Структурированное извлечение данных о ПО:**
```python
vendor = str(row.get(col_vendor, "") or "").strip()
product = str(row.get(col_product, "") or "").strip()
version = str(row.get(col_version, "") or "").strip()
# Не добавлять в description, а в отдельные поля!
```

3. **Парсинг информации об эксплойтах:**
```python
exploit_text = str(row.get(col_exploit, "") or "").strip()
exploit_available = bool(exploit_text and 'есть' in exploit_text.lower())

exploit_method_text = str(row.get(col_exploit_method, "") or "").strip()
exploit_type = _detect_exploit_type(exploit_method_text)  # remote/local
```

4. **Парсинг методов устранения:**
```python
fix_method = str(row.get(col_fix_method, "") or "").strip()
fix_info = str(row.get(col_fix_info, "") or "").strip()
date_fix = row.get(col_fix_date, None)
```

### 4.2 Создание нового парсера для веб-скрейпинга БДУ

**Новый файл: `services/parsers/bdu_web_parser.py`**

Необходим для парсинга уязвимостей напрямую с сайта БДУ ФСТЭК:

- URL шаблон: `https://bdu.fstec.ru/vul/{BDU_ID}`
- Формат API (если есть): проверить наличие JSON API
- Периодичность: ежедневная проверка новых записей
- Инкрементальное обновление: только новые BDU

**Ключевые функции:**
1. `fetch_bdu_vulnerability(bdu_id)` - получить данные по ID
2. `fetch_latest_bdu_vulnerabilities(limit=50)` - последние записи
3. `parse_bdu_html(html)` - парсинг HTML страницы паспорта
4. `extract_structured_data(parsed)` - извлечение структурированных данных
5. `sync_with_database(vulns)` - синхронизация с БД

---

## 5. ИЗМЕНЕНИЯ В FRONTEND (UI/UX)

### 5.1 Модальное окно просмотра уязвимости

**Файл: `templates/vulnerabilities_list.html`**

**Добавить новые секции:**

#### 5.1.1 Блок БДУ информации
```html
<!-- БДУ ФСТЭК Информация -->
<div class="bg-blue-50 rounded-xl p-4" id="bdu-info-block" style="display:none;">
    <h4 class="font-semibold text-blue-900 mb-3 flex items-center">
        <i class="fas fa-shield-halved text-blue-500 mr-2"></i>
        БДУ ФСТЭК
    </h4>
    <div class="space-y-2">
        <div class="flex justify-between">
            <span class="text-blue-700">BDU ID:</span>
            <span id="view-bdu-id" class="font-mono font-semibold text-blue-900"></span>
        </div>
        <div class="flex justify-between">
            <span class="text-blue-700">Дата публикации:</span>
            <span id="view-bdu-published" class="font-medium text-sm"></span>
        </div>
        <div class="flex justify-between">
            <span class="text-blue-700">Статус БДУ:</span>
            <span id="view-bdu-status" class="font-medium"></span>
        </div>
        <div class="flex justify-between">
            <span class="text-blue-700">Класс уязвимости:</span>
            <span id="view-vulnerability-class" class="font-medium"></span>
        </div>
        <a id="view-bdu-link" href="#" target="_blank" 
           class="inline-flex items-center text-sm text-blue-600 hover:text-blue-800">
            <i class="fas fa-external-link-alt mr-2"></i>
            Открыть в БДУ ФСТЭК
        </a>
    </div>
</div>
```

#### 5.1.2 Блок информации о ПО
```html
<!-- Информация о ПО -->
<div class="bg-purple-50 rounded-xl p-4">
    <h4 class="font-semibold text-purple-900 mb-3 flex items-center">
        <i class="fas fa-server text-purple-500 mr-2"></i>
        Уязвимое программное обеспечение
    </h4>
    <div class="space-y-2">
        <div>
            <span class="text-purple-700 font-medium">Вендор:</span>
            <span id="view-vendor" class="ml-2"></span>
        </div>
        <div>
            <span class="text-purple-700 font-medium">Продукт:</span>
            <span id="view-product" class="ml-2"></span>
        </div>
        <div>
            <span class="text-purple-700 font-medium">Версии:</span>
            <span id="view-versions" class="ml-2 text-sm"></span>
        </div>
        <div>
            <span class="text-purple-700 font-medium">Тип ПО:</span>
            <span id="view-software-type" class="ml-2"></span>
        </div>
        <div id="view-os-block">
            <span class="text-purple-700 font-medium">ОС:</span>
            <div id="view-os-list" class="mt-1 flex flex-wrap gap-1"></div>
        </div>
    </div>
</div>
```

#### 5.1.3 Блок эксплуатации
```html
<!-- Эксплуатация уязвимости -->
<div class="bg-red-50 rounded-xl p-4 border-2" id="exploit-block">
    <h4 class="font-semibold text-red-900 mb-3 flex items-center">
        <i class="fas fa-bomb text-red-600 mr-2"></i>
        Информация об эксплуатации
        <span id="exploit-badge" class="ml-auto px-3 py-1 rounded-full text-xs font-bold"></span>
    </h4>
    <div class="space-y-2">
        <div class="flex justify-between">
            <span class="text-red-700">Эксплойт доступен:</span>
            <span id="view-exploit-available" class="font-bold"></span>
        </div>
        <div class="flex justify-between">
            <span class="text-red-700">Тип эксплуатации:</span>
            <span id="view-exploit-type" class="font-medium"></span>
        </div>
        <div class="mt-2">
            <span class="text-red-700 font-medium">Способ эксплуатации:</span>
            <p id="view-exploitation-method" class="text-sm text-gray-700 mt-1 bg-white rounded-lg p-2"></p>
        </div>
    </div>
</div>
```

#### 5.1.4 Блок устранения
```html
<!-- Устранение уязвимости -->
<div class="bg-green-50 rounded-xl p-4">
    <h4 class="font-semibold text-green-900 mb-3 flex items-center">
        <i class="fas fa-wrench text-green-600 mr-2"></i>
        Устранение
    </h4>
    <div class="space-y-2">
        <div>
            <span class="text-green-700 font-medium">Способ устранения:</span>
            <span id="view-remediation-method" class="ml-2"></span>
        </div>
        <div>
            <span class="text-green-700 font-medium">Дата устранения:</span>
            <span id="view-remediation-date" class="ml-2"></span>
        </div>
        <div class="mt-2">
            <span class="text-green-700 font-medium">Информация об устранении:</span>
            <p id="view-remediation-info" class="text-sm text-gray-700 mt-1 bg-white rounded-lg p-2"></p>
        </div>
    </div>
</div>
```

### 5.2 Фильтры в списке уязвимостей

**Добавить новые фильтры:**

```html
<!-- Фильтр по вендору -->
<div>
    <label class="block text-sm font-medium text-gray-700 mb-2">Вендор</label>
    <select name="vendor" class="w-full px-4 py-2 border rounded-lg">
        <option value="">Все вендоры</option>
        <!-- Динамически из БД -->
    </select>
</div>

<!-- Фильтр по наличию эксплойта -->
<div>
    <label class="flex items-center space-x-2">
        <input type="checkbox" name="has_exploit" class="rounded">
        <span class="text-sm font-medium text-gray-700">Только с эксплойтом</span>
    </label>
</div>

<!-- Фильтр по источнику -->
<div>
    <label class="block text-sm font-medium text-gray-700 mb-2">Источник</label>
    <select name="source" class="w-full px-4 py-2 border rounded-lg">
        <option value="">Все источники</option>
        <option value="bdu">БДУ ФСТЭК</option>
        <option value="nvd">NVD</option>
        <option value="both">БДУ + NVD</option>
    </select>
</div>

<!-- Фильтр по дате выявления -->
<div class="grid grid-cols-2 gap-2">
    <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">Выявлена с</label>
        <input type="date" name="discovered_from" class="w-full px-4 py-2 border rounded-lg">
    </div>
    <div>
        <label class="block text-sm font-medium text-gray-700 mb-2">Выявлена до</label>
        <input type="date" name="discovered_to" class="w-full px-4 py-2 border rounded-lg">
    </div>
</div>
```

### 5.3 JavaScript обновления

**Файл: `static/js/main.js` (или создать `static/js/bdu.js`)**

Добавить функции для отображения БДУ данных:

```javascript
function showVulnerabilityDetails(vulnId) {
    fetch(`/api/vulnerabilities/${vulnId}`)
        .then(response => response.json())
        .then(data => {
            // Существующие поля...
            
            // БДУ информация
            if (data.bdu_id) {
                document.getElementById('bdu-info-block').style.display = 'block';
                document.getElementById('view-bdu-id').textContent = data.bdu_id;
                document.getElementById('view-bdu-published').textContent = 
                    formatDate(data.bdu_published_date);
                document.getElementById('view-bdu-status').textContent = 
                    data.bdu_status || 'Не указан';
                document.getElementById('view-vulnerability-class').textContent = 
                    data.vulnerability_class || 'Не указан';
                document.getElementById('view-bdu-link').href = 
                    `https://bdu.fstec.ru/vul/${data.bdu_id}`;
            } else {
                document.getElementById('bdu-info-block').style.display = 'none';
            }
            
            // Информация о ПО
            document.getElementById('view-vendor').textContent = data.vendor || 'Не указан';
            document.getElementById('view-product').textContent = data.product_name || 'Не указан';
            document.getElementById('view-versions').textContent = 
                data.affected_versions || 'Не указано';
            document.getElementById('view-software-type').textContent = 
                data.software_type || 'Не указан';
            
            // ОС
            if (data.operating_systems && data.operating_systems.length > 0) {
                const osList = document.getElementById('view-os-list');
                osList.innerHTML = data.operating_systems.map(os => 
                    `<span class="px-2 py-1 bg-purple-200 text-purple-800 rounded text-xs">${os}</span>`
                ).join('');
            }
            
            // Эксплойт
            const exploitBlock = document.getElementById('exploit-block');
            const exploitBadge = document.getElementById('exploit-badge');
            if (data.exploit_available) {
                exploitBlock.classList.add('border-red-500');
                exploitBadge.textContent = '⚠️ ЭКСПЛОЙТ ДОСТУПЕН';
                exploitBadge.className += ' bg-red-600 text-white';
                document.getElementById('view-exploit-available').innerHTML = 
                    '<span class="text-red-600 font-bold">ДА</span>';
            } else {
                exploitBadge.textContent = '✓ Эксплойт не обнаружен';
                exploitBadge.className += ' bg-green-600 text-white';
                document.getElementById('view-exploit-available').innerHTML = 
                    '<span class="text-green-600">Нет</span>';
            }
            
            document.getElementById('view-exploit-type').textContent = 
                translateExploitType(data.exploit_type);
            document.getElementById('view-exploitation-method').textContent = 
                data.exploitation_method || 'Информация отсутствует';
            
            // Устранение
            document.getElementById('view-remediation-method').textContent = 
                data.remediation_method || 'Не указан';
            document.getElementById('view-remediation-date').textContent = 
                formatDate(data.remediation_date) || 'Не устранена';
            document.getElementById('view-remediation-info').textContent = 
                data.remediation_info || 'Информация отсутствует';
            
            // Открыть модальное окно
            openViewModal();
        });
}

function translateExploitType(type) {
    const types = {
        'remote': 'Удаленная эксплуатация',
        'local': 'Локальная эксплуатация',
        'physical': 'Физический доступ',
        'network': 'Сетевая'
    };
    return types[type] || type || 'Не указан';
}
```

---

## 6. ИЗМЕНЕНИЯ В API

### 6.1 Обновление эндпоинтов

**Файл: `app.py`**

#### 6.1.1 GET `/api/vulnerabilities/<id>` - добавить БДУ поля

```python
@app.route('/api/vulnerabilities/<int:vuln_id>', methods=['GET'])
def get_vulnerability_api(vuln_id):
    vuln = vulnerability_service.get_vulnerability(vuln_id)
    if not vuln:
        return jsonify({'error': 'Not found'}), 404
    
    return jsonify({
        # Существующие поля...
        
        # БДУ поля
        'bdu_id': vuln.bdu_id,
        'bdu_published_date': vuln.bdu_published_date.isoformat() if vuln.bdu_published_date else None,
        'bdu_status': vuln.bdu_status,
        
        # ПО
        'vendor': vuln.vendor,
        'product_name': vuln.product_name,
        'affected_versions': vuln.affected_versions,
        'software_type': vuln.software_type,
        'operating_systems': vuln.operating_systems,
        'hardware_platforms': vuln.hardware_platforms,
        
        # Техническая информация
        'date_discovered': vuln.date_discovered.isoformat() if vuln.date_discovered else None,
        'vulnerability_class': vuln.vulnerability_class,
        'error_type_russian': vuln.error_type_russian,
        
        # Эксплуатация
        'exploit_available': vuln.exploit_available,
        'exploit_type': vuln.exploit_type,
        'exploitation_method': vuln.exploitation_method,
        
        # Устранение
        'remediation_method': vuln.remediation_method,
        'remediation_info': vuln.remediation_info,
        'remediation_date': vuln.remediation_date.isoformat() if vuln.remediation_date else None,
        
        # Полные данные БДУ
        'bdu_raw_data': vuln.bdu_raw_data
    })
```

#### 6.1.2 GET `/api/vulnerabilities` - добавить фильтры

```python
@app.route('/api/vulnerabilities', methods=['GET'])
def list_vulnerabilities_api():
    # Существующие фильтры...
    
    # Новые фильтры
    vendor = request.args.get('vendor')
    product = request.args.get('product')
    has_exploit = request.args.get('has_exploit') == 'true'
    source = request.args.get('source')  # 'bdu', 'nvd', 'both'
    discovered_from = request.args.get('discovered_from')
    discovered_to = request.args.get('discovered_to')
    
    # Применить фильтры в запросе к БД...
```

#### 6.1.3 POST `/api/bdu/sync` - новый эндпоинт для синхронизации

```python
@app.route('/api/bdu/sync', methods=['POST'])
@admin_required
def sync_bdu_vulnerabilities():
    """
    Синхронизация уязвимостей с БДУ ФСТЭК
    Парсит последние записи и обновляет существующие
    """
    try:
        from services.parsers.bdu_web_parser import BDUWebParser
        
        parser = BDUWebParser()
        result = parser.sync_latest(limit=100)
        
        return jsonify({
            'success': True,
            'synced': result['synced'],
            'updated': result['updated'],
            'errors': result['errors']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

#### 6.1.4 GET `/api/vendors` - список вендоров

```python
@app.route('/api/vendors', methods=['GET'])
def get_vendors_list():
    """Получить список всех вендоров для фильтра"""
    vendors = vulnerability_service.get_unique_vendors()
    return jsonify({'vendors': vendors})
```

---

## 7. ОБНОВЛЕНИЕ СЕРВИСНОГО СЛОЯ

### 7.1 Файл: `services/vulnerability_service.py`

Добавить методы для работы с БДУ данными:

```python
def get_vulnerabilities_by_vendor(self, vendor: str, limit=50):
    """Получить уязвимости конкретного вендора"""
    pass

def get_vulnerabilities_with_exploits(self, limit=50):
    """Получить уязвимости с доступными эксплойтами"""
    pass

def get_bdu_vulnerabilities(self, limit=50):
    """Получить только БДУ уязвимости"""
    pass

def get_unique_vendors(self):
    """Получить список уникальных вендоров"""
    pass

def update_bdu_data(self, vuln_id: int, bdu_data: dict):
    """Обновить БДУ данные для существующей уязвимости"""
    pass

def merge_bdu_with_nvd(self, cve_id: str, bdu_id: str):
    """Объединить данные БДУ и NVD для одной уязвимости"""
    pass
```

---

## 8. НОВЫЙ ПАРСЕР БДУ

### 8.1 Файл: `services/parsers/bdu_web_parser.py` (СОЗДАТЬ НОВЫЙ)

```python
"""
Парсер БДУ ФСТЭК для автоматической синхронизации уязвимостей
"""

import requests
from bs4 import BeautifulSoup
from datetime import datetime
from typing import Dict, List, Optional
import re

class BDUWebParser:
    BASE_URL = "https://bdu.fstec.ru"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (VulnerabilityManager/1.0)'
        })
    
    def fetch_vulnerability(self, bdu_id: str) -> Optional[Dict]:
        """
        Получить данные уязвимости по BDU ID
        
        Args:
            bdu_id: Идентификатор BDU (например, "2026-00669" или "BDU:2026-00669")
        
        Returns:
            Dict с полными данными уязвимости или None
        """
        # Нормализация ID
        clean_id = bdu_id.replace('BDU:', '').strip()
        url = f"{self.BASE_URL}/vul/{clean_id}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            return self._parse_vulnerability_page(response.text, bdu_id)
        except Exception as e:
            print(f"❌ Ошибка при получении {bdu_id}: {e}")
            return None
    
    def fetch_latest_vulnerabilities(self, limit: int = 50) -> List[Dict]:
        """
        Получить последние уязвимости из БДУ
        
        Args:
            limit: Количество записей для получения
        
        Returns:
            List[Dict] список уязвимостей
        """
        url = f"{self.BASE_URL}/vul"
        params = {'size': limit, 'page': 0}
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            return self._parse_list_page(response.text)
        except Exception as e:
            print(f"❌ Ошибка при получении списка: {e}")
            return []
    
    def _parse_vulnerability_page(self, html: str, bdu_id: str) -> Dict:
        """
        Парсинг страницы паспорта уязвимости
        
        Returns:
            Dict со всеми полями БДУ
        """
        soup = BeautifulSoup(html, 'html.parser')
        
        data = {
            'bdu_id': bdu_id,
            'source': 'bdu_fstec'
        }
        
        # Парсинг заголовка
        title_elem = soup.find('h1', class_='vulnerability-title')
        if title_elem:
            data['title'] = title_elem.text.strip()
        
        # Парсинг таблицы с полями
        # TODO: Реализовать детальный парсинг в зависимости от структуры HTML
        # Это требует изучения реальной HTML структуры страницы БДУ
        
        table_rows = soup.find_all('tr')
        for row in table_rows:
            cells = row.find_all('td')
            if len(cells) >= 2:
                field_name = cells[0].text.strip()
                field_value = cells[1].text.strip()
                
                # Маппинг полей
                if 'Идентификатор' in field_name and 'CVE' in field_value:
                    data['cve_id'] = self._extract_cve(field_value)
                elif 'Вендор' in field_name:
                    data['vendor'] = field_value
                elif 'Название ПО' in field_name or 'Наименование ПО' in field_name:
                    data['product_name'] = field_value
                elif 'Версия ПО' in field_name:
                    data['affected_versions'] = field_value
                elif 'CVSS' in field_name:
                    # Парсинг CVSS
                    pass
                # ... и так далее для всех полей
        
        return data
    
    def _parse_list_page(self, html: str) -> List[Dict]:
        """Парсинг списка уязвимостей"""
        # TODO: Реализовать парсинг списка
        pass
    
    def _extract_cve(self, text: str) -> Optional[str]:
        """Извлечь CVE ID из текста"""
        match = re.search(r'CVE-\d{4}-\d+', text)
        return match.group(0) if match else None
    
    def sync_with_database(self, vulnerabilities: List[Dict]):
        """
        Синхронизировать полученные уязвимости с базой данных
        
        Args:
            vulnerabilities: Список словарей с данными уязвимостей
        
        Returns:
            Dict с результатами синхронизации
        """
        from services.vulnerability_service import VulnerabilityService
        
        service = VulnerabilityService()
        
        synced = 0
        updated = 0
        errors = []
        
        for vuln_data in vulnerabilities:
            try:
                # Проверить, существует ли уязвимость
                existing = None
                
                if vuln_data.get('bdu_id'):
                    existing = service.get_by_bdu_id(vuln_data['bdu_id'])
                
                if not existing and vuln_data.get('cve_id'):
                    existing = service.get_by_cve_id(vuln_data['cve_id'])
                
                if existing:
                    # Обновить существующую
                    service.update_bdu_data(existing.id, vuln_data)
                    updated += 1
                else:
                    # Создать новую
                    service.create_from_bdu(vuln_data)
                    synced += 1
                    
            except Exception as e:
                errors.append(f"BDU {vuln_data.get('bdu_id')}: {str(e)}")
        
        return {
            'synced': synced,
            'updated': updated,
            'errors': errors
        }
```

---

## 9. МИГРАЦИЯ ДАННЫХ

### 9.1 Скрипт миграции: `scripts/migration/add_bdu_fields.sql`

```sql
-- Миграция для добавления БДУ полей
-- Дата: 2026-01-22
-- Описание: Добавление полей для поддержки БДУ ФСТЭК

BEGIN;

-- Добавление новых колонок
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_id VARCHAR(50);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_published_date TIMESTAMP;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_status VARCHAR(100);

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vendor VARCHAR(255);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS product_name VARCHAR(255);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS affected_versions TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS software_type VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS operating_systems TEXT[];
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS hardware_platforms TEXT[];

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS date_discovered DATE;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vulnerability_class VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS error_type_russian TEXT;

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS exploit_available BOOLEAN DEFAULT FALSE;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS exploit_type VARCHAR(50);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS exploitation_method TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediation_method VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediation_info TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS remediation_date DATE;

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS bdu_raw_data JSONB;

-- Создание уникального индекса для BDU ID
CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerabilities_bdu_id_unique ON vulnerabilities(bdu_id);

-- Создание индексов для поиска
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vendor ON vulnerabilities(vendor);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_product ON vulnerabilities(product_name);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_exploit_available ON vulnerabilities(exploit_available);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_date_discovered ON vulnerabilities(date_discovered);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_software_type ON vulnerabilities(software_type);

-- GIN индекс для массивов
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_os_gin ON vulnerabilities USING GIN(operating_systems);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_platforms_gin ON vulnerabilities USING GIN(hardware_platforms);

-- Комментарии к новым полям
COMMENT ON COLUMN vulnerabilities.bdu_id IS 'Идентификатор БДУ ФСТЭК (формат: BDU:YYYY-XXXXX)';
COMMENT ON COLUMN vulnerabilities.date_discovered IS 'Дата выявления уязвимости (отличается от created_date)';
COMMENT ON COLUMN vulnerabilities.exploit_available IS 'Доступен ли публичный эксплойт для уязвимости';
COMMENT ON COLUMN vulnerabilities.vendor IS 'Производитель уязвимого ПО';
COMMENT ON COLUMN vulnerabilities.product_name IS 'Название уязвимого продукта';

COMMIT;
```

### 9.2 Скрипт обратной миграции существующих данных

**Файл: `scripts/migration/backfill_bdu_data.py`**

```python
#!/usr/bin/env python3
"""
Обратная миграция существующих данных
Извлекает BDU ID и другую структурированную информацию из description/title
"""

import re
from services.vulnerability_service import VulnerabilityService

def extract_bdu_id(text: str) -> str:
    """Извлечь BDU ID из текста"""
    if not text:
        return None
    match = re.search(r'BDU[:\s-]*(\d{4}-\d+)', text, re.IGNORECASE)
    if match:
        return f"BDU:{match.group(1)}"
    return None

def extract_vendor_product(description: str):
    """Попытаться извлечь вендора и продукт из описания"""
    # Поиск паттернов типа "[ПО] Вендор: X, продукт: Y"
    match = re.search(r'\[ПО\]\s*Вендор:\s*([^,]+),\s*продукт:\s*([^,]+)', description)
    if match:
        return {
            'vendor': match.group(1).strip(),
            'product': match.group(2).strip()
        }
    return {}

def backfill_bdu_fields():
    """Заполнить БДУ поля для существующих записей"""
    service = VulnerabilityService()
    
    # Получить все уязвимости
    all_vulns = service.get_all_vulnerabilities_unlimited()
    
    updated = 0
    for vuln in all_vulns:
        changes = {}
        
        # Извлечь BDU ID из title или description
        bdu_id = extract_bdu_id(vuln.title) or extract_bdu_id(vuln.description)
        if bdu_id and not vuln.bdu_id:
            changes['bdu_id'] = bdu_id
        
        # Извлечь вендора и продукт
        if vuln.description:
            sw_info = extract_vendor_product(vuln.description)
            if sw_info:
                changes.update(sw_info)
        
        # Обновить если есть изменения
        if changes:
            service.update_vulnerability(vuln.id, **changes)
            updated += 1
            print(f"✅ Обновлена уязвимость {vuln.id}: {changes}")
    
    print(f"\n🎉 Обновлено записей: {updated} из {len(all_vulns)}")

if __name__ == '__main__':
    backfill_bdu_fields()
```

---

## 10. ДАШБОРД И АНАЛИТИКА

### 10.1 Новые метрики для дашборда

Добавить в `templates/dashboard.html`:

```html
<!-- БДУ Статистика -->
<div class="bg-gradient-to-br from-blue-500 to-blue-600 rounded-2xl shadow-xl p-6 text-white">
    <div class="flex items-center justify-between mb-4">
        <div>
            <p class="text-blue-100 text-sm font-medium">БДУ ФСТЭК</p>
            <p class="text-3xl font-bold" id="bdu-count">{{ bdu_count }}</p>
        </div>
        <div class="bg-white bg-opacity-20 p-3 rounded-xl">
            <i class="fas fa-shield-halved text-2xl"></i>
        </div>
    </div>
    <div class="flex items-center text-sm">
        <span class="text-blue-100">Синхронизировано уязвимостей</span>
    </div>
</div>

<!-- Уязвимости с эксплойтами -->
<div class="bg-gradient-to-br from-red-500 to-red-600 rounded-2xl shadow-xl p-6 text-white">
    <div class="flex items-center justify-between mb-4">
        <div>
            <p class="text-red-100 text-sm font-medium">С эксплойтами</p>
            <p class="text-3xl font-bold" id="exploit-count">{{ exploit_count }}</p>
        </div>
        <div class="bg-white bg-opacity-20 p-3 rounded-xl">
            <i class="fas fa-bomb text-2xl"></i>
        </div>
    </div>
    <div class="flex items-center text-sm">
        <span class="text-red-100">Требуют немедленного внимания</span>
    </div>
</div>
```

### 10.2 Графики и визуализация

Добавить новые графики:

1. **График: Источники уязвимостей (БДУ vs NVD vs Оба)**
2. **График: Топ-10 вендоров по количеству уязвимостей**
3. **График: Уязвимости с эксплойтами по времени**
4. **График: Время от выявления до устранения**

---

## 11. ТЕСТИРОВАНИЕ

### 11.1 Unit-тесты

**Файл: `tests/test_bdu_parser.py`** (СОЗДАТЬ)

```python
import unittest
from services.parsers.bdu_web_parser import BDUWebParser

class TestBDUParser(unittest.TestCase):
    
    def setUp(self):
        self.parser = BDUWebParser()
    
    def test_extract_cve(self):
        """Тест извлечения CVE ID"""
        text = "CVE-2024-12345, CVE-2024-67890"
        cve = self.parser._extract_cve(text)
        self.assertIsNotNone(cve)
        self.assertTrue(cve.startswith('CVE-'))
    
    def test_fetch_vulnerability(self):
        """Тест получения данных уязвимости"""
        # FIXME: Требует доступ к реальному API БДУ или моку
        pass
    
    # ... дополнительные тесты
```

### 11.2 Интеграционные тесты

**Файл: `tests/test_bdu_integration.py`** (СОЗДАТЬ)

```python
import unittest
from services.parsers.bdu_web_parser import BDUWebParser
from services.vulnerability_service import VulnerabilityService

class TestBDUIntegration(unittest.TestCase):
    
    def test_full_sync_flow(self):
        """Тест полного цикла синхронизации БДУ"""
        parser = BDUWebParser()
        service = VulnerabilityService()
        
        # 1. Получить данные из БДУ
        vulns = parser.fetch_latest_vulnerabilities(limit=5)
        self.assertGreater(len(vulns), 0)
        
        # 2. Синхронизировать с БД
        result = parser.sync_with_database(vulns)
        
        # 3. Проверить результаты
        self.assertIn('synced', result)
        self.assertIn('updated', result)
```

---

## 12. ДОКУМЕНТАЦИЯ

### 12.1 Обновление README

Добавить секцию о БДУ ФСТЭК:

```markdown
## Интеграция с БДУ ФСТЭК

Система поддерживает импорт и синхронизацию уязвимостей из Банка данных угроз безопасности информации ФСТЭК России.

### Поддерживаемые поля БДУ:

- Идентификатор BDU
- Информация о вендоре и продукте
- Статус подтверждения производителем
- Информация об эксплойтах
- Способы устранения
- И многое другое...

### Синхронизация с БДУ:

```bash
# Импорт из Excel
python scripts/import_bdu_from_excel.py

# Веб-парсинг (требует реализации)
python services/parsers/bdu_web_parser.py
```

### API для работы с БДУ:

- `GET /api/vulnerabilities?source=bdu` - только БДУ уязвимости
- `GET /api/vendors` - список вендоров
- `POST /api/bdu/sync` - синхронизация с БДУ
```

### 12.2 API документация

**Файл: `docs/API_BDU.md`** (СОЗДАТЬ)

Детальное описание всех API эндпоинтов для работы с БДУ данными.

---

## 13. ПРИОРИТИЗАЦИЯ ЗАДАЧ

### 🔴 КРИТИЧЕСКИЙ ПРИОРИТЕТ (Фаза 1)

**Срок: 1-2 недели**

1. ✅ **Миграция БД** - добавить основные поля БДУ
   - Поля: `bdu_id`, `vendor`, `product_name`, `exploit_available`
   - Индексы для быстрого поиска
   
2. ✅ **Обновление модели данных**
   - Класс `Vulnerability` с новыми полями
   - Обновление `from_db_row()`
   
3. ✅ **Обновление парсера Excel**
   - Извлечение `bdu_id` в отдельное поле
   - Парсинг информации об эксплойтах
   - Извлечение вендора и продукта
   
4. ✅ **Обновление API**
   - GET `/api/vulnerabilities/<id>` с БДУ полями
   - Фильтр по эксплойтам
   
5. ✅ **Обновление UI**
   - Отображение BDU ID
   - Блок информации об эксплойтах
   - Информация о вендоре/продукте

### 🟡 ВЫСОКИЙ ПРИОРИТЕТ (Фаза 2)

**Срок: 2-3 недели**

1. ⏳ **Веб-парсер БДУ**
   - Базовая реализация парсинга страниц БДУ
   - Синхронизация новых записей
   
2. ⏳ **Расширенные фильтры**
   - Фильтр по вендору
   - Фильтр по источнику (БДУ/NVD)
   - Фильтр по дате выявления
   
3. ⏳ **Дополнительные UI блоки**
   - Блок устранения
   - Технические детали ПО
   - Информация о платформах
   
4. ⏳ **Обратная миграция данных**
   - Скрипт для извлечения БДУ данных из существующих записей

### 🟢 СРЕДНИЙ ПРИОРИТЕТ (Фаза 3)

**Срок: 3-4 недели**

1. ⏳ **Аналитика и дашборд**
   - Статистика по БДУ
   - Графики по вендорам
   - Метрики эксплойтов
   
2. ⏳ **Автоматическая синхронизация**
   - Cron-задача для регулярного парсинга БДУ
   - Уведомления о новых критических уязвимостях
   
3. ⏳ **Экспорт отчетов**
   - Генерация отчетов по БДУ
   - Экспорт в форматы для ФСТЭК

### 🔵 НИЗКИЙ ПРИОРИТЕТ (Фаза 4)

**Срок: 1-2 месяца**

1. ⏳ **Расширенная валидация**
   - Проверка корректности данных БДУ
   - Сопоставление с NVD данными
   
2. ⏳ **Кэширование**
   - Кэш для часто запрашиваемых БДУ данных
   
3. ⏳ **Полнотекстовый поиск**
   - Поиск по русскоязычным описаниям БДУ

---

## 14. РИСКИ И ОГРАНИЧЕНИЯ

### 14.1 Технические риски

1. **Структура HTML БДУ может измениться**
   - Решение: Регулярное тестирование парсера
   - Fallback на импорт из Excel
   
2. **Ограничения по частоте запросов к БДУ**
   - Решение: Уважительный rate limiting
   - Кэширование результатов
   
3. **Несовпадение данных БДУ и NVD**
   - Решение: Логика объединения данных
   - Приоритет актуальных данных

### 14.2 Правовые вопросы

1. **Лицензия на использование данных БДУ**
   - Проверить условия использования
   - Соблюдать авторские права ФСТЭК

### 14.3 Производительность

1. **Увеличение размера таблицы**
   - +15-20 полей на запись
   - Решение: Оптимизация индексов
   
2. **Сложные запросы с массивами**
   - GIN индексы для TEXT[]
   - Pagination для больших выборок

---

## 15. МЕТРИКИ УСПЕХА

### KPI для оценки внедрения:

1. **Покрытие данными БДУ**: > 80% уязвимостей с BDU ID
2. **Скорость синхронизации**: < 5 минут для 100 записей
3. **Точность парсинга**: > 95% корректно распознанных полей
4. **Удобство UI**: снижение времени на анализ уязвимости на 30%
5. **Использование фильтров**: > 50% пользователей используют новые фильтры

---

## 16. ЗАКЛЮЧЕНИЕ

### Ключевые выводы:

1. **БДУ ФСТЭК имеет богатую структуру данных**, которая существенно отличается от NVD
   
2. **Критически важные отсутствующие поля**:
   - `bdu_id` - для идентификации российских уязвимостей
   - `exploit_available` - для приоритизации угроз
   - `vendor` и `product_name` - для структурированной фильтрации
   
3. **Необходима миграция БД** - добавление ~20 новых полей
   
4. **Требуется обновление всех слоев**:
   - База данных (миграция)
   - Модели (entities.py)
   - Сервисы (парсеры, API)
   - Frontend (UI/UX, фильтры)
   
5. **Поэтапное внедрение** - от критических полей к полной интеграции

### Следующие шаги:

1. ✅ Утвердить список полей для добавления
2. ⏳ Выполнить миграцию БД (Фаза 1)
3. ⏳ Обновить парсер Excel
4. ⏳ Реализовать отображение в UI
5. ⏳ Разработать веб-парсер БДУ
6. ⏳ Добавить аналитику и дашборды

---

**Подготовил:** AI Assistant  
**Дата:** 22 января 2026  
**Версия документа:** 1.0

---

## ПРИЛОЖЕНИЕ A: SQL скрипты

См. `scripts/migration/add_bdu_fields.sql`

## ПРИЛОЖЕНИЕ B: Примеры кода

См. секции 8-9 данного документа

## ПРИЛОЖЕНИЕ C: Скриншоты UI (TODO)

Необходимо добавить скриншоты после реализации UI изменений

