# БДУ ФСТЭК - Краткое резюме необходимых изменений

**🎯 Цель:** Интеграция полной структуры паспорта уязвимости БДУ ФСТЭК в систему

---

## ❌ ЧТО ОТСУТСТВУЕТ (критично)

### 1. Идентификация БДУ
- **`bdu_id`** - идентификатор BDU:YYYY-XXXXX (сейчас только в title)
- **`bdu_status`** - статус подтверждения производителем

### 2. Информация о ПО
- **`vendor`** - производитель (нет структурированного поля!)
- **`product_name`** - название продукта
- **`affected_versions`** - затронутые версии
- **`software_type`** - тип ПО (прикладное/системное)
- **`operating_systems[]`** - список ОС
- **`hardware_platforms[]`** - платформы (x86, ARM и т.д.)

### 3. Эксплуатация (!)
- **`exploit_available`** - наличие эксплойта (⚠️ критично!)
- **`exploit_type`** - удаленная/локальная
- **`exploitation_method`** - способ эксплуатации

### 4. Устранение
- **`remediation_method`** - способ устранения
- **`remediation_info`** - информация о патче
- **`remediation_date`** - дата исправления

### 5. Даты
- **`date_discovered`** - дата выявления (≠ created_date!)

---

## 📊 СРАВНЕНИЕ: СЕЙЧАС vs НУЖНО

| Блок | Текущее состояние | Что добавить |
|------|-------------------|--------------|
| **Идентификация** | ✅ CVE ID есть | ❌ BDU ID отсутствует |
| **Информация о ПО** | ❌ Все в description | ❌ 6 структурированных полей |
| **Эксплуатация** | ❌ Нет ничего | ❌ 3 критичных поля |
| **Устранение** | ❌ Частично в описании | ❌ 3 поля для патчей |
| **CVSS** | ✅ Хорошо реализовано | ✅ OK |
| **Ссылки** | ✅ Есть JSONB | ✅ OK |

---

## 🔧 ИЗМЕНЕНИЯ В БД (минимум)

```sql
-- КРИТИЧНО (Фаза 1)
ALTER TABLE vulnerabilities ADD COLUMN bdu_id VARCHAR(50) UNIQUE;
ALTER TABLE vulnerabilities ADD COLUMN vendor VARCHAR(255);
ALTER TABLE vulnerabilities ADD COLUMN product_name VARCHAR(255);
ALTER TABLE vulnerabilities ADD COLUMN exploit_available BOOLEAN DEFAULT FALSE;
ALTER TABLE vulnerabilities ADD COLUMN date_discovered DATE;

-- ВЫСОКИЙ ПРИОРИТЕТ (Фаза 2)  
ALTER TABLE vulnerabilities ADD COLUMN affected_versions TEXT;
ALTER TABLE vulnerabilities ADD COLUMN bdu_status VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN exploit_type VARCHAR(50);
ALTER TABLE vulnerabilities ADD COLUMN remediation_method VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN remediation_date DATE;

-- СРЕДНИЙ ПРИОРИТЕТ (Фаза 3)
ALTER TABLE vulnerabilities ADD COLUMN software_type VARCHAR(100);
ALTER TABLE vulnerabilities ADD COLUMN operating_systems TEXT[];
ALTER TABLE vulnerabilities ADD COLUMN exploitation_method TEXT;
ALTER TABLE vulnerabilities ADD COLUMN remediation_info TEXT;

-- Индексы
CREATE UNIQUE INDEX idx_bdu_id ON vulnerabilities(bdu_id);
CREATE INDEX idx_vendor ON vulnerabilities(vendor);
CREATE INDEX idx_exploit ON vulnerabilities(exploit_available);
```

---

## 🎨 ИЗМЕНЕНИЯ В UI

### Новые блоки в модальном окне:

1. **📘 Блок БДУ ФСТЭК**
   - BDU ID с ссылкой на сайт
   - Статус БДУ
   - Дата публикации

2. **💻 Блок информации о ПО**
   - Вендор / Продукт / Версии
   - Тип ПО
   - Поддерживаемые ОС

3. **💣 Блок эксплуатации (с предупреждением!)**
   - Наличие эксплойта (красный бейдж если есть)
   - Тип эксплуатации
   - Способ эксплуатации

4. **🔧 Блок устранения**
   - Способ устранения
   - Дата исправления
   - Информация о патче

### Новые фильтры:

- ☑️ **Только с эксплойтом** (checkbox)
- 🏢 **Фильтр по вендору** (dropdown)
- 📦 **Фильтр по продукту** (dropdown)
- 🔍 **Источник**: БДУ / NVD / Оба
- 📅 **Дата выявления**: от - до

---

## 📝 ИЗМЕНЕНИЯ В ПАРСЕРЕ

**Файл:** `scripts/import_bdu_from_excel.py`

### Сейчас:
```python
# BDU ID идет в title
title = " - ".join([bdu_id, name])

# Вся информация о ПО - в description
description = f"Вендор: {vendor}, Продукт: {product}..."
```

### Нужно:
```python
# BDU ID в отдельное поле
vuln.bdu_id = normalize_bdu_id(bdu_id)

# Структурированные данные о ПО
vuln.vendor = vendor
vuln.product_name = product
vuln.affected_versions = version

# Информация об эксплойтах
vuln.exploit_available = detect_exploit(exploit_text)
vuln.exploit_type = parse_exploit_type(exploit_method)
```

---

## 🚀 API ИЗМЕНЕНИЯ

### Новые эндпоинты:

```python
GET  /api/vendors                    # Список вендоров
GET  /api/vulnerabilities?vendor=X   # Фильтр по вендору
GET  /api/vulnerabilities?has_exploit=true  # Только с эксплойтом
POST /api/bdu/sync                   # Синхронизация с БДУ
```

### Обновить существующие:

```python
GET /api/vulnerabilities/<id>
# Добавить в response:
{
  "bdu_id": "BDU:2026-00669",
  "vendor": "Microsoft",
  "product_name": "Windows Server",
  "exploit_available": true,
  "exploit_type": "remote",
  ...
}
```

---

## ⚡ ПРИОРИТЕТЫ (MVP)

### 🔴 Фаза 1 (1-2 недели) - МИНИМУМ
1. Миграция БД - добавить 5 критичных полей
2. Обновить модель `Vulnerability`
3. Обновить парсер Excel
4. Обновить API GET `/api/vulnerabilities/<id>`
5. Добавить отображение в UI

**Результат:** BDU ID, вендор, эксплойты видны в системе

### 🟡 Фаза 2 (2-3 недели) - РАСШИРЕНИЕ
1. Добавить остальные БДУ поля
2. Фильтры по вендору и эксплойтам
3. Блоки устранения в UI
4. Веб-парсер БДУ (базовый)

**Результат:** Полная поддержка БДУ структуры

### 🟢 Фаза 3 (3-4 недели) - АНАЛИТИКА
1. Дашборд с БДУ метриками
2. Автоматическая синхронизация
3. Отчеты по БДУ

**Результат:** Полноценная аналитика БДУ

---

## 📦 ФАЙЛЫ ДЛЯ ИЗМЕНЕНИЯ

### База данных:
- `scripts/migration/add_bdu_fields.sql` (создать)
- `models/init_database.py` (обновить)

### Backend:
- `models/entities.py` (добавить поля)
- `scripts/import_bdu_from_excel.py` (улучшить парсинг)
- `services/parsers/bdu_web_parser.py` (создать новый)
- `app.py` (обновить API)

### Frontend:
- `templates/vulnerabilities_list.html` (добавить блоки)
- `static/js/main.js` (добавить функции)
- CSS для новых блоков

---

## ⚠️ РИСКИ

1. **HTML структура БДУ может измениться** → fallback на Excel
2. **Увеличение размера БД** → оптимизация индексов
3. **Несовпадение БДУ и NVD данных** → логика объединения

---

## ✅ КРИТЕРИИ УСПЕХА

- [ ] ✅ BDU ID отображается во всех уязвимостях из БДУ
- [ ] ✅ Фильтр по вендору работает
- [ ] ⚠️ Эксплойты выделяются красным
- [ ] 📊 Статистика БДУ на дашборде
- [ ] 🔄 Синхронизация с БДУ раз в день

---

## 📚 ДОКУМЕНТЫ

- **Полный анализ:** `docs/BDU_STRUCTURE_ANALYSIS_2026.md` (70+ страниц)
- **Это резюме:** `docs/BDU_QUICK_SUMMARY.md`
- **Миграция:** `scripts/migration/add_bdu_fields.sql`

---

**Главное:** Сейчас БДУ данные "размазаны" по description. Нужно сделать структурированные поля для эффективной работы!

