# 🟠 Grafana Parser - Быстрый старт

## 📋 Что было добавлено

### 1. **UI Фильтры** ✅
- В списке уязвимостей (`/vulnerabilities`) появился новый фильтр **"Источник"**
- Можно выбрать: Grafana, БДУ, NVD, RedHat, OSV
- Цветные бейджи источников отображаются рядом с категорией

### 2. **Страница парсеров** ✅
- В разделе `/parsers` появилась секция **"Grafana Security Advisories"**
- Оранжевый дизайн с настройками фильтров
- Подсказка по запуску через CLI

### 3. **Backend API** ✅
- Добавлен параметр `source` во все слои:
  - `app.py` → роуты
  - `vulnerability_service.py` → сервисный слой
  - `legacy_repositories.py` → SQL запросы
- Фильтрация работает через `WHERE source ILIKE '%grafana%'`

---

## 🚀 Как протестировать

### Шаг 1: Импортировать тестовые данные

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager

# Тестовый прогон (не сохраняет в БД)
python3 scripts/import_grafana_advisories.py --dry-run --limit 5

# Реальный импорт (только critical, первые 10)
python3 scripts/import_grafana_advisories.py --severity critical --limit 10
```

### Шаг 2: Открыть веб-интерфейс

1. Запустить приложение (если не запущено):
   ```bash
   python3 app.py
   ```

2. Открыть браузер: `http://localhost:5000`

### Шаг 3: Проверить список уязвимостей

1. Перейти в **"Управление уязвимостями"** (`/vulnerabilities`)
2. Найти фильтр **"Источник"**
3. Выбрать **"🟠 Grafana Labs"**
4. Нажать **"Применить"**
5. Проверить, что отображаются только Grafana уязвимости
6. Проверить, что рядом с категорией есть оранжевый бейдж **"🟠 Grafana"**

### Шаг 4: Проверить страницу парсеров

1. Перейти в **"Парсеры"** (`/parsers`)
2. Прокрутить до секции **"Grafana Security Advisories"** (оранжевый блок)
3. Проверить наличие настроек:
   - Фильтр по Severity
   - Фильтр по Продукту
   - Лимит
4. Увидеть подсказку с командой запуска

---

## 📊 Ожидаемые результаты

### В списке уязвимостей:
```
┌────────────────────────────────────────────────────┐
│ CVE-2025-41118                                     │
│ Grafana  🟠 Grafana                               │
│ Exposure of Storage Secret in Pyroscope           │
│ 🔴 Критический  CVSS: 9.1                         │
└────────────────────────────────────────────────────┘
```

### Фильтр источника:
```
Источник: [🟠 Grafana Labs ▼]
```

### В консоли (при импорте):
```
🚀 Starting Grafana Security Advisories sync...
📋 Fetching advisories list...
✅ Found 243 advisories

[1/10] Processing CVE-2025-41118...
   ➕ Created

[2/10] Processing CVE-2025-41115...
   ➕ Created

...

============================================================
📊 Sync completed!
   Total:   10
   New:     10
   Updated: 0
   Skipped: 0
   Errors:  0
============================================================
```

---

## 🔍 SQL Проверка

Проверить импортированные данные в БД:

```sql
-- Подсчитать Grafana уязвимости
SELECT COUNT(*) 
FROM turn 
WHERE source ILIKE '%grafana%';

-- Посмотреть первые 5
SELECT cve, name, cvss, source 
FROM turn 
WHERE source ILIKE '%grafana%' 
ORDER BY id DESC 
LIMIT 5;

-- Статистика по источникам
SELECT source, COUNT(*) as count 
FROM turn 
WHERE cve IS NOT NULL 
GROUP BY source 
ORDER BY count DESC;
```

---

## 🎯 Что делать, если...

### Не отображаются уязвимости Grafana
1. Проверить, что импорт прошел успешно (см. консоль)
2. Проверить в БД: `SELECT * FROM turn WHERE source ILIKE '%grafana%'`
3. Очистить кеш браузера (Ctrl+Shift+R)
4. Проверить логи app.py

### Фильтр не работает
1. Проверить, что в `app.py` добавлен параметр `source`
2. Проверить консоль браузера (F12) на ошибки
3. Проверить, что форма передает параметр: `/vulnerabilities?source=grafana`

### Бейджи не отображаются
1. Проверить, что в БД поле `source` заполнено
2. Проверить код в `templates/vulnerabilities_list.html` (строки 163-189)
3. Очистить кеш браузера

### Ошибка при импорте
```bash
# Проверить зависимости
pip3 install requests beautifulsoup4

# Проверить подключение к БД
python3 -c "from models.database import DatabaseManager; db = DatabaseManager(); print('DB OK')"

# Запустить с --debug
python3 scripts/import_grafana_advisories.py --debug --dry-run --limit 1
```

---

## 📂 Файлы для проверки

Если что-то не работает, проверить эти файлы:

1. **Backend:**
   - `app.py` (строка ~514: добавлен `source` параметр)
   - `services/vulnerability_service.py` (строка ~67: добавлен `source`)
   - `models/legacy_repositories.py` (строка ~1279: добавлен SQL фильтр)

2. **Frontend:**
   - `templates/vulnerabilities_list.html` (строки 95-110: фильтр)
   - `templates/vulnerabilities_list.html` (строки 163-189: бейджи)
   - `templates/parsers.html` (строка ~125: Grafana секция)

3. **Парсеры:**
   - `services/parsers/grafana_parser.py`
   - `services/parsers/grafana_mapper.py`
   - `scripts/import_grafana_advisories.py`

---

## 🎉 Готово!

Если все работает:
- ✅ Фильтр по источнику работает
- ✅ Бейджи отображаются
- ✅ Импорт завершается успешно
- ✅ SQL запросы находят данные

**Grafana интеграция успешна! 🟠**

---

## 📞 Дополнительная информация

- Полная документация: `docs/grafana_parser/README.md`
- Детали реализации: `GRAFANA_INTEGRATION_READY.md`
- Код парсера: `services/parsers/grafana_parser.py`

