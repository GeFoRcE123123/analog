# Инструкция по проверке логов парсинга

## Проблема
Парсинг возвращает 0 спарсено, 0 сохранено.

## Шаги для диагностики

### 1. Запустите парсинг через UI
- Перейдите на страницу "Парсеры"
- Нажмите "Запустить все парсеры"

### 2. Проверьте логи бэкенда

```bash
sshpass -p '123' ssh user@10.0.88.20 'docker logs vulnerability-backend --tail 300 -f'
```

Ищите следующие метки в логах:

#### Ключевые метки:
- `[PARSE_ALL]` - главный метод парсинга
- `[HTML]` - HTML парсер
- `[HTML_PARSER]` - методы HTML парсера
- `[REPO]` - операции с базой данных
- `✅` - успешные операции
- `❌` - ошибки
- `⚠️` - предупреждения

### 3. Что проверять в логах:

#### A. Инициализация парсеров:
```
✅ HTML парсер инициализирован
```
Если видите:
```
⚠️ HTML парсер не доступен: ...
```
→ Проблема в импорте/инициализации HTML парсера

#### B. Вызов parse_all:
```
🚀 [PARSE_ALL] Начало парсинга: sources=['ubuntu', 'debian'], limit=50
   [PARSE_ALL] html_parser=<...>, type=<class '...'>
```
Если `html_parser=None` → парсер не инициализирован

#### C. HTML парсинг:
```
🔍 [HTML] Проверка HTML парсера: html_parser=...
🔍 [HTML] Начинаем HTML парсинг источника: ubuntu, лимит: 50
🔍 [HTML_PARSER] parse_source вызван: source_name=ubuntu, limit=50
📋 [HTML_PARSER] Получен список из X CVE для парсинга: ...
```
Если список CVE пустой → проблема в `_get_fallback_cve_list`

#### D. Обработка CVE:
```
🔄 [1/3] Обрабатываем CVE-2024-TEST-001 из ubuntu
✅ [1/3] Обработана уязвимость CVE-2024-TEST-001: ...
```

#### E. Сохранение в БД:
```
💾 [REPO] Начинаем сохранение уязвимости: cve_id=CVE-2024-TEST-001
✅ [REPO] Уязвимость сохранена: cve_id=..., ID=...
```

### 4. Типичные проблемы и решения:

#### Проблема: HTML парсер не инициализирован
**Причина:** Ошибка импорта зависимостей (selenium, BeautifulSoup)
**Решение:** Проверить requirements.txt и установку зависимостей в Docker

#### Проблема: parse_source возвращает пустой список
**Причина:** Метод `_get_fallback_cve_list` не вызывается или возвращает пустой список
**Решение:** Проверить логи вызова `_get_cve_list`

#### Проблема: Данные не сохраняются в БД
**Причина:** Ошибка в методе `add()` репозитория
**Решение:** Проверить логи с меткой `[REPO]`

### 5. Проверка БД

```bash
sshpass -p '123' ssh user@10.0.88.11 'docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) FROM vulnerabilities;"'
```

### 6. Тестовый запрос API

```bash
curl -X POST http://10.0.88.20:5000/api/parsers/run-all \
  -H "Content-Type: application/json" \
  -d '{"sources":["ubuntu"],"limit_per_source":3}'
```

## Ожидаемый вывод в логах при успешном парсинге:

```
🚀 [PARSE_ALL] Начало парсинга: sources=['ubuntu'], limit=3
   [PARSE_ALL] html_parser=<services.html_vulnerability_parser.HTMLVulnerabilityParser object>, type=<class 'services.html_vulnerability_parser.HTMLVulnerabilityParser'>
🔍 [HTML] Проверка HTML парсера: html_parser=...
🔍 [HTML] Начинаем HTML парсинг источника: ubuntu, лимит: 3
🔍 [HTML_PARSER] parse_source вызван: source_name=ubuntu, limit=3
📋 Используем fallback список для ubuntu
🧪 ТЕСТОВЫЕ ДАННЫЕ: Используем 3 тестовых CVE
📋 [HTML_PARSER] Получен список из 3 CVE: ['CVE-2024-TEST-001', 'CVE-2024-TEST-002', 'CVE-2024-TEST-003']
🔄 [1/3] Обрабатываем CVE-2024-TEST-001 из ubuntu
✅ [1/3] Обработана уязвимость CVE-2024-TEST-001: [ТЕСТ] Ubuntu CVE-2024-TEST-001
...
✅ ubuntu: обработано 3 уязвимостей
💾 Сохранение 3 уязвимостей из ubuntu в БД...
💾 [REPO] Начинаем сохранение уязвимости: cve_id=CVE-2024-TEST-001
✅ [REPO] Уязвимость сохранена: cve_id=CVE-2024-TEST-001, ID=1
...
✅ Сохранено 3 уязвимостей из ubuntu в БД
✅ [PARSE_ALL] Парсинг завершен: спарсено=3, сохранено=3
```

