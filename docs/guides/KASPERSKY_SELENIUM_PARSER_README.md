# 🔍 Парсер уязвимостей Kaspersky с Selenium

## 📋 Описание

Парсер для сбора информации об уязвимостях Kaspersky со страницы advisories с использованием Selenium для работы с динамическим контентом и выпадающими списками.

## 🚀 Установка

### 1. Установка зависимостей

```bash
pip install selenium>=4.15.0
pip install undetected-chromedriver>=3.5.0
```

Или через requirements.txt:

```bash
pip install -r requirements.txt
```

### 2. Установка Chrome/Chromium

Парсер использует Chrome/Chromium браузер. Убедитесь, что он установлен:

- **Linux:** `sudo apt-get install chromium-browser` или `sudo apt-get install google-chrome-stable`
- **macOS:** `brew install --cask google-chrome`
- **Windows:** Скачайте с https://www.google.com/chrome/

### 3. ChromeDriver

`undetected-chromedriver` автоматически скачает и настроит ChromeDriver, но можно установить вручную:

```bash
# Linux/macOS
pip install webdriver-manager

# Или скачайте вручную с https://chromedriver.chromium.org/
```

## 📝 Использование

### Вариант 1: Standalone скрипт

```bash
python services/legacy_parsers/kaspersky_selenium_standalone.py
```

### Вариант 2: Через UnifiedParserService

```python
from services.legacy_parsers.kaspersky_selenium_parser import KasperskySeleniumParser
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository

db_manager = DatabaseManager()
vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)

parser = KasperskySeleniumParser(
    vuln_repo,
    headless=False,  # True для headless режима
    use_undetected=True  # True для обхода обнаружения
)

results = parser.parse(limit=10)  # limit=None для всех
print(f"Спарсено: {results['parsed']}, Сохранено: {results['saved']}")
```

### Вариант 3: Через UnifiedParserService (после интеграции)

```python
from services.unified_parser_service import unified_parser_service

results = unified_parser_service.parse_all(
    enable_legacy_parsers=True,
    legacy_parser_sources=['kaspersky_selenium']
)
```

## ⚙️ Параметры

### KasperskySeleniumParser

- `vulnerability_repo` - Репозиторий для сохранения уязвимостей (обязательно)
- `headless` - Запускать браузер в headless режиме (по умолчанию: `False`)
- `use_undetected` - Использовать undetected-chromedriver для обхода обнаружения (по умолчанию: `True`)

### parse()

- `limit` - Максимальное количество advisory для парсинга (по умолчанию: `None` = все)
- `**kwargs` - Дополнительные параметры

## 📊 Что парсится

Для каждой advisory извлекается:

1. **Дата выдачи** - Дата advisory (например, "November 24, 2025")
2. **CVE ID** - Идентификатор CVE (если указан)
3. **Описание** - Описание уязвимости (Issue/Description секция)
4. **Affected Applications** - Таблица с:
   - Application (название приложения)
   - Version (версия)
   - Recommendations (рекомендации)
5. **Общие рекомендации** - Рекомендации по устранению
6. **Ссылка** - URL на advisory

**ИСКЛЮЧАЕТСЯ:**
- Раздел Acknowledgments/Credits (благодарности исследователям)

## 🔧 Особенности реализации

### 1. Обход обнаружения

Используется `undetected-chromedriver` для обхода обнаружения автоматизации:
- Отключены флаги автоматизации
- Настроен User-Agent
- Используются специальные опции Chrome

### 2. Ожидание загрузки

- `WebDriverWait` для ожидания элементов
- Дополнительные задержки для загрузки JavaScript
- Прокрутка к элементам перед кликом

### 3. Обработка ошибок

- Try-except блоки для каждой advisory
- Логирование ошибок с сохранением в список
- Продолжение парсинга при ошибках отдельных элементов

### 4. Headless режим

Опциональный headless режим для запуска без GUI:

```python
parser = KasperskySeleniumParser(vuln_repo, headless=True)
```

## 📈 Прогресс и логирование

Парсер выводит детальную информацию о прогрессе:

```
2025-12-29 15:30:00 - INFO - Инициализация веб-драйвера...
2025-12-29 15:30:05 - INFO - Открытие страницы: https://support.kaspersky.ru/...
2025-12-29 15:30:10 - INFO - Найдено 25 advisories
2025-12-29 15:30:11 - INFO - Парсинг advisory 1/25...
2025-12-29 15:30:15 - INFO - ✅ Сохранено: KASPERSKY-2025-11-24-1
...
2025-12-29 15:35:00 - INFO - ✅ Парсинг завершен: спарсено 25, сохранено 25
```

Логи также сохраняются в файл `kaspersky_selenium_parser.log`.

## 🗄️ Сохранение в БД

Данные сохраняются через `LegacyVulnerabilityRepository` в таблицу `turn`:

- `cve_id` - CVE ID или сгенерированный ID
- `title` - Заголовок advisory
- `description` - Полное описание с affected applications
- `source_identifier` - "Kaspersky"
- `category` - "Kaspersky"
- `raw_cve_json5` - Дополнительные данные (дата, affected applications, raw text)

## ⚠️ Возможные проблемы

### 1. ChromeDriver не найден

**Решение:** Установите ChromeDriver или используйте `undetected-chromedriver` (автоматически).

### 2. Страница не загружается

**Решение:** 
- Проверьте интернет-соединение
- Увеличьте timeout в коде
- Попробуйте использовать `headless=False` для отладки

### 3. Элементы не найдены

**Решение:**
- Структура страницы могла измениться
- Обновите селекторы в методе `parse()`
- Проверьте страницу вручную в браузере

### 4. Блокировка по антиботу

**Решение:**
- Используйте `use_undetected=True`
- Увеличьте задержки между запросами
- Используйте прокси (требует доработки кода)

## 🔄 Интеграция в UnifiedParserService

Для интеграции в общую систему парсеров:

1. Добавьте импорт в `services/legacy_parsers/__init__.py`:
```python
from .kaspersky_selenium_parser import KasperskySeleniumParser
```

2. Добавьте в `UnifiedParserService.__init__()`:
```python
self.legacy_parsers['kaspersky_selenium'] = KasperskySeleniumParser(self.vuln_repo)
```

3. Используйте через API:
```json
{
  "enable_legacy_parsers": true,
  "legacy_parser_sources": ["kaspersky_selenium"]
}
```

## 📝 Пример использования

```python
from services.legacy_parsers.kaspersky_selenium_parser import KasperskySeleniumParser
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository

# Инициализация
db_manager = DatabaseManager()
vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)

# Создание парсера
parser = KasperskySeleniumParser(
    vuln_repo,
    headless=False,
    use_undetected=True
)

# Парсинг первых 10 advisory
results = parser.parse(limit=10)

# Результаты
print(f"Спарсено: {results['parsed']}")
print(f"Сохранено: {results['saved']}")
print(f"Ошибок: {len(results['errors'])}")

if results['errors']:
    for error in results['errors']:
        print(f"  - {error}")
```

## 🔗 Связанные файлы

- `services/legacy_parsers/kaspersky_selenium_parser.py` - Основной класс парсера
- `services/legacy_parsers/kaspersky_selenium_standalone.py` - Standalone скрипт
- `services/legacy_parsers/base_legacy_parser.py` - Базовый класс
- `models/legacy_repositories.py` - Репозиторий для сохранения

## 📚 Документация

- [Selenium Documentation](https://www.selenium.dev/documentation/)
- [undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver)
- [Kaspersky Advisories](https://support.kaspersky.ru/vulnerability/list-of-advisories/12430#120825)

