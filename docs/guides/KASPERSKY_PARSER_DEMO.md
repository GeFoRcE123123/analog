# 🎬 Демонстрация работы парсера Kaspersky с Selenium

## 📋 Статус готовности

Для запуска парсера необходимо установить зависимости:

### ✅ Созданные файлы
- `services/legacy_parsers/kaspersky_selenium_parser.py` - Основной класс парсера
- `services/legacy_parsers/kaspersky_selenium_standalone.py` - Standalone скрипт
- `test_kaspersky_selenium_demo.py` - Демонстрационный скрипт

### ⚠️ Требуется установка

1. **Python зависимости:**
```bash
pip install selenium>=4.15.0
pip install undetected-chromedriver>=3.5.0
pip install psycopg[binary]>=3.2.1
```

2. **Chrome/Chromium браузер:**
- macOS: `brew install --cask google-chrome`
- Linux: `sudo apt-get install google-chrome-stable`
- Windows: Скачать с https://www.google.com/chrome/

3. **Настройка БД:**
- Убедитесь, что PostgreSQL запущен
- Проверьте настройки в `config.py`

## 🚀 Как будет работать парсер

### Пошаговый процесс:

1. **Инициализация**
   ```
   ✅ Создание веб-драйвера (Chrome)
   ✅ Настройка опций (headless, undetected)
   ✅ Подключение к БД
   ```

2. **Загрузка страницы**
   ```
   🌐 Открытие: https://support.kaspersky.ru/vulnerability/list-of-advisories/12430#120825
   ⏳ Ожидание загрузки контента (3-5 секунд)
   🔍 Поиск списка advisories
   ```

3. **Парсинг каждого advisory**
   ```
   Для каждого advisory:
   1. Клик на элемент для раскрытия деталей
   2. Извлечение информации:
      - Дата выдачи (например: "November 24, 2025")
      - CVE ID (если указан)
      - Описание уязвимости
      - Таблица Affected Applications
      - Рекомендации
   3. Пропуск раздела Acknowledgments
   4. Формирование объекта Vulnerability
   5. Сохранение в БД
   ```

4. **Результаты**
   ```
   ✅ Спарсено: X advisory
   ✅ Сохранено: Y уязвимостей
   ❌ Ошибок: Z
   ```

## 📊 Примерный вывод при работе

```
======================================================================
🚀 ДЕМОНСТРАЦИЯ ПАРСЕРА KASPERSKY С SELENIUM
======================================================================

📦 Проверка зависимостей...
   ✅ Selenium 4.15.0 установлен
   ✅ undetected-chromedriver доступен

🗄️  Проверка подключения к БД...
   ✅ Подключение к БД установлено

📥 Импорт парсера...
   ✅ Парсер импортирован успешно

🔧 Создание экземпляра парсера...
   ✅ Парсер создан
   Параметры:
     - headless: True
     - use_undetected: True

======================================================================
🌐 ЗАПУСК ПАРСИНГА
======================================================================

Инициализация веб-драйвера...
Открытие страницы: https://support.kaspersky.ru/vulnerability/list-of-advisories/12430#120825
Ожидание загрузки контента...
Найдено 25 advisories с селектором: //a[contains(text(), 'Advisory issued')]
Начало парсинга 3 advisories...

Парсинг advisory 1/3...
✅ Сохранено: KASPERSKY-2025-11-24-1

Парсинг advisory 2/3...
✅ Сохранено: KASPERSKY-2025-11-18-2

Парсинг advisory 3/3...
✅ Сохранено: KASPERSKY-2025-10-15-3

✅ Парсинг завершен: спарсено 3, сохранено 3

======================================================================
📊 РЕЗУЛЬТАТЫ ПАРСИНГА
======================================================================

✅ Спарсено advisory: 3
✅ Сохранено уязвимостей: 3
❌ Ошибок: 0

🎉 Парсинг завершен успешно!
   В БД добавлено 3 новых уязвимостей Kaspersky

======================================================================
```

## 🔧 Что извлекается из каждого advisory

### Пример структуры данных:

```python
{
    'date': datetime(2025, 11, 24),
    'cve_id': 'CVE-2025-XXXXX',  # или None
    'description': 'Kaspersky has fixed a security issue that could occur during the installation...',
    'affected_applications': [
        {
            'application': 'Kaspersky Security Center',
            'version': '15.1.0.22239',
            'recommendations': 'Use only the latest version of the installer'
        }
    ],
    'recommendations': 'When installing the product, use only the latest version...',
    'link': 'https://support.kaspersky.ru/vulnerability/...'
}
```

## 💾 Сохранение в БД

Каждая advisory сохраняется как объект `Vulnerability` с полями:

- `cve_id`: CVE ID или сгенерированный ID
- `title`: "Kaspersky Security Advisory (2025-11-24)"
- `description`: Полное описание с affected applications
- `source_identifier`: "Kaspersky"
- `category`: "Kaspersky"
- `cvss_score`: 0.0 (если не указан)
- `severity`: "low" (по умолчанию, если нет CVSS)
- `raw_cve_json5`: Дополнительные данные (JSON)

## 🎯 Особенности реализации

1. **Обход обнаружения**: Использует `undetected-chromedriver`
2. **Ожидание загрузки**: `WebDriverWait` и дополнительные задержки
3. **Обработка ошибок**: Продолжает парсинг при ошибках отдельных элементов
4. **Headless режим**: Опциональный запуск без GUI
5. **Логирование**: Детальные логи всех операций

## 📝 Команды для запуска

После установки зависимостей:

```bash
# Демонстрация (первые 3 advisory)
python test_kaspersky_selenium_demo.py

# Полный парсинг (все advisory)
python services/legacy_parsers/kaspersky_selenium_standalone.py
```

## ⚠️ Возможные проблемы

1. **ChromeDriver не найден**
   - `undetected-chromedriver` скачает автоматически
   - Или установите вручную

2. **Блокировка по антиботу**
   - Используется `undetected-chromedriver`
   - Можно увеличить задержки

3. **Элементы не найдены**
   - Структура страницы могла измениться
   - Нужно обновить селекторы

4. **Ошибки БД**
   - Проверьте подключение
   - Проверьте настройки в `config.py`

