# 🧪 Тесты для парсеров уязвимостей

## 📋 Описание

Набор тестов для проверки работы всех парсеров уязвимостей:
- **HTML парсеры** (Ubuntu, Debian, Red Hat, и т.д.)
- **API парсеры** (NVD, OSV, GitHub Advisories)
- **Legacy парсеры** (RedHat, Cisco, Cert, FortiGuard, и т.д.)
- **Анализ выходных данных** и **валидация**

## 🚀 Запуск тестов

### Все тесты
```bash
pytest tests/
```

### Конкретный файл тестов
```bash
pytest tests/test_html_parsers.py
```

### Конкретный тест
```bash
pytest tests/test_html_parsers.py::TestUbuntuParser::test_ubuntu_parser_output
```

### С маркерами
```bash
pytest -m unit          # Только unit-тесты
pytest -m integration   # Только integration-тесты
pytest -m html          # Тесты HTML парсеров
pytest -m legacy        # Тесты legacy парсеров
```

### С подробным выводом
```bash
pytest -v -s           # Подробный вывод с print
pytest --tb=short       # Короткий traceback
```

## 📁 Структура тестов

```
tests/
├── __init__.py
├── conftest.py              # Фикстуры и конфигурация
├── pytest.ini               # Конфигурация pytest
├── test_parser_output.py    # Тесты валидации выходных данных
├── test_html_parsers.py     # Тесты HTML парсеров
├── test_api_parsers.py      # Тесты API парсеров
├── test_legacy_parsers.py   # Тесты legacy парсеров
└── auto_fix_helper.py       # Хелпер для автоматического исправления
```

## 🧪 Типы тестов

### 1. Unit-тесты
Проверка отдельных функций парсеров:
- Инициализация парсеров
- Обработка входных данных
- Создание объектов Vulnerability
- Нормализация данных

### 2. Integration-тесты
Проверка работы парсеров с реальными данными:
- Парсинг HTML/JSON
- Обработка ошибок соединения
- Валидация выходных данных

### 3. Тесты валидации
Проверка состава и корректности отпарсенных данных:
- Наличие обязательных полей
- Типы данных
- Форматы дат
- Кодировки

## 🔧 Автоматическое исправление

Модуль `auto_fix_helper.py` предоставляет функции для:
- Предложения исправлений на основе ошибок
- Открытия файлов в редакторе
- Анализа результатов тестов

### Пример использования:
```python
from tests.auto_fix_helper import AutoFixHelper

helper = AutoFixHelper()
fix = helper.suggest_fix(
    error_type='AttributeError',
    error_message="'NoneType' object has no attribute 'text'",
    file_path='services/html_vulnerability_parser.py',
    line_number=123
)

print(fix['code'])  # if element and element.text:
helper.open_file_in_editor(fix['file_path'], fix['line_number'])
```

## 📊 Анализ результатов

После запуска тестов можно проанализировать результаты:

```python
from tests.auto_fix_helper import AutoFixHelper

helper = AutoFixHelper()
test_results = {
    'errors': [
        {
            'type': 'AttributeError',
            'message': "'NoneType' object has no attribute 'text'",
            'file': 'services/html_vulnerability_parser.py',
            'line': 123
        }
    ]
}

fixes = helper.analyze_test_results(test_results)
for fix in fixes:
    print(f"Исправление для {fix['file_path']}: {fix['code']}")
```

## ⚠️ Примечания

- Некоторые тесты требуют доступа к внешним API (NVD, OSV)
- Тесты с маркером `@pytest.mark.slow` могут выполняться долго
- Тесты с маркером `@pytest.mark.api` требуют интернет-соединения
- Используйте моки для тестирования без реальных запросов

## 🔍 Отладка

Для отладки тестов используйте:
```bash
pytest -v -s --pdb          # Остановка на ошибках
pytest --lf                 # Запуск только упавших тестов
pytest --ff                 # Сначала упавшие, потом остальные
```

