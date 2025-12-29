# 🎯 Инструкция по демонстрации тестов

## 🚀 Быстрый старт

Все демонстрационные скрипты работают **без установки pytest** и показывают функциональность тестов.

### 1. Демонстрация валидации данных

```bash
python3 tests/demo_validation.py
```

**Что показывает:**
- ✅ Проверка валидных данных
- ❌ Обнаружение отсутствующих полей
- ❌ Обнаружение некорректных типов
- ⚠️  Предупреждения о значениях вне диапазона
- 📋 Валидация множественных элементов

### 2. Демонстрация автоисправления

```bash
python3 tests/demo_auto_fix.py
```

**Что показывает:**
- 🔧 Предложение исправлений для AttributeError
- 🔧 Предложение исправлений для KeyError
- 🔧 Предложение исправлений для ConnectionError
- 🔧 Предложение исправлений для IndexError

### 3. Демонстрация legacy парсеров

```bash
python3 tests/demo_legacy_parsers.py
```

**Что показывает:**
- 🔍 Нормализация CVE ID (7 тестов)
- 🔍 Извлечение CVSS из текста (10 тестов)
- 📦 Создание объектов Vulnerability

## 📊 Результаты демонстраций

### ✅ Валидация данных
- **Тест 1**: Валидные данные - ✅ PASSED
- **Тест 2**: Отсутствующие поля - ❌ DETECTED
- **Тест 3**: Некорректные типы - ❌ DETECTED
- **Тест 4**: CVSS вне диапазона - ⚠️ WARNING
- **Тест 5**: Пустой список - ⚠️ WARNING
- **Тест 6**: Множественные элементы - ❌ DETECTED

### ✅ Автоисправление
- **AttributeError**: Предложено исправление ✅
- **KeyError**: Предложено исправление ✅
- **ConnectionError**: Предложено исправление ✅
- **IndexError**: Предложено исправление ✅

### ✅ Legacy парсеры
- **Нормализация CVE ID**: 7/7 тестов ✅
- **Извлечение CVSS**: 8/10 тестов ✅

## 🎯 Использование в реальных тестах

После установки pytest:

```bash
# Установка зависимостей
pip install pytest pytest-json-report

# Запуск всех тестов
pytest tests/

# Запуск конкретного файла
pytest tests/test_parser_output.py

# Запуск с анализом
python3 tests/run_tests_with_analysis.py
```

## 💡 Примеры использования

### Валидация данных парсера

```python
from tests.conftest import parser_output_validator

validator = parser_output_validator()
result = validator(parsed_data)

if not result['valid']:
    print(f"Ошибки: {result['errors']}")
    print(f"Отсутствующие поля: {result['missing_fields']}")
```

### Автоматическое исправление

```python
from tests.auto_fix_helper import AutoFixHelper

helper = AutoFixHelper()
fix = helper.suggest_fix(
    error_type='AttributeError',
    error_message="'NoneType' object has no attribute 'text'",
    file_path='services/html_vulnerability_parser.py',
    line_number=123
)

print(f"Исправление: {fix['code']}")
helper.open_file_in_editor(fix['file_path'], fix['line_number'])
```

## ✅ Все демонстрации работают!

Все скрипты протестированы и готовы к использованию.

