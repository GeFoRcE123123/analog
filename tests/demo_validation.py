#!/usr/bin/env python3
"""
Демонстрация валидации данных парсера
Работает без pytest
"""
import sys
from pathlib import Path

# Добавляем корень проекта в путь
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def parser_output_validator(parsed_data):
    """Валидатор для проверки выходных данных парсера"""
    result = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'missing_fields': {}
    }
    
    required_fields = ['cve_id', 'title', 'description', 'severity', 'cvss_score']
    
    if not parsed_data:
        result['warnings'].append('Парсер вернул пустой список')
        return result
    
    for idx, item in enumerate(parsed_data):
        # Проверка обязательных полей
        for field in required_fields:
            if field not in item:
                result['valid'] = False
                result['errors'].append(f"Элемент {idx}: отсутствует обязательное поле '{field}'")
                if field not in result['missing_fields']:
                    result['missing_fields'][field] = []
                result['missing_fields'][field].append(idx)
            elif item[field] is None or (isinstance(item[field], str) and not item[field].strip()):
                result['valid'] = False
                result['errors'].append(f"Элемент {idx}: поле '{field}' пустое или None")
        
        # Проверка типов данных
        if 'cvss_score' in item:
            if not isinstance(item['cvss_score'], (int, float)):
                result['valid'] = False
                result['errors'].append(f"Элемент {idx}: 'cvss_score' должен быть числом, получен {type(item['cvss_score'])}")
            elif item['cvss_score'] < 0 or item['cvss_score'] > 10:
                result['warnings'].append(f"Элемент {idx}: 'cvss_score' вне диапазона 0-10: {item['cvss_score']}")
    
    return result


def main():
    print("=" * 70)
    print("📊 ДЕМОНСТРАЦИЯ ВАЛИДАЦИИ ДАННЫХ ПАРСЕРА")
    print("=" * 70)
    
    # Тест 1: Валидные данные
    print("\n✅ ТЕСТ 1: Валидные данные")
    print("-" * 70)
    valid_data = [
        {
            'cve_id': 'CVE-2024-0001',
            'title': 'Test Vulnerability',
            'description': 'Test description',
            'severity': 'high',
            'cvss_score': 7.5
        }
    ]
    
    result = parser_output_validator(valid_data)
    print(f"   Валидность: {result['valid']}")
    print(f"   Ошибки: {len(result['errors'])}")
    print(f"   Предупреждения: {len(result['warnings'])}")
    if result['valid']:
        print("   ✅ Все поля присутствуют и валидны!")
    
    # Тест 2: Отсутствующие поля
    print("\n❌ ТЕСТ 2: Отсутствующие обязательные поля")
    print("-" * 70)
    invalid_data = [
        {
            'cve_id': 'CVE-2024-0001',
            'title': 'Test Vulnerability',
            # Отсутствует description
            'severity': 'high',
            'cvss_score': 7.5
        }
    ]
    
    result = parser_output_validator(invalid_data)
    print(f"   Валидность: {result['valid']}")
    print(f"   Ошибки: {len(result['errors'])}")
    if result['errors']:
        print(f"   ❌ Первая ошибка: {result['errors'][0]}")
    print(f"   Отсутствующие поля: {list(result['missing_fields'].keys())}")
    
    # Тест 3: Некорректные типы
    print("\n❌ ТЕСТ 3: Некорректные типы данных")
    print("-" * 70)
    wrong_type_data = [
        {
            'cve_id': 'CVE-2024-0001',
            'title': 'Test Vulnerability',
            'description': 'Test description',
            'severity': 'high',
            'cvss_score': '7.5'  # Строка вместо числа
        }
    ]
    
    result = parser_output_validator(wrong_type_data)
    print(f"   Валидность: {result['valid']}")
    print(f"   Ошибки: {len(result['errors'])}")
    if result['errors']:
        print(f"   ❌ Первая ошибка: {result['errors'][0]}")
    
    # Тест 4: CVSS вне диапазона
    print("\n⚠️  ТЕСТ 4: CVSS вне диапазона 0-10")
    print("-" * 70)
    out_of_range_data = [
        {
            'cve_id': 'CVE-2024-0001',
            'title': 'Test Vulnerability',
            'description': 'Test description',
            'severity': 'high',
            'cvss_score': 15.0  # Вне диапазона 0-10
        }
    ]
    
    result = parser_output_validator(out_of_range_data)
    print(f"   Валидность: {result['valid']}")
    print(f"   Ошибки: {len(result['errors'])}")
    print(f"   Предупреждения: {len(result['warnings'])}")
    if result['warnings']:
        print(f"   ⚠️  Предупреждение: {result['warnings'][0]}")
    
    # Тест 5: Пустой список
    print("\n⚠️  ТЕСТ 5: Пустой список (парсер не вернул данных)")
    print("-" * 70)
    result = parser_output_validator([])
    print(f"   Валидность: {result['valid']}")
    print(f"   Предупреждения: {len(result['warnings'])}")
    if result['warnings']:
        print(f"   ⚠️  Предупреждение: {result['warnings'][0]}")
    
    # Тест 6: Множественные элементы
    print("\n📋 ТЕСТ 6: Валидация множественных элементов")
    print("-" * 70)
    multiple_data = [
        {
            'cve_id': 'CVE-2024-0001',
            'title': 'Test Vulnerability 1',
            'description': 'Test description 1',
            'severity': 'high',
            'cvss_score': 7.5
        },
        {
            'cve_id': 'CVE-2024-0002',
            'title': 'Test Vulnerability 2',
            'description': 'Test description 2',
            'severity': 'medium',
            'cvss_score': 5.0
        },
        {
            'cve_id': 'CVE-2024-0003',
            # Отсутствуют обязательные поля
            'severity': 'low'
        }
    ]
    
    result = parser_output_validator(multiple_data)
    print(f"   Всего элементов: {len(multiple_data)}")
    print(f"   Валидность: {result['valid']}")
    print(f"   Ошибки: {len(result['errors'])}")
    if result['errors']:
        print(f"   ❌ Ошибки найдены в элементах: {set([e.split(':')[0] for e in result['errors']])}")
    
    print("\n" + "=" * 70)
    print("✅ ДЕМОНСТРАЦИЯ ВАЛИДАЦИИ ЗАВЕРШЕНА!")
    print("=" * 70)


if __name__ == '__main__':
    main()

