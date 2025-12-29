#!/usr/bin/env python3
"""
Демонстрация автоматического исправления ошибок
Работает без pytest
"""
import re
from pathlib import Path


class AutoFixHelper:
    """Класс для автоматического исправления ошибок в парсерах"""
    
    def suggest_fix(self, error_type: str, error_message: str, file_path: str, line_number: int = None):
        """Предложение исправления на основе ошибки"""
        fixes = {
            'AttributeError': {
                'pattern': r"'NoneType' object has no attribute '(\w+)'",
                'fix_template': "if {var} and {var}.{attr}:",
                'description': "Добавить проверку на None перед доступом к атрибуту"
            },
            'KeyError': {
                'pattern': r"KeyError: '(\w+)'",
                'fix_template': "data.get('{key}', default_value)",
                'description': "Использовать .get() вместо прямого доступа к ключу"
            },
            'IndexError': {
                'pattern': r"list index out of range",
                'fix_template': "if len({var}) > {index}:",
                'description': "Добавить проверку длины списка перед доступом по индексу"
            },
            'ConnectionError': {
                'pattern': r"Connection",
                'fix_template': """try:
    response = requests.get(url, timeout=30)
except (ConnectionError, TimeoutError) as e:
    logger.error(f"Ошибка соединения: {e}")
    return []""",
                'description': "Добавить обработку ошибок соединения"
            }
        }
        
        for error, fix_info in fixes.items():
            if error in error_type or re.search(fix_info['pattern'], error_message):
                match = re.search(fix_info['pattern'], error_message)
                if match:
                    groups = match.groups()
                    if groups:
                        if error == 'AttributeError':
                            fix_code = f"if element and element.{groups[0]}:"
                        elif error == 'KeyError':
                            fix_code = f"data.get('{groups[0]}', default_value)"
                        else:
                            fix_code = fix_info['fix_template']
                    else:
                        fix_code = fix_info['fix_template']
                else:
                    fix_code = fix_info['fix_template']
                
                return {
                    'fix_type': error,
                    'code': fix_code,
                    'description': fix_info['description'],
                    'file_path': file_path,
                    'line_number': line_number,
                    'error_message': error_message
                }
        
        return {
            'fix_type': 'unknown',
            'code': None,
            'description': f"Неизвестная ошибка: {error_type} - {error_message}",
            'file_path': file_path,
            'line_number': line_number
        }


def main():
    print("=" * 70)
    print("🔧 ДЕМОНСТРАЦИЯ АВТОМАТИЧЕСКОГО ИСПРАВЛЕНИЯ ОШИБОК")
    print("=" * 70)
    
    helper = AutoFixHelper()
    
    # Пример 1: AttributeError
    print("\n1️⃣  ОШИБКА: AttributeError")
    print("-" * 70)
    error1 = {
        'type': 'AttributeError',
        'message': "'NoneType' object has no attribute 'text'",
        'file': 'services/html_vulnerability_parser.py',
        'line': 123
    }
    
    print(f"   Файл: {error1['file']}")
    print(f"   Строка: {error1['line']}")
    print(f"   Сообщение: {error1['message']}")
    
    fix1 = helper.suggest_fix(
        error_type=error1['type'],
        error_message=error1['message'],
        file_path=error1['file'],
        line_number=error1['line']
    )
    
    print(f"\n   ✅ Тип ошибки: {fix1['fix_type']}")
    print(f"   📝 Описание: {fix1['description']}")
    print(f"   💡 Предлагаемое исправление:")
    print(f"      {fix1['code']}")
    print(f"\n   🔍 До исправления:")
    print(f"      element.text  # Может упасть если element = None")
    print(f"   🔍 После исправления:")
    print(f"      {fix1['code']}")
    
    # Пример 2: KeyError
    print("\n2️⃣  ОШИБКА: KeyError")
    print("-" * 70)
    error2 = {
        'type': 'KeyError',
        'message': "KeyError: 'cve_id'",
        'file': 'services/nvd_parser.py',
        'line': 45
    }
    
    print(f"   Файл: {error2['file']}")
    print(f"   Строка: {error2['line']}")
    print(f"   Сообщение: {error2['message']}")
    
    fix2 = helper.suggest_fix(
        error_type=error2['type'],
        error_message=error2['message'],
        file_path=error2['file'],
        line_number=error2['line']
    )
    
    print(f"\n   ✅ Тип ошибки: {fix2['fix_type']}")
    print(f"   📝 Описание: {fix2['description']}")
    print(f"   💡 Предлагаемое исправление:")
    print(f"      {fix2['code']}")
    print(f"\n   🔍 До исправления:")
    print(f"      cve_id = data['cve_id']  # Может упасть если ключа нет")
    print(f"   🔍 После исправления:")
    print(f"      cve_id = {fix2['code']}")
    
    # Пример 3: ConnectionError
    print("\n3️⃣  ОШИБКА: ConnectionError")
    print("-" * 70)
    error3 = {
        'type': 'ConnectionError',
        'message': 'Connection error: Failed to connect to api.example.com',
        'file': 'services/legacy_parsers/redhat_parser.py',
        'line': 67
    }
    
    print(f"   Файл: {error3['file']}")
    print(f"   Строка: {error3['line']}")
    print(f"   Сообщение: {error3['message']}")
    
    fix3 = helper.suggest_fix(
        error_type=error3['type'],
        error_message=error3['message'],
        file_path=error3['file'],
        line_number=error3['line']
    )
    
    print(f"\n   ✅ Тип ошибки: {fix3['fix_type']}")
    print(f"   📝 Описание: {fix3['description']}")
    print(f"   💡 Предлагаемое исправление:")
    print(f"      {fix3['code']}")
    print(f"\n   🔍 До исправления:")
    print(f"      response = requests.get(url)  # Может упасть при ошибке соединения")
    print(f"   🔍 После исправления:")
    print(f"      {fix3['code']}")
    
    # Пример 4: IndexError
    print("\n4️⃣  ОШИБКА: IndexError")
    print("-" * 70)
    error4 = {
        'type': 'IndexError',
        'message': 'list index out of range',
        'file': 'services/html_vulnerability_parser.py',
        'line': 89
    }
    
    print(f"   Файл: {error4['file']}")
    print(f"   Строка: {error4['line']}")
    print(f"   Сообщение: {error4['message']}")
    
    fix4 = helper.suggest_fix(
        error_type=error4['type'],
        error_message=error4['message'],
        file_path=error4['file'],
        line_number=error4['line']
    )
    
    print(f"\n   ✅ Тип ошибки: {fix4['fix_type']}")
    print(f"   📝 Описание: {fix4['description']}")
    print(f"   💡 Предлагаемое исправление:")
    print(f"      {fix4['code']}")
    print(f"\n   🔍 До исправления:")
    print(f"      item = items[0]  # Может упасть если список пустой")
    print(f"   🔍 После исправления:")
    print(f"      if len(items) > 0:")
    print(f"          item = items[0]")
    
    print("\n" + "=" * 70)
    print("✅ ДЕМОНСТРАЦИЯ АВТОИСПРАВЛЕНИЯ ЗАВЕРШЕНА!")
    print("=" * 70)
    print("\n💡 Использование:")
    print("   - При обнаружении ошибки в тестах, используйте AutoFixHelper")
    print("   - Получите предложение исправления")
    print("   - Примените исправление в коде парсера")


if __name__ == '__main__':
    main()

