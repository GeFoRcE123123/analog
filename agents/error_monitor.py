#!/usr/bin/env python3
"""
Агент мониторинга ошибок в терминале
Анализирует stderr и stdout, определяет тип ошибки и файл
"""
import sys
import json
import re
from typing import Optional, Dict, List

# Паттерны для распознавания ошибок
ERROR_PATTERNS = {
    'psycopg.UndefinedColumn': {
        'pattern': r'column "(\w+)" does not exist',
        'suggested_fix': 'Удалить колонку из запроса или добавить в схему БД',
        'file_pattern': r'File "([^"]+)", line (\d+)'
    },
    'AttributeError': {
        'pattern': r"'(\w+)' object has no attribute '(\w+)'",
        'suggested_fix': 'Добавить проверку на None или инициализировать объект',
        'file_pattern': r'File "([^"]+)", line (\d+)'
    },
    'AssertionError': {
        'pattern': r'overwriting an existing endpoint function: (\w+)',
        'suggested_fix': 'Удалить дубликат маршрута или изменить имя функции',
        'file_pattern': r'File "([^"]+)", line (\d+)'
    },
    'ImportError': {
        'pattern': r'cannot import name (\w+) from',
        'suggested_fix': 'Проверить импорт или установить недостающий модуль',
        'file_pattern': r'File "([^"]+)", line (\d+)'
    },
    'ConnectionRefusedError': {
        'pattern': r'Connection refused|Failed to connect|Network is unreachable',
        'suggested_fix': 'Проверить доступность сервиса или IP адрес',
        'file_pattern': r'File "([^"]+)", line (\d+)'
    },
    'PermissionError': {
        'pattern': r'permission denied|Permission denied|EACCES',
        'suggested_fix': 'Использовать sudo или добавить пользователя в группу docker',
        'file_pattern': r'File "([^"]+)", line (\d+)'
    },
    'ModuleNotFoundError': {
        'pattern': r"No module named '(\w+)'",
        'suggested_fix': 'Установить модуль: pip install <module>',
        'file_pattern': r'File "([^"]+)", line (\d+)'
    }
}

def parse_error(line: str) -> Optional[Dict]:
    """Парсит строку лога и определяет тип ошибки"""
    for error_type, config in ERROR_PATTERNS.items():
        pattern = config['pattern']
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            file_match = re.search(config['file_pattern'], line)
            file_path = file_match.group(1) if file_match else None
            line_num = int(file_match.group(2)) if file_match and file_match.lastindex >= 2 else None
            
            return {
                'error_type': error_type,
                'details': match.groups(),
                'raw_line': line.strip(),
                'file': file_path,
                'line': line_num,
                'suggested_fix': config['suggested_fix'],
                'timestamp': __import__('datetime').datetime.now().isoformat()
            }
    return None

def main():
    """Основная функция мониторинга"""
    errors_found = []
    
    try:
        for line in sys.stdin:
            # Выводим строку как есть
            sys.stdout.write(line)
            sys.stdout.flush()
            
            # Анализируем на наличие ошибок
            error = parse_error(line)
            if error:
                errors_found.append(error)
                # Выводим JSON с ошибкой в stderr
                print(json.dumps(error, ensure_ascii=False), file=sys.stderr, flush=True)
    
    except KeyboardInterrupt:
        pass
    finally:
        # В конце выводим сводку ошибок
        if errors_found:
            summary = {
                'total_errors': len(errors_found),
                'errors': errors_found,
                'unique_errors': len(set(e['error_type'] for e in errors_found))
            }
            print(json.dumps(summary, ensure_ascii=False, indent=2), file=sys.stderr)

if __name__ == '__main__':
    main()

