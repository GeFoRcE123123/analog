"""
Хелпер для автоматического исправления ошибок в парсерах
"""
import os
import re
import subprocess
from typing import Dict, Any, Optional
from pathlib import Path


class AutoFixHelper:
    """Класс для автоматического исправления ошибок в парсерах"""
    
    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or Path(__file__).parent.parent
        self.fixes_applied = []
    
    def suggest_fix(self, error_type: str, error_message: str, file_path: str, line_number: int = None) -> Dict[str, Any]:
        """
        Предложение исправления на основе ошибки
        
        Args:
            error_type: Тип ошибки (AttributeError, KeyError, и т.д.)
            error_message: Сообщение об ошибке
            file_path: Путь к файлу с ошибкой
            line_number: Номер строки (опционально)
            
        Returns:
            Dict с предложением исправления
        """
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
            },
            'TimeoutError': {
                'pattern': r"Timeout",
                'fix_template': """try:
    response = requests.get(url, timeout=30)
except (ConnectionError, TimeoutError) as e:
    logger.error(f"Таймаут запроса: {e}")
    return []""",
                'description': "Добавить обработку таймаутов"
            }
        }
        
        for error, fix_info in fixes.items():
            if error in error_type or re.search(fix_info['pattern'], error_message):
                # Извлекаем детали из сообщения об ошибке
                match = re.search(fix_info['pattern'], error_message)
                if match:
                    groups = match.groups()
                    fix_code = fix_info['fix_template'].format(
                        var=groups[0] if groups else 'element',
                        attr=groups[0] if groups and len(groups) > 0 else 'text',
                        key=groups[0] if groups else 'key',
                        index=0
                    )
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
            'line_number': line_number,
            'error_message': error_message
        }
    
    def open_file_in_editor(self, file_path: str, line_number: int = None):
        """
        Открыть файл в редакторе
        
        Args:
            file_path: Путь к файлу
            line_number: Номер строки (опционально)
        """
        full_path = self.project_root / file_path
        
        if not full_path.exists():
            print(f"⚠️ Файл не найден: {full_path}")
            return
        
        # Определяем редактор (можно настроить через переменную окружения)
        editor = os.getenv('EDITOR', 'nano')
        
        try:
            if line_number:
                # Открываем файл на указанной строке
                subprocess.run([editor, f"+{line_number}", str(full_path)])
            else:
                subprocess.run([editor, str(full_path)])
        except Exception as e:
            print(f"❌ Ошибка открытия файла: {e}")
    
    def apply_fix(self, fix_suggestion: Dict[str, Any], dry_run: bool = True) -> bool:
        """
        Применить исправление к файлу
        
        Args:
            fix_suggestion: Предложение исправления от suggest_fix()
            dry_run: Если True, только показать что будет изменено, не применять
            
        Returns:
            True если исправление применено успешно
        """
        file_path = fix_suggestion['file_path']
        full_path = self.project_root / file_path
        
        if not full_path.exists():
            print(f"⚠️ Файл не найден: {full_path}")
            return False
        
        if dry_run:
            print(f"🔍 [DRY RUN] Предлагаемое исправление для {file_path}:")
            print(f"   Тип: {fix_suggestion['fix_type']}")
            print(f"   Описание: {fix_suggestion['description']}")
            print(f"   Код: {fix_suggestion['code']}")
            return False
        
        # Здесь можно добавить автоматическое применение исправления
        # Но это требует более сложной логики парсинга и изменения кода
        print(f"💡 Для применения исправления откройте файл: {full_path}")
        print(f"   И примените: {fix_suggestion['code']}")
        
        return False
    
    def analyze_test_results(self, test_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Анализ результатов тестов и предложение исправлений
        
        Args:
            test_results: Результаты тестов с ошибками
            
        Returns:
            Список предложений исправлений
        """
        fixes = []
        
        if 'errors' in test_results:
            for error in test_results['errors']:
                if 'file' in error and 'message' in error:
                    fix = self.suggest_fix(
                        error_type=error.get('type', 'Unknown'),
                        error_message=error['message'],
                        file_path=error['file'],
                        line_number=error.get('line')
                    )
                    fixes.append(fix)
        
        return fixes


def main():
    """Пример использования AutoFixHelper"""
    helper = AutoFixHelper()
    
    # Пример ошибки
    error = {
        'type': 'AttributeError',
        'message': "'NoneType' object has no attribute 'text'",
        'file': 'services/html_vulnerability_parser.py',
        'line': 123
    }
    
    fix = helper.suggest_fix(
        error_type=error['type'],
        error_message=error['message'],
        file_path=error['file'],
        line_number=error['line']
    )
    
    print("Предложение исправления:")
    print(f"  Тип: {fix['fix_type']}")
    print(f"  Описание: {fix['description']}")
    print(f"  Код: {fix['code']}")
    
    # Открыть файл в редакторе
    # helper.open_file_in_editor(error['file'], error['line'])


if __name__ == '__main__':
    main()

