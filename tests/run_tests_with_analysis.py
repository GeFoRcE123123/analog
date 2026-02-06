#!/usr/bin/env python3
"""
Скрипт для запуска тестов с автоматическим анализом и предложением исправлений
"""
import sys
import subprocess
import json
from pathlib import Path
from tests.auto_fix_helper import AutoFixHelper

def run_tests():
    """Запуск тестов и сбор результатов"""
    print("🧪 Запуск тестов...")
    
    try:
        # Запускаем pytest с JSON выводом
        result = subprocess.run(
            ['pytest', 'tests/', '-v', '--tb=short', '--json-report', '--json-report-file=test_results.json'],
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        if result.stderr:
            print("Ошибки:", result.stderr)
        
        return result.returncode == 0, result.stdout, result.stderr
    except FileNotFoundError:
        print("❌ pytest не найден. Установите: pip install pytest pytest-json-report")
        return False, "", "pytest not found"


def analyze_results():
    """Анализ результатов тестов и предложение исправлений"""
    helper = AutoFixHelper()
    
    # Пытаемся прочитать JSON отчет
    results_file = Path('test_results.json')
    if not results_file.exists():
        print("⚠️ JSON отчет не найден. Используйте: pip install pytest-json-report")
        return
    
    try:
        with open(results_file, 'r') as f:
            results = json.load(f)
        
        print("\n📊 Анализ результатов тестов:")
        print(f"   Всего тестов: {results.get('summary', {}).get('total', 0)}")
        print(f"   Успешно: {results.get('summary', {}).get('passed', 0)}")
        print(f"   Провалено: {results.get('summary', {}).get('failed', 0)}")
        print(f"   Пропущено: {results.get('summary', {}).get('skipped', 0)}")
        
        # Анализируем ошибки
        if 'tests' in results:
            errors = []
            for test in results['tests']:
                if test.get('outcome') == 'failed':
                    error_info = {
                        'type': 'TestFailure',
                        'message': test.get('call', {}).get('longrepr', ''),
                        'file': test.get('nodeid', '').split('::')[0],
                        'test': test.get('nodeid', '')
                    }
                    errors.append(error_info)
            
            if errors:
                print("\n🔧 Предложения исправлений:")
                fixes = helper.analyze_test_results({'errors': errors})
                
                for i, fix in enumerate(fixes, 1):
                    print(f"\n   {i}. {fix['file_path']}")
                    print(f"      Тип: {fix['fix_type']}")
                    print(f"      Описание: {fix['description']}")
                    if fix['code']:
                        print(f"      Исправление: {fix['code']}")
                    
                    # Предлагаем открыть файл
                    response = input(f"      Открыть файл в редакторе? (y/n): ")
                    if response.lower() == 'y':
                        helper.open_file_in_editor(fix['file_path'], fix.get('line_number'))
    
    except Exception as e:
        print(f"❌ Ошибка анализа результатов: {e}")


def main():
    """Основная функция"""
    print("=" * 60)
    print("🚀 Запуск тестов с автоматическим анализом")
    print("=" * 60)
    
    success, stdout, stderr = run_tests()
    
    if not success:
        print("\n" + "=" * 60)
        print("❌ Тесты провалились. Анализируем ошибки...")
        print("=" * 60)
        analyze_results()
    else:
        print("\n" + "=" * 60)
        print("✅ Все тесты прошли успешно!")
        print("=" * 60)
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())

