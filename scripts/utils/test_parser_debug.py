#!/usr/bin/env python3
"""
Тестовый скрипт для диагностики проблемы парсинга
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("ДИАГНОСТИКА ПАРСЕРА")
print("=" * 60)

# 1. Проверка импортов
print("\n1. Проверка импортов...")
try:
    from services.unified_parser_service import UnifiedParserService
    print("   ✅ UnifiedParserService импортирован")
except Exception as e:
    print(f"   ❌ Ошибка импорта UnifiedParserService: {e}")
    sys.exit(1)

try:
    from services.html_vulnerability_parser import HTMLVulnerabilityParser
    print("   ✅ HTMLVulnerabilityParser импортирован")
except Exception as e:
    print(f"   ❌ Ошибка импорта HTMLVulnerabilityParser: {e}")
    sys.exit(1)

# 2. Инициализация UnifiedParserService
print("\n2. Инициализация UnifiedParserService...")
try:
    service = UnifiedParserService()
    print(f"   ✅ UnifiedParserService создан")
    print(f"   html_parser: {service.html_parser}")
    print(f"   type(html_parser): {type(service.html_parser)}")
except Exception as e:
    print(f"   ❌ Ошибка создания UnifiedParserService: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 3. Проверка HTML парсера
print("\n3. Проверка HTML парсера...")
if service.html_parser:
    print("   ✅ HTML парсер инициализирован")
    print(f"   type: {type(service.html_parser)}")
    
    # Проверка метода parse_source
    print("\n4. Тест parse_source('ubuntu', limit=3)...")
    try:
        result = service.html_parser.parse_source('ubuntu', limit=3)
        print(f"   ✅ parse_source вернул {len(result)} уязвимостей")
        if result:
            print(f"   Первая уязвимость: cve_id={result[0].get('cve_id')}, title={result[0].get('title', 'N/A')[:50]}")
        else:
            print("   ⚠️  parse_source вернул пустой список!")
    except Exception as e:
        print(f"   ❌ Ошибка при вызове parse_source: {e}")
        import traceback
        traceback.print_exc()
else:
    print("   ❌ HTML парсер НЕ инициализирован!")

# 5. Тест parse_all
print("\n5. Тест parse_all(sources=['ubuntu'], limit_per_source=3)...")
try:
    results = service.parse_all(sources=['ubuntu'], limit_per_source=3)
    print(f"   ✅ parse_all завершен")
    print(f"   total_parsed: {results.get('total_parsed', 0)}")
    print(f"   total_saved: {results.get('total_saved', 0)}")
    print(f"   by_source: {results.get('by_source', {})}")
    print(f"   errors: {results.get('errors', [])}")
except Exception as e:
    print(f"   ❌ Ошибка при вызове parse_all: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("ДИАГНОСТИКА ЗАВЕРШЕНА")
print("=" * 60)

