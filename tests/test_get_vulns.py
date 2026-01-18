#!/usr/bin/env python3
"""Тестовый скрипт для проверки get_all_vulnerabilities"""
import sys
import os

# Добавляем путь к проекту
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository

print("=" * 70)
print("ТЕСТ: get_all_vulnerabilities")
print("=" * 70)

try:
    db = DatabaseManager()
    print(f"✅ БД подключена: {db.connection is not None}")
    
    repo = LegacyVulnerabilityRepository(db.connection)
    print(f"✅ Репозиторий создан")
    
    # Тест 1: С лимитом 10
    print("\n📊 Тест 1: get_all_vulnerabilities(limit=10)")
    vulns = repo.get_all_vulnerabilities(limit=10)
    print(f"   Результат: {len(vulns)} уязвимостей")
    
    if len(vulns) > 0:
        v = vulns[0]
        print(f"   Первая: ID={v.id}, CVE={getattr(v, 'cve_id', 'N/A')}, Title={v.title[:50]}")
    else:
        print("   ⚠️  Уязвимостей не найдено!")
        
        # Проверяем напрямую через SQL
        print("\n🔍 Проверка через SQL напрямую...")
        with db.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM turn")
            count = cursor.fetchone()[0]
            print(f"   Записей в turn: {count}")
            
            if count > 0:
                cursor.execute("SELECT id, cve, name FROM turn LIMIT 3")
                rows = cursor.fetchall()
                print(f"   Примеры записей:")
                for row in rows:
                    print(f"     ID: {row[0]}, CVE: {row[1]}, Name: {row[2][:50] if row[2] else 'N/A'}")
    
    # Тест 2: Без лимита (должен получить все)
    print("\n📊 Тест 2: get_all_vulnerabilities(limit=None)")
    vulns_all = repo.get_all_vulnerabilities(limit=None)
    print(f"   Результат: {len(vulns_all)} уязвимостей")
    
    print("\n" + "=" * 70)
    print("✅ ТЕСТ ЗАВЕРШЕН")
    print("=" * 70)
    
except Exception as e:
    print(f"\n❌ ОШИБКА: {e}")
    import traceback
    traceback.print_exc()
