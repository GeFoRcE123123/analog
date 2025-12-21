#!/usr/bin/env python3
"""
Тестовый скрипт для прямой проверки сохранения уязвимостей в БД
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.database import DatabaseManager
from models.postgres_repositories import PostgresVulnerabilityRepository
from models.entities import Vulnerability
from datetime import datetime

def test_direct_save():
    """Прямое тестирование сохранения в БД"""
    print("=" * 60)
    print("ТЕСТ ПРЯМОГО СОХРАНЕНИЯ В БД")
    print("=" * 60)
    
    try:
        # 1. Подключение к БД
        print("\n1. Подключение к БД...")
        db_manager = DatabaseManager()
        print(f"   ✓ Соединение установлено: {db_manager.connection}")
        print(f"   ✓ Autocommit: {db_manager.connection.autocommit}")
        
        # 2. Создание репозитория
        print("\n2. Создание репозитория...")
        repo = PostgresVulnerabilityRepository(db_manager.connection)
        print(f"   ✓ Репозиторий создан")
        print(f"   ✓ Connection в репозитории: {repo.connection}")
        print(f"   ✓ Autocommit в репозитории: {repo.connection.autocommit}")
        
        # 3. Проверка существующих записей
        print("\n3. Проверка существующих записей...")
        existing = repo.get_by_cve_id("CVE-2024-TEST-001")
        if existing:
            print(f"   ⚠️  Уязвимость CVE-2024-TEST-001 уже существует: {existing.title}")
        else:
            print(f"   ✓ Уязвимость CVE-2024-TEST-001 не найдена, можно создавать")
        
        # 4. Создание тестовой уязвимости
        print("\n4. Создание тестовой уязвимости...")
        test_vuln = Vulnerability(
            id=None,
            title="[ТЕСТ] Ubuntu CVE-2024-TEST-001",
            description="[ТЕСТОВАЯ ЗАПИСЬ] Уязвимость CVE-2024-TEST-001 для проверки работы системы парсинга уязвимостей.",
            severity="medium",
            status="new",
            assigned_operator=None,
            created_date=datetime.now(),
            completed_date=None,
            approved=False,
            modifications=None,
            cvss_score=5.0,
            risk_level="medium",
            category="ubuntu",
            cve_id="CVE-2024-TEST-001"
        )
        print(f"   ✓ Объект создан: title={test_vuln.title}, cve_id={test_vuln.cve_id}")
        
        # 5. Сохранение в БД
        print("\n5. Сохранение в БД...")
        result = repo.add(test_vuln)
        print(f"   Результат add(): {result}")
        if result:
            print(f"   ✓ Уязвимость сохранена! ID: {test_vuln.id}")
        else:
            print(f"   ❌ Ошибка сохранения!")
        
        # 6. Проверка в БД напрямую
        print("\n6. Проверка в БД напрямую...")
        with db_manager.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id = %s", ("CVE-2024-TEST-001",))
            count = cursor.fetchone()[0]
            print(f"   Записей с CVE-2024-TEST-001: {count}")
            
            if count > 0:
                cursor.execute("SELECT id, title, cve_id, severity FROM vulnerabilities WHERE cve_id = %s", ("CVE-2024-TEST-001",))
                row = cursor.fetchone()
                print(f"   ✓ Найдена запись: ID={row[0]}, title={row[1]}, cve_id={row[2]}, severity={row[3]}")
        
        # 7. Общая статистика
        print("\n7. Общая статистика БД...")
        with db_manager.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NOT NULL")
            with_cve = cursor.fetchone()[0]
            print(f"   Всего уязвимостей: {total}")
            print(f"   С CVE ID: {with_cve}")
        
        print("\n" + "=" * 60)
        print("ТЕСТ ЗАВЕРШЕН")
        print("=" * 60)
        
        return result
        
    except Exception as e:
        print(f"\n❌ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_direct_save()

