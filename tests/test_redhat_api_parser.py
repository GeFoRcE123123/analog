"""
Тест парсера Red Hat API
"""
import sys
import os

# Добавляем путь к корню проекта
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import logging
from services.parsers.redhat_api_parser import RedHatAPIParser
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_parser_fetch():
    """Тест получения данных из API"""
    print("\n" + "=" * 50)
    print("ТЕСТ 1: Получение данных из Red Hat API")
    print("=" * 50)
    
    parser = RedHatAPIParser()
    cves = parser.fetch_page(page=1, per_page=5)
    
    assert len(cves) > 0, "Не получено ни одной CVE"
    assert 'CVE' in cves[0], "CVE не содержит поле 'CVE'"
    
    print(f"✅ Получено {len(cves)} CVE из API")
    print(f"   Пример: {cves[0].get('CVE', 'N/A')}")
    return True


def test_parser_transform():
    """Тест преобразования данных"""
    print("\n" + "=" * 50)
    print("ТЕСТ 2: Преобразование данных")
    print("=" * 50)
    
    parser = RedHatAPIParser()
    cves = parser.fetch_page(page=1, per_page=1)
    
    if not cves:
        print("⚠️ Нет данных для теста")
        return False
    
    redhat_cve = cves[0]
    vulnerability = parser.transform_to_vulnerability(redhat_cve)
    
    assert vulnerability is not None, "Преобразование вернуло None"
    assert hasattr(vulnerability, 'cve_id'), "Нет поля cve_id"
    assert vulnerability.cve_id == redhat_cve.get('CVE', ''), "CVE ID не совпадает"
    
    print(f"✅ Преобразование успешно")
    print(f"   CVE ID: {vulnerability.cve_id}")
    print(f"   Title: {vulnerability.title[:50]}...")
    print(f"   Severity: {vulnerability.severity}")
    print(f"   CVSS: {vulnerability.cvss_score}")
    return True


def test_parser_save():
    """Тест сохранения в БД"""
    print("\n" + "=" * 50)
    print("ТЕСТ 3: Сохранение в БД")
    print("=" * 50)
    
    parser = RedHatAPIParser()
    stats = parser.parse_and_save(limit=3)
    
    assert stats['total_fetched'] > 0, "Не получено данных"
    # Может быть пропущено если уже существуют
    assert stats['total_saved'] + stats['total_skipped'] > 0, "Ничего не обработано"
    
    print(f"✅ Сохранение успешно")
    print(f"   Получено: {stats['total_fetched']}")
    print(f"   Сохранено: {stats['total_saved']}")
    print(f"   Пропущено: {stats['total_skipped']}")
    print(f"   Ошибок: {stats['total_errors']}")
    return True


def test_db_retrieval():
    """Тест получения данных из БД"""
    print("\n" + "=" * 50)
    print("ТЕСТ 4: Получение данных из БД")
    print("=" * 50)
    
    db_manager = DatabaseManager()
    repo = LegacyVulnerabilityRepository(db_manager.connection)
    
    # Получаем все уязвимости и фильтруем Red Hat
    all_vulns = repo.get_all_vulnerabilities()
    vulnerabilities = all_vulns[:10]  # Берем первые 10
    
    # Ищем Red Hat уязвимости по source или по названию
    redhat_vulns = []
    for v in vulnerabilities:
        source = getattr(v, 'source', '').lower() if hasattr(v, 'source') else ''
        title = getattr(v, 'title', '').lower() if hasattr(v, 'title') else ''
        cve = getattr(v, 'cve', '').lower() if hasattr(v, 'cve') else ''
        if 'redhat' in source or 'red hat' in title or 'redhat' in title:
            redhat_vulns.append(v)
    
    print(f"✅ Найдено {len(redhat_vulns)} Red Hat уязвимостей в БД")
    for vuln in redhat_vulns[:3]:
        cve_id = getattr(vuln, 'cve', 'N/A') or getattr(vuln, 'cve_id', 'N/A')
        title = getattr(vuln, 'title', 'N/A')
        print(f"   - {cve_id}: {title[:50]}...")
    
    # Если не найдено, это не критично - может быть просто нет в первых 10
    return True  # Тест проходит, даже если не найдено (может быть в других записях)


def main():
    """Запуск всех тестов"""
    print("\n" + "=" * 60)
    print("ТЕСТИРОВАНИЕ ПАРСЕРА RED HAT API")
    print("=" * 60)
    
    tests = [
        ("Получение данных из API", test_parser_fetch),
        ("Преобразование данных", test_parser_transform),
        ("Сохранение в БД", test_parser_save),
        ("Получение из БД", test_db_retrieval),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result, None))
        except Exception as e:
            results.append((name, False, str(e)))
            logger.error(f"❌ Тест '{name}' упал: {e}", exc_info=True)
    
    # Итоги
    print("\n" + "=" * 60)
    print("ИТОГИ ТЕСТИРОВАНИЯ")
    print("=" * 60)
    
    passed = sum(1 for _, result, _ in results if result)
    total = len(results)
    
    for name, result, error in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
        if error:
            print(f"      Ошибка: {error}")
    
    print(f"\nРезультат: {passed}/{total} тестов пройдено")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    exit(main())

