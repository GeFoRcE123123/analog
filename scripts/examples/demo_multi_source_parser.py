#!/usr/bin/env python3
"""
Демонстрационный скрипт для MultiSourceVulnerabilityParser
Показывает работу парсера на нескольких источниках
"""

import sys
import os
import json
import logging

# Добавляем путь к проекту
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from services.multi_source_vulnerability_parser import MultiSourceVulnerabilityParser

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def main():
    print("=" * 80)
    print("MULTI-SOURCE VULNERABILITY PARSER - ДЕМОНСТРАЦИЯ")
    print("=" * 80)
    
    # Выбираем несколько источников для демонстрации
    # (те, которые обычно доступны)
    demo_sources = {
        'ubuntu': 'https://ubuntu.com/security/notices',
        'debian': 'https://www.debian.org/security/',
        'huntr': 'https://huntr.com/bounties/hacktivity',
        'cvecrowd': 'https://cvecrowd.com/',
        'fedisec': 'https://fedisecfeeds.github.io/',
    }
    
    print(f"\n📋 Источники для парсинга: {len(demo_sources)}")
    for name, url in demo_sources.items():
        print(f"  - {name}: {url}")
    
    # Создание парсера
    print("\n🔧 Инициализация парсера...")
    parser = MultiSourceVulnerabilityParser(timeout=30, delay=1.5)
    
    # Парсинг источников
    print("\n🚀 Начало парсинга...\n")
    results = parser.parse_all_sources(demo_sources, limit_per_source=20)
    
    # Вывод результатов
    print("\n" + "=" * 80)
    print("РЕЗУЛЬТАТЫ ПАРСИНГА")
    print("=" * 80)
    
    all_vulnerabilities = []
    
    for source_name, vulnerabilities in results.items():
        count = len(vulnerabilities)
        status = "✅" if count > 0 else "⚠️"
        print(f"\n{status} {source_name.upper()}: {count} уязвимостей")
        
        all_vulnerabilities.extend(vulnerabilities)
        
        # Показываем первые 5 уязвимостей
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                print(f"  {i}. {vuln.cve_id}")
                print(f"     {vuln.title[:70]}...")
                print(f"     Severity: {vuln.severity}, Vendor: {vuln.vendor}")
                if vuln.cvss_score:
                    print(f"     CVSS: {vuln.cvss_score}")
                print()
    
    # Итоговая статистика
    print("=" * 80)
    print(f"✅ ВСЕГО НАЙДЕНО УЯЗВИМОСТЕЙ: {len(all_vulnerabilities)}")
    
    if all_vulnerabilities:
        # Статистика по severity
        severity_count = {}
        for vuln in all_vulnerabilities:
            severity_count[vuln.severity] = severity_count.get(vuln.severity, 0) + 1
        
        print("\n📊 Статистика по уровню серьезности:")
        for severity, count in sorted(severity_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  {severity.upper()}: {count}")
        
        # Статистика по вендорам
        vendor_count = {}
        for vuln in all_vulnerabilities:
            vendor_count[vuln.vendor] = vendor_count.get(vuln.vendor, 0) + 1
        
        print("\n📈 Статистика по вендорам:")
        for vendor, count in sorted(vendor_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  {vendor}: {count}")
        
        # Сохранение результатов
        output_file = 'demo_parsed_vulnerabilities.json'
        output_data = [
            {
                'cve_id': v.cve_id,
                'title': v.title,
                'description': v.description,
                'severity': v.severity,
                'published_date': v.published_date,
                'source_url': v.source_url,
                'vendor': v.vendor,
                'cvss_score': v.cvss_score,
                'affected_products': v.affected_products or [],
                'references': v.references or []
            }
            for v in all_vulnerabilities
        ]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Результаты сохранены в {output_file}")
        print(f"📄 Всего записей: {len(output_data)}")
    else:
        print("\n⚠️  Уязвимости не найдены. Возможные причины:")
        print("  - Сайты используют защиту от ботов (403 Forbidden)")
        print("  - Контент загружается динамически через JavaScript")
        print("  - Структура HTML изменилась")
        print("  - Требуется авторизация")
        print("\n💡 Рекомендации:")
        print("  - Используйте Selenium для динамического контента")
        print("  - Настройте прокси для обхода блокировок")
        print("  - Обновите селекторы для конкретных сайтов")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
