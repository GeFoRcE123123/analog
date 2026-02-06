#!/usr/bin/env python3
"""
Тестовый скрипт для проверки работы MultiSourceVulnerabilityParser
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
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    # Список источников для парсинга
    sources = {
        'moxa': 'https://www.moxa.com/en/support/support/security-advisory',
        'fortiguard': 'https://www.fortiguard.com/psirt',
        'suse': 'https://www.suse.com/support/update/',
        'schneider': 'https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp',
        'hp': 'https://support.hp.com/us-en/security-bulletins',
        'adobe': 'https://helpx.adobe.com/security.html',
        'ubuntu': 'https://ubuntu.com/security/notices',
        'debian': 'https://www.debian.org/security/',
        'cisco': 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x',
        'mongodb': 'https://www.mongodb.com/alerts',
        'dell': 'https://www.dell.com/support/security/ru-ru',
        'broadcom': 'https://support.broadcom.com/web/ecx/security-advisory?segment=BSN',
        'huntr': 'https://huntr.com/bounties/hacktivity',
        'splunk': 'https://advisory.splunk.com/advisories',
        'siemens': 'https://www.siemens.com/global/en/products/services/cert.html#SecurityPublications',
        'teamviewer': 'https://www.teamviewer.com/en-cis/resources/trust-center/security-bulletins/',
        'autodesk': 'https://www.autodesk.com/trust/security-advisories',
        'cvecrowd': 'https://cvecrowd.com/',
        'feedly': 'https://feedly.com/cve',
        'sap': 'https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html?anchorId=section_370125364',
        'qualcomm': 'https://docs.qualcomm.com/product/publicresources/securitybulletin/april-2025-bulletin.html',
        'fedisec': 'https://fedisecfeeds.github.io/',
    }
    
    # Создание парсера
    print("🔧 Инициализация парсера...")
    parser = MultiSourceVulnerabilityParser(timeout=30, delay=1.0)
    
    # Парсинг всех источников
    print("\n🚀 Начало парсинга всех источников...")
    print(f"📋 Всего источников: {len(sources)}\n")
    
    results = parser.parse_all_sources(sources, limit_per_source=20)  # Ограничиваем для теста
    
    # Вывод результатов
    print("\n" + "=" * 80)
    print("РЕЗУЛЬТАТЫ ПАРСИНГА")
    print("=" * 80)
    
    all_vulnerabilities = []
    total_by_vendor = {}
    
    for source_name, vulnerabilities in results.items():
        count = len(vulnerabilities)
        print(f"\n📊 {source_name.upper()}: {count} уязвимостей")
        all_vulnerabilities.extend(vulnerabilities)
        
        # Подсчет по вендорам
        for vuln in vulnerabilities:
            vendor = vuln.vendor
            total_by_vendor[vendor] = total_by_vendor.get(vendor, 0) + 1
        
        # Показываем первые 3 уязвимости из каждого источника
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities[:3], 1):
                print(f"  {i}. {vuln.cve_id} - {vuln.title[:60]}...")
                print(f"     Severity: {vuln.severity}, Vendor: {vuln.vendor}")
                if vuln.cvss_score:
                    print(f"     CVSS: {vuln.cvss_score}")
        else:
            print("  ⚠️  Уязвимости не найдены")
    
    print(f"\n{'=' * 80}")
    print(f"✅ Всего найдено уязвимостей: {len(all_vulnerabilities)}")
    print(f"\n📈 Статистика по вендорам:")
    for vendor, count in sorted(total_by_vendor.items(), key=lambda x: x[1], reverse=True):
        print(f"  {vendor}: {count}")
    
    # Сохранение в JSON
    output_file = 'parsed_vulnerabilities.json'
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
    print(f"📄 Всего записей в файле: {len(output_data)}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
