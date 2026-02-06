#!/usr/bin/env python3
"""
Скрипт обратного заполнения БДУ данных (Backfill)
==================================================

Извлекает BDU ID, вендора, продукт и другую структурированную информацию
из существующих записей (из полей title и description).

Использование:
    python scripts/migration/backfill_bdu_data.py [--dry-run] [--limit N]

Опции:
    --dry-run   Не сохранять изменения, только показать что будет изменено
    --limit N   Обработать только N записей (для тестирования)
    --verbose   Подробный вывод
"""

import sys
import os
import re
import argparse
from datetime import datetime
from typing import Optional, Dict, List, Tuple

# Добавляем корень проекта в путь
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from services.vulnerability_service import VulnerabilityService


class BDUDataExtractor:
    """Извлекатель БДУ данных из текстовых полей"""
    
    # Паттерны для извлечения данных
    PATTERNS = {
        'bdu_id': [
            r'BDU[:\s-]*(\d{4}-\d{5,6})',  # BDU:2026-00669 или BDU 2026-00669
            r'(\d{4}-\d{5,6})\s*\(BDU\)',  # 2026-00669 (BDU)
        ],
        'vendor': [
            r'\[ПО\]\s*Вендор:\s*([^,\n]+?)(?:,|$)',  # [ПО] Вендор: Microsoft,
            r'Вендор:\s*([^,\n]+?)(?:,|$)',
            r'Производитель:\s*([^,\n]+?)(?:,|$)',
        ],
        'product': [
            r'\[ПО\].*?продукт:\s*([^,\n]+?)(?:,|$)',  # продукт: Windows Server,
            r'Название ПО:\s*([^,\n]+?)(?:,|$)',
            r'Продукт:\s*([^,\n]+?)(?:,|$)',
        ],
        'version': [
            r'\[ПО\].*?версия:\s*([^,\n]+?)(?:,|$)',  # версия: 2019,
            r'Версия[:\s]+([^,\n]+?)(?:,|$)',
        ],
        'exploit': [
            r'\[Наличие эксплойта\]\s*([^\n]+)',
            r'Эксплойт:\s*([^\n]+)',
        ],
        'cvss_score': [
            r'CVSS.*?(\d+\.\d+)',  # CVSS 3.1: 7.5
            r'(\d+\.\d+)\s*\(CVSS\)',
        ],
        'date_discovered': [
            r'\[Дата выявления\]\s*(\d{4}-\d{2}-\d{2})',
            r'Выявлена:\s*(\d{4}-\d{2}-\d{2})',
        ],
        'remediation_date': [
            r'\[Дата устранения\]\s*(\d{4}-\d{2}-\d{2})',
            r'Устранена:\s*(\d{4}-\d{2}-\d{2})',
        ],
        'remediation_info': [
            r'\[Информация об устранении\]\s*([^\n\[]+)',
        ],
    }
    
    def extract_bdu_id(self, text: str) -> Optional[str]:
        """Извлечь BDU ID из текста"""
        if not text:
            return None
        
        for pattern in self.PATTERNS['bdu_id']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                bdu_num = match.group(1)
                return f"BDU:{bdu_num}"
        return None
    
    def extract_vendor(self, text: str) -> Optional[str]:
        """Извлечь вендора из текста"""
        if not text:
            return None
        
        for pattern in self.PATTERNS['vendor']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                vendor = match.group(1).strip()
                # Очистка
                vendor = vendor.replace('-', '').strip()
                if vendor and vendor != '-' and len(vendor) > 1:
                    return vendor[:255]  # Ограничение длины
        return None
    
    def extract_product(self, text: str) -> Optional[str]:
        """Извлечь название продукта из текста"""
        if not text:
            return None
        
        for pattern in self.PATTERNS['product']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                product = match.group(1).strip()
                product = product.replace('-', '').strip()
                if product and product != '-' and len(product) > 1:
                    return product[:255]
        return None
    
    def extract_version(self, text: str) -> Optional[str]:
        """Извлечь версию из текста"""
        if not text:
            return None
        
        for pattern in self.PATTERNS['version']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                version = match.group(1).strip()
                if version and version != '-' and len(version) > 0:
                    return version
        return None
    
    def extract_exploit_info(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Извлечь информацию об эксплойте
        
        Returns:
            Tuple[bool, Optional[str]]: (exploit_available, exploit_type)
        """
        if not text:
            return False, None
        
        exploit_available = False
        exploit_type = None
        
        for pattern in self.PATTERNS['exploit']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                exploit_text = match.group(1).lower()
                
                # Проверка наличия эксплойта
                if any(word in exploit_text for word in ['есть', 'да', 'доступен', 'существует', 'имеется']):
                    exploit_available = True
                
                # Определение типа эксплуатации
                if 'удален' in exploit_text or 'remote' in exploit_text:
                    exploit_type = 'remote'
                elif 'локал' in exploit_text or 'local' in exploit_text:
                    exploit_type = 'local'
                elif 'сетев' in exploit_text or 'network' in exploit_text:
                    exploit_type = 'network'
                
                break
        
        return exploit_available, exploit_type
    
    def extract_date(self, text: str, date_type: str) -> Optional[str]:
        """Извлечь дату из текста"""
        if not text:
            return None
        
        pattern_key = f'{date_type}_date' if date_type in ['discovered', 'remediation'] else date_type
        
        if pattern_key not in self.PATTERNS:
            return None
        
        for pattern in self.PATTERNS[pattern_key]:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                date_str = match.group(1)
                try:
                    # Валидация даты
                    datetime.strptime(date_str, '%Y-%m-%d')
                    return date_str
                except ValueError:
                    continue
        return None
    
    def extract_all(self, title: str, description: str) -> Dict:
        """
        Извлечь все БДУ данные из title и description
        
        Returns:
            Dict с извлеченными данными
        """
        combined_text = f"{title}\n{description}"
        
        data = {}
        
        # BDU ID
        bdu_id = self.extract_bdu_id(title) or self.extract_bdu_id(description)
        if bdu_id:
            data['bdu_id'] = bdu_id
        
        # Вендор и продукт
        vendor = self.extract_vendor(description)
        if vendor:
            data['vendor'] = vendor
        
        product = self.extract_product(description)
        if product:
            data['product_name'] = product
        
        version = self.extract_version(description)
        if version:
            data['affected_versions'] = version
        
        # Эксплойт
        exploit_available, exploit_type = self.extract_exploit_info(description)
        if exploit_available:
            data['exploit_available'] = True
            if exploit_type:
                data['exploit_type'] = exploit_type
        
        # Даты
        date_discovered = self.extract_date(description, 'discovered')
        if date_discovered:
            data['date_discovered'] = date_discovered
        
        date_remediation = self.extract_date(description, 'remediation')
        if date_remediation:
            data['remediation_date'] = date_remediation
        
        return data


def backfill_vulnerabilities(dry_run=False, limit=None, verbose=False):
    """
    Главная функция обратного заполнения
    
    Args:
        dry_run: Только показать изменения, не сохранять
        limit: Обработать только N записей
        verbose: Подробный вывод
    
    Returns:
        Dict с результатами
    """
    print("🚀 Запуск обратного заполнения БДУ данных...")
    print(f"   Режим: {'DRY RUN (без сохранения)' if dry_run else 'ЗАПИСЬ В БД'}")
    if limit:
        print(f"   Лимит: {limit} записей")
    print()
    
    service = VulnerabilityService(use_optimized=False)
    extractor = BDUDataExtractor()
    
    # Получить все уязвимости
    try:
        all_vulns = service.get_all_vulnerabilities_unlimited()
        total = len(all_vulns)
        print(f"📊 Найдено уязвимостей: {total}")
    except Exception as e:
        print(f"❌ Ошибка при получении уязвимостей: {e}")
        return {'error': str(e)}
    
    # Ограничить количество если нужно
    if limit:
        all_vulns = all_vulns[:limit]
    
    # Счетчики
    stats = {
        'processed': 0,
        'updated': 0,
        'skipped': 0,
        'errors': [],
        'fields_extracted': {
            'bdu_id': 0,
            'vendor': 0,
            'product_name': 0,
            'exploit_available': 0,
            'dates': 0,
        }
    }
    
    # Обработка каждой уязвимости
    for idx, vuln in enumerate(all_vulns, 1):
        stats['processed'] += 1
        
        try:
            # Извлечь данные
            extracted = extractor.extract_all(vuln.title or '', vuln.description or '')
            
            if not extracted:
                stats['skipped'] += 1
                if verbose:
                    print(f"  [{idx}/{len(all_vulns)}] ID {vuln.id}: нет данных для извлечения")
                continue
            
            # Подсчет извлеченных полей
            for field in extracted:
                if field in stats['fields_extracted']:
                    stats['fields_extracted'][field] += 1
                elif field in ['date_discovered', 'remediation_date']:
                    stats['fields_extracted']['dates'] += 1
            
            # Вывод
            if verbose or extracted:
                print(f"✅ [{idx}/{len(all_vulns)}] ID {vuln.id}:")
                for field, value in extracted.items():
                    print(f"     {field}: {value}")
            
            # Обновить в БД (если не dry-run)
            if not dry_run:
                success = service.update_vulnerability(vuln.id, **extracted)
                if success:
                    stats['updated'] += 1
                else:
                    stats['errors'].append(f"ID {vuln.id}: не удалось обновить")
            else:
                stats['updated'] += 1  # В dry-run считаем как обновленные
            
        except Exception as e:
            stats['errors'].append(f"ID {vuln.id}: {str(e)}")
            if verbose:
                print(f"❌ [{idx}/{len(all_vulns)}] ID {vuln.id}: Ошибка - {e}")
    
    return stats


def print_results(stats: Dict):
    """Вывести результаты обработки"""
    print("\n" + "="*60)
    print("📊 РЕЗУЛЬТАТЫ ОБРАБОТКИ")
    print("="*60)
    print(f"✅ Обработано записей:     {stats['processed']}")
    print(f"🔄 Обновлено записей:      {stats['updated']}")
    print(f"⏭️  Пропущено (нет данных): {stats['skipped']}")
    print()
    print("📋 Извлечено полей:")
    for field, count in stats['fields_extracted'].items():
        print(f"   • {field:20s}: {count}")
    
    if stats['errors']:
        print(f"\n⚠️  Ошибок: {len(stats['errors'])}")
        print("   Первые 10 ошибок:")
        for error in stats['errors'][:10]:
            print(f"   - {error}")
    
    print("\n" + "="*60)


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(
        description='Обратное заполнение БДУ данных из существующих записей',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  # Тестовый прогон (не сохранять изменения)
  python scripts/migration/backfill_bdu_data.py --dry-run
  
  # Обработать только 100 записей
  python scripts/migration/backfill_bdu_data.py --limit 100 --verbose
  
  # Полная обработка с сохранением
  python scripts/migration/backfill_bdu_data.py
        """
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Не сохранять изменения, только показать что будет изменено'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Обработать только N записей (для тестирования)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Подробный вывод'
    )
    
    args = parser.parse_args()
    
    # Запуск обработки
    try:
        stats = backfill_vulnerabilities(
            dry_run=args.dry_run,
            limit=args.limit,
            verbose=args.verbose
        )
        
        # Вывод результатов
        print_results(stats)
        
        # Предупреждение для dry-run
        if args.dry_run:
            print("\n⚠️  ЭТО БЫЛ ТЕСТОВЫЙ ПРОГОН! Данные НЕ сохранены в БД.")
            print("   Запустите без --dry-run для сохранения изменений.")
        else:
            print("\n✅ Данные успешно сохранены в базу данных!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Прервано пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

