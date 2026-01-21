#!/usr/bin/env python3
"""
Скрипт импорта уязвимостей Grafana Security Advisories

Usage:
    python scripts/import_grafana_advisories.py
    python scripts/import_grafana_advisories.py --severity critical
    python scripts/import_grafana_advisories.py --product grafana
    python scripts/import_grafana_advisories.py --dry-run
    python scripts/import_grafana_advisories.py --limit 10
"""

import sys
import argparse
from pathlib import Path

# Добавить корневую директорию в PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def sync_grafana_advisories(severity=None, product=None, dry_run=False, limit=None):
    """
    Синхронизация Grafana advisories с БД
    
    Args:
        severity: Фильтр по severity (critical, high, medium, low)
        product: Фильтр по продукту
        dry_run: Режим тестирования (не сохранять в БД)
        limit: Максимальное количество advisory для обработки
    """
    from services.parsers.grafana_parser import GrafanaSecurityParser
    from services.parsers.grafana_mapper import GrafanaDataMapper
    
    logger.info("🚀 Starting Grafana Security Advisories sync...")
    logger.info(f"   Filters: severity={severity}, product={product}, limit={limit}")
    logger.info(f"   Mode: {'DRY RUN' if dry_run else 'LIVE'}")
    
    # Инициализация
    parser = GrafanaSecurityParser(cache_enabled=True)
    mapper = GrafanaDataMapper()
    
    stats = {
        'total': 0,
        'new': 0,
        'updated': 0,
        'skipped': 0,
        'errors': []
    }
    
    try:
        # Получить advisory
        logger.info("📋 Fetching advisories list...")
        advisories = parser.fetch_all_advisories(
            severity=severity,
            product=product,
            limit=limit
        )
        stats['total'] = len(advisories)
        
        logger.info(f"✅ Found {len(advisories)} advisories")
        
        if not dry_run:
            # Импорт сервиса только если не dry-run
            from services.vulnerability_service import VulnerabilityService
            service = VulnerabilityService()
        else:
            service = None
        
        # Обработать каждый advisory
        for i, grafana_data in enumerate(advisories, 1):
            cve_id = grafana_data.get('cve_id', 'UNKNOWN')
            logger.info(f"\n[{i}/{len(advisories)}] Processing {cve_id}...")
            
            try:
                # Маппинг на БД структуру
                db_data = mapper.map_to_db_format(grafana_data)
                
                if dry_run:
                    logger.info(f"   [DRY RUN] Would process: {cve_id}")
                    logger.info(f"   Vendor: {db_data.get('vendor')}")
                    logger.info(f"   Product: {db_data.get('product_name')}")
                    logger.info(f"   CVSS: {db_data.get('cvss_score')}")
                    logger.info(f"   Severity: {db_data.get('severity')}")
                    stats['new'] += 1
                    continue
                
                # Проверить, существует ли в БД
                existing = service.get_by_cve_id(cve_id)
                
                if existing:
                    # Проверить, нужно ли обновить
                    if should_update(existing, db_data):
                        service.update_vulnerability(existing.id, db_data)
                        stats['updated'] += 1
                        logger.info(f"   ✏️  Updated")
                    else:
                        stats['skipped'] += 1
                        logger.info(f"   ⏭️  Skipped (no changes)")
                else:
                    # Создать новую запись
                    service.create_vulnerability(db_data)
                    stats['new'] += 1
                    logger.info(f"   ➕ Created")
            
            except Exception as e:
                error_msg = f"{cve_id}: {str(e)}"
                stats['errors'].append(error_msg)
                logger.error(f"   ❌ Error: {e}")
                import traceback
                logger.debug(traceback.format_exc())
    
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise
    
    # Итоговая статистика
    print("\n" + "="*60)
    print("📊 Sync completed!")
    print(f"   Total:   {stats['total']}")
    print(f"   New:     {stats['new']}")
    print(f"   Updated: {stats['updated']}")
    print(f"   Skipped: {stats['skipped']}")
    print(f"   Errors:  {len(stats['errors'])}")
    
    if stats['errors']:
        print("\n❌ Errors:")
        for error in stats['errors'][:10]:  # Показать первые 10
            print(f"   - {error}")
        if len(stats['errors']) > 10:
            print(f"   ... and {len(stats['errors']) - 10} more")
    
    print("="*60)
    return stats


def should_update(existing, new_data):
    """
    Проверить, нужно ли обновлять запись
    
    Args:
        existing: Существующая запись из БД
        new_data: Новые данные
    
    Returns:
        bool: True если нужно обновить
    """
    # Сравнить ключевые поля
    
    # CVSS Score
    if hasattr(existing, 'cvss_score') and existing.cvss_score != new_data.get('cvss_score'):
        logger.debug(f"   CVSS changed: {existing.cvss_score} -> {new_data.get('cvss_score')}")
        return True
    
    # Title
    if hasattr(existing, 'title') and existing.title != new_data.get('title'):
        logger.debug(f"   Title changed")
        return True
    
    # Description
    if hasattr(existing, 'description'):
        existing_desc = existing.description or ''
        new_desc = new_data.get('description', '')
        if existing_desc != new_desc and len(new_desc) > len(existing_desc):
            logger.debug(f"   Description updated (longer)")
            return True
    
    # Remediation info
    if hasattr(existing, 'remediation_info'):
        existing_rem = existing.remediation_info or ''
        new_rem = new_data.get('remediation_info', '')
        if not existing_rem and new_rem:
            logger.debug(f"   Remediation info added")
            return True
    
    # Если source не указан или отличается
    if hasattr(existing, 'source') and existing.source != 'grafana':
        logger.debug(f"   Adding Grafana source data")
        return True
    
    return False


def main():
    parser = argparse.ArgumentParser(
        description='Import Grafana Security Advisories',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Импорт всех advisory
    python scripts/import_grafana_advisories.py
    
    # Только критические
    python scripts/import_grafana_advisories.py --severity critical
    
    # Только для Grafana
    python scripts/import_grafana_advisories.py --product grafana
    
    # Тестовый режим (первые 10)
    python scripts/import_grafana_advisories.py --dry-run --limit 10
    
    # Комбинация
    python scripts/import_grafana_advisories.py --severity high --product pyroscope --limit 5
        """
    )
    
    parser.add_argument(
        '--severity',
        choices=['critical', 'high', 'medium', 'low'],
        help='Filter by severity level'
    )
    
    parser.add_argument(
        '--product',
        help='Filter by product name (e.g., grafana, pyroscope)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Test mode: do not save to database'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        help='Maximum number of advisories to process'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Настроить уровень логирования
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        stats = sync_grafana_advisories(
            severity=args.severity,
            product=args.product,
            dry_run=args.dry_run,
            limit=args.limit
        )
        
        # Exit code
        if stats['errors']:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except KeyboardInterrupt:
        logger.info("\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()

