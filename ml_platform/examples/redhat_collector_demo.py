#!/usr/bin/env python3
"""
Демонстрация работы Red Hat Collector
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml_platform.security.collectors.redhat_collector import RedHatCollector
from ml_platform.core.logger import PlatformLogger

logger = PlatformLogger.get_logger()


def main():
    """Основная функция демонстрации"""
    
    print("=" * 60)
    print("Демонстрация Red Hat Collector")
    print("=" * 60)
    print()
    
    # Создание коллектора
    collector = RedHatCollector(data_dir="cve_data/redhat")
    
    # Опция 1: Скачивание данных (ограничено для демо)
    print("1. Скачивание CVE из Red Hat API (первые 3 страницы для демо)...")
    try:
        pages = collector.download_all_cves(max_pages=3)
        print(f"   ✓ Скачано страниц: {pages}")
    except Exception as e:
        print(f"   ✗ Ошибка скачивания: {e}")
        print("   (Продолжаем с обработкой существующих файлов, если есть)")
    
    print()
    
    # Опция 2: Обработка существующих файлов
    print("2. Обработка JSON файлов...")
    try:
        records = collector.load_json_files()
        print(f"   ✓ Загружено записей: {len(records)}")
        
        if records:
            # Показываем примеры
            print("\n   Примеры записей:")
            for i, record in enumerate(records[:3], 1):
                print(f"\n   Запись {i}:")
                print(f"     CVE ID: {record.get('cve_id', 'N/A')}")
                print(f"     Severity: {record.get('severity', 'N/A')}")
                print(f"     CVSS3: {record.get('cvss3', 'N/A')}")
                print(f"     Описание (первые 100 символов): {record.get('description', '')[:100]}...")
    
    except Exception as e:
        print(f"   ✗ Ошибка обработки: {e}")
        records = []
    
    print()
    
    # Опция 3: Создание DataFrame
    if records:
        print("3. Создание DataFrame...")
        try:
            df = collector.create_dataframe(records)
            print(f"   ✓ DataFrame создан: {len(df)} записей")
            print(f"   Колонки: {', '.join(df.columns)}")
            
            # Статистика
            print("\n   Статистика:")
            print(f"     С описанием: {df['description'].notna().sum()}")
            print(f"     С CVSS3: {df['cvss3'].notna().sum()}")
            print(f"     С severity: {df['severity'].notna().sum()}")
            
            # Сохранение в CSV
            print("\n4. Сохранение в CSV...")
            csv_path = collector.save_to_csv(df)
            if csv_path:
                print(f"   ✓ Сохранено в: {csv_path}")
        
        except Exception as e:
            print(f"   ✗ Ошибка создания DataFrame: {e}")
    
    print()
    print("=" * 60)
    print("Демонстрация завершена")
    print("=" * 60)
    print("\nДля полного скачивания используйте:")
    print("  python3 services/redhat_full_downloader.py --all")


if __name__ == "__main__":
    main()
