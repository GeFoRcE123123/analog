#!/usr/bin/env python3
"""
Скрипт для импорта Red Hat CVE из CSV файла
"""
import sys
import os

# Добавляем путь к корню проекта
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from services.redhat_db_importer import RedHatDBImporter

if __name__ == "__main__":
    csv_path = "/tmp/cve_data/full/redhat_all_cve.csv"
    limit = None  # Импортировать все
    
    print("🚀 Начало импорта Red Hat CVE из CSV...")
    print(f"📁 CSV файл: {csv_path}")
    
    importer = RedHatDBImporter(data_dir="/tmp/cve_data/full")
    result = importer.import_from_csv(csv_path, limit=limit)
    
    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ ИМПОРТА")
    print("=" * 50)
    print(f"Всего записей: {result.get('total', 0)}")
    print(f"Импортировано: {result.get('imported', 0)}")
    print(f"Пропущено: {result.get('skipped', 0)}")
    print(f"Ошибок: {result.get('errors', 0)}")
    
    if result.get('errors') > 0 and result.get('errors_list'):
        print(f"\nПервые 10 ошибок:")
        for error in result.get('errors_list', [])[:10]:
            print(f"  - {error}")
    
    sys.exit(0 if result.get('success') else 1)
