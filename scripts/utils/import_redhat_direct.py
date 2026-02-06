#!/usr/bin/env python3
"""
Прямой импорт Red Hat CVE из CSV файла используя существующие модули
"""
import sys
import os
import json
import pandas as pd
from pathlib import Path

# Добавляем путь к корню проекта
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from config import Config
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from services.redhat_cve_importer import RedHatCVEImporter

def import_from_csv(csv_path: str, limit: int = None):
    """Импорт из CSV файла"""
    print(f"🚀 Начало импорта Red Hat CVE из CSV: {csv_path}")
    
    # Инициализация
    db_manager = DatabaseManager()
    if Config.USE_LEGACY_SCHEMA:
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
    else:
        from models.postgres_repositories import PostgresVulnerabilityRepository
        vuln_repo = PostgresVulnerabilityRepository(db_manager.connection)
    
    redhat_importer = RedHatCVEImporter()
    
    # Чтение CSV
    print(f"📖 Чтение CSV файла...")
    df = pd.read_csv(csv_path)
    
    if limit:
        df = df.head(limit)
    
    total = len(df)
    imported = 0
    skipped = 0
    errors = 0
    
    print(f"📊 Всего записей для обработки: {total}")
    
    # Обработка записей
    for i, (_, row) in enumerate(df.iterrows(), 1):
        try:
            cve_id = row.get('cve_id', '')
            if not cve_id:
                errors += 1
                continue
            
            # Проверка существования
            existing = vuln_repo.get_by_cve_id(cve_id)
            if existing:
                skipped += 1
                if i % 1000 == 0:
                    print(f"Обработано {i}/{total}: импортировано {imported}, пропущено {skipped}, ошибок {errors}")
                continue
            
            # Создаем запись в формате Red Hat API
            redhat_cve = {
                'CVE': cve_id,
                'bugzilla_description': row.get('description', ''),
                'threat_severity': row.get('severity', ''),
                'public_date': row.get('public_date', ''),
                'cvss3': {
                    'cvss3_base_score': row.get('cvss3') if pd.notna(row.get('cvss3')) else None
                } if pd.notna(row.get('cvss3')) else {}
            }
            
            # Трансформация в NVD формат
            nvd_vuln = redhat_importer.transform_redhat_to_nvd_format(redhat_cve)
            
            if not nvd_vuln:
                errors += 1
                continue
            
            # Сохранение в БД
            if redhat_importer.save_nvd_vulnerability(nvd_vuln):
                imported += 1
            else:
                errors += 1
            
            # Логирование прогресса
            if i % 1000 == 0:
                print(f"Обработано {i}/{total}: импортировано {imported}, пропущено {skipped}, ошибок {errors}")
        
        except Exception as e:
            errors += 1
            if i % 1000 == 0:
                print(f"Ошибка при импорте записи {i}: {e}")
    
    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ ИМПОРТА")
    print("=" * 50)
    print(f"Всего записей: {total}")
    print(f"Импортировано: {imported}")
    print(f"Пропущено: {skipped}")
    print(f"Ошибок: {errors}")
    
    return {
        'success': True,
        'total': total,
        'imported': imported,
        'skipped': skipped,
        'errors': errors
    }

if __name__ == "__main__":
    csv_path = "/tmp/cve_data/full/redhat_all_cve.csv"
    limit = None  # Импортировать все
    
    if not os.path.exists(csv_path):
        print(f"❌ Файл не найден: {csv_path}")
        sys.exit(1)
    
    result = import_from_csv(csv_path, limit=limit)
    sys.exit(0 if result.get('success') else 1)
