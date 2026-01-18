"""
Импорт Red Hat CVE из скачанных JSON файлов в базу данных
"""

import json
import glob
import logging
import sys
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

# Добавление пути к корню проекта
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from config import Config
from models.database import DatabaseManager
from models.entities import Vulnerability
from models.postgres_repositories import PostgresVulnerabilityRepository
from models.legacy_repositories import LegacyVulnerabilityRepository
from services.redhat_cve_importer import RedHatCVEImporter

logger = logging.getLogger(__name__)


class RedHatDBImporter:
    """Импортер Red Hat CVE из JSON файлов в БД"""
    
    def __init__(self, data_dir: str = "cve_data/full"):
        """
        Инициализация импортера
        
        Args:
            data_dir: Директория с JSON файлами
        """
        self.data_dir = Path(data_dir)
        self.db_manager = DatabaseManager()
        
        # Используем legacy или modern репозиторий
        if Config.USE_LEGACY_SCHEMA:
            self.vuln_repo = LegacyVulnerabilityRepository(self.db_manager.connection)
        else:
            self.vuln_repo = PostgresVulnerabilityRepository(self.db_manager.connection)
        
        # Используем существующий RedHatCVEImporter для трансформации
        self.redhat_importer = RedHatCVEImporter()
    
    def load_json_files(self) -> List[Dict[str, Any]]:
        """
        Загрузка всех JSON файлов
        
        Returns:
            Список всех записей CVE
        """
        file_paths = sorted(glob.glob(str(self.data_dir / "page_*.json")))
        
        if not file_paths:
            logger.warning(f"Не найдено JSON файлов в {self.data_dir}")
            return []
        
        all_records = []
        
        logger.info(f"Загрузка {len(file_paths)} JSON файлов...")
        
        for path in file_paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for item in data:
                        all_records.append(item)
            except Exception as e:
                logger.error(f"Ошибка при загрузке файла {path}: {e}")
                continue
        
        logger.info(f"Загружено {len(all_records)} записей CVE")
        return all_records
    
    def import_to_database(
        self,
        records: Optional[List[Dict[str, Any]]] = None,
        limit: Optional[int] = None,
        skip_existing: bool = True
    ) -> Dict[str, Any]:
        """
        Импорт записей в базу данных
        
        Args:
            records: Список записей (если None, загружает из файлов)
            limit: Максимальное количество записей для импорта
            skip_existing: Пропускать существующие CVE
            
        Returns:
            Словарь со статистикой импорта
        """
        if records is None:
            records = self.load_json_files()
        
        if not records:
            return {
                'success': False,
                'message': 'Нет данных для импорта',
                'total': 0,
                'imported': 0,
                'skipped': 0,
                'errors': 0
            }
        
        # Ограничение количества
        if limit:
            records = records[:limit]
        
        stats = {
            'total': len(records),
            'imported': 0,
            'skipped': 0,
            'errors': 0,
            'errors_list': []
        }
        
        logger.info(f"Начало импорта {len(records)} записей Red Hat CVE в БД")
        
        for i, redhat_cve in enumerate(records, 1):
            try:
                cve_id = redhat_cve.get('CVE', '')
                
                if not cve_id:
                    stats['errors'] += 1
                    stats['errors_list'].append(f"Запись {i}: отсутствует CVE ID")
                    continue
                
                # Проверка существования
                if skip_existing:
                    existing = self.vuln_repo.get_by_cve_id(cve_id)
                    if existing:
                        stats['skipped'] += 1
                        if i % 100 == 0:
                            logger.info(f"Обработано {i}/{len(records)}: импортировано {stats['imported']}, пропущено {stats['skipped']}")
                        continue
                
                # Трансформация в NVD формат
                nvd_vuln = self.redhat_importer.transform_redhat_to_nvd_format(redhat_cve)
                
                if not nvd_vuln:
                    stats['errors'] += 1
                    stats['errors_list'].append(f"{cve_id}: ошибка трансформации")
                    continue
                
                # Сохранение в БД
                if self.redhat_importer.save_nvd_vulnerability(nvd_vuln):
                    stats['imported'] += 1
                else:
                    stats['errors'] += 1
                    stats['errors_list'].append(f"{cve_id}: ошибка сохранения")
                
                # Логирование прогресса
                if i % 100 == 0:
                    logger.info(
                        f"Обработано {i}/{len(records)}: "
                        f"импортировано {stats['imported']}, "
                        f"пропущено {stats['skipped']}, "
                        f"ошибок {stats['errors']}"
                    )
            
            except Exception as e:
                stats['errors'] += 1
                error_msg = f"Ошибка при импорте записи {i}: {e}"
                stats['errors_list'].append(error_msg)
                logger.error(error_msg, exc_info=True)
        
        logger.info(
            f"Импорт завершен: всего {stats['total']}, "
            f"импортировано {stats['imported']}, "
            f"пропущено {stats['skipped']}, "
            f"ошибок {stats['errors']}"
        )
        
        return {
            'success': True,
            'message': f"Импортировано {stats['imported']} из {stats['total']} записей",
            **stats
        }
    
    def import_from_csv(self, csv_path: str, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Импорт из CSV файла
        
        Args:
            csv_path: Путь к CSV файлу
            limit: Максимальное количество записей
            
        Returns:
            Словарь со статистикой импорта
        """
        try:
            import pandas as pd
            
            df = pd.read_csv(csv_path)
            
            if limit:
                df = df.head(limit)
            
            records = []
            for _, row in df.iterrows():
                # Создаем запись в формате Red Hat API
                record = {
                    'CVE': row.get('cve_id', ''),
                    'bugzilla_description': row.get('description', ''),
                    'threat_severity': row.get('severity', ''),
                    'public_date': row.get('public_date', ''),
                    'cvss3': {
                        'cvss3_base_score': row.get('cvss3') if pd.notna(row.get('cvss3')) else None
                    } if pd.notna(row.get('cvss3')) else {}
                }
                records.append(record)
            
            return self.import_to_database(records, skip_existing=True)
        
        except Exception as e:
            logger.error(f"Ошибка импорта из CSV: {e}")
            return {
                'success': False,
                'message': f"Ошибка импорта из CSV: {e}",
                'total': 0,
                'imported': 0,
                'skipped': 0,
                'errors': 1
            }


def main():
    """Основная функция для запуска из командной строки"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Импорт Red Hat CVE в БД')
    parser.add_argument('--data-dir', type=str, default='cve_data/full', help='Директория с JSON файлами')
    parser.add_argument('--csv', type=str, help='Путь к CSV файлу для импорта')
    parser.add_argument('--limit', type=int, help='Максимальное количество записей')
    parser.add_argument('--skip-existing', action='store_true', default=True, help='Пропускать существующие CVE')
    
    args = parser.parse_args()
    
    importer = RedHatDBImporter(data_dir=args.data_dir)
    
    if args.csv:
        result = importer.import_from_csv(args.csv, limit=args.limit)
    else:
        result = importer.import_to_database(limit=args.limit, skip_existing=args.skip_existing)
    
    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ ИМПОРТА")
    print("=" * 50)
    print(f"Всего записей: {result['total']}")
    print(f"Импортировано: {result['imported']}")
    print(f"Пропущено: {result['skipped']}")
    print(f"Ошибок: {result['errors']}")
    
    if result['errors'] > 0 and result.get('errors_list'):
        print(f"\nПервые 10 ошибок:")
        for error in result['errors_list'][:10]:
            print(f"  - {error}")
    
    return 0 if result['success'] else 1


if __name__ == "__main__":
    exit(main())
