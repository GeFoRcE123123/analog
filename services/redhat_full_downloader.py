#!/usr/bin/env python3
"""
Полное скачивание всех CVE из Red Hat Security Data API
Скрипт для массового скачивания и обработки данных
"""

import requests
import time
import os
import json
import glob
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

BASE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
PER_PAGE = 1000
DATA_DIR = Path("cve_data/full")
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Экспорт для использования в других модулях
__all__ = ['download_all_pages', 'process_json_files', 'save_to_csv', 'DATA_DIR', 'BASE_URL', 'PER_PAGE']


def download_all_pages(max_pages: int = None) -> int:
    """
    Скачивание всех страниц CVE из Red Hat API
    
    Args:
        max_pages: Максимальное количество страниц (None = все)
        
    Returns:
        Количество скачанных страниц
    """
    page = 1
    total_pages = 0
    
    logger.info("Начало скачивания CVE из Red Hat API")
    
    while True:
        if max_pages and page > max_pages:
            logger.info(f"Достигнут лимит страниц: {max_pages}")
            break
        
        logger.info(f"Скачивание страницы {page}...")
        
        try:
            url = f"{BASE_URL}?per_page={PER_PAGE}&page={page}&isCompressed=false"
            response = requests.get(url, timeout=30)
            
            if response.status_code != 200:
                logger.warning(f"Ошибка {response.status_code} — завершаем скачивание")
                break
            
            data = response.json()
            
            # Если данных нет — выходим
            if not data:
                logger.info("Больше данных нет")
                break
            
            # Сохраняем файл
            file_path = DATA_DIR / f"page_{page}.json"
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"  → Сохранено {len(data)} записей в {file_path}")
            total_pages += 1
            
            # Уважаем API — делаем паузу
            time.sleep(1)
            
            page += 1
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Ошибка при скачивании страницы {page}: {e}")
            break
        except Exception as e:
            logger.error(f"Неожиданная ошибка на странице {page}: {e}")
            break
    
    logger.info(f"✅ Все страницы скачаны! Всего: {total_pages} страниц")
    return total_pages


def process_json_files() -> pd.DataFrame:
    """
    Обработка всех JSON файлов и создание DataFrame
    
    Returns:
        DataFrame с данными CVE
    """
    file_paths = sorted(glob.glob(str(DATA_DIR / "page_*.json")))
    
    if not file_paths:
        logger.warning(f"Не найдено JSON файлов в {DATA_DIR}")
        return pd.DataFrame()
    
    logger.info(f"Обработка {len(file_paths)} JSON файлов...")
    
    all_records = []
    
    for path in file_paths:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data:
                    # Извлекаем описание
                    description = item.get('bugzilla_description', '') or (
                        item.get('details', [''])[0] if isinstance(item.get('details', []), list) and item.get('details') else ''
                    )
                    
                    # Извлекаем CVSS3 score
                    cvss3_data = item.get('cvss3', {})
                    if isinstance(cvss3_data, dict):
                        cvss3_score = cvss3_data.get('cvss3_base_score', None)
                    else:
                        cvss3_score = item.get('cvss3_score', None)
                    
                    # Извлекаем severity
                    severity = (
                        item.get('threat_severity', '') or
                        item.get('severity', '')
                    )
                    
                    all_records.append({
                        'cve_id': item.get('CVE', ''),
                        'description': str(description) if description else '',
                        'severity': severity,
                        'cvss3': cvss3_score,
                        'public_date': item.get('public_date', '')
                    })
        
        except Exception as e:
            logger.error(f"Ошибка при обработке файла {path}: {e}")
            continue
    
    df = pd.DataFrame(all_records)
    logger.info(f"✅ Создан DataFrame с {len(df)} записями")
    
    return df


def save_to_csv(df: pd.DataFrame, filename: str = "redhat_all_cve.csv") -> str:
    """
    Сохранение DataFrame в CSV
    
    Args:
        df: DataFrame
        filename: Имя файла
        
    Returns:
        Путь к сохраненному файлу
    """
    file_path = DATA_DIR / filename
    df.to_csv(file_path, index=False, encoding='utf-8')
    logger.info(f"✅ Данные сохранены в {file_path}")
    return str(file_path)


def main():
    """Основная функция"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Скачивание и обработка CVE из Red Hat API')
    parser.add_argument('--download', action='store_true', help='Скачать данные из API')
    parser.add_argument('--process', action='store_true', help='Обработать скачанные JSON файлы')
    parser.add_argument('--max-pages', type=int, default=None, help='Максимальное количество страниц для скачивания')
    parser.add_argument('--all', action='store_true', help='Выполнить все операции (скачать и обработать)')
    
    args = parser.parse_args()
    
    if args.all or args.download:
        # Скачивание
        pages = download_all_pages(max_pages=args.max_pages)
        logger.info(f"Скачано страниц: {pages}")
    
    if args.all or args.process:
        # Обработка
        df = process_json_files()
        
        if not df.empty:
            # Сохранение в CSV
            csv_path = save_to_csv(df)
            
            # Показываем статистику
            logger.info(f"\nСтатистика:")
            logger.info(f"  Всего CVE: {len(df)}")
            logger.info(f"  С описанием: {df['description'].notna().sum()}")
            logger.info(f"  С CVSS3: {df['cvss3'].notna().sum()}")
            logger.info(f"  С severity: {df['severity'].notna().sum()}")
            
            # Показываем первые строки
            logger.info(f"\nПервые 5 записей:")
            print(df.head().to_string())
        else:
            logger.warning("DataFrame пуст, нечего обрабатывать")


if __name__ == "__main__":
    main()
