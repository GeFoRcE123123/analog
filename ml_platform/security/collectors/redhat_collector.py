"""
Сборщик данных из Red Hat Security Data API
"""

import requests
import time
import os
import json
import glob
import pandas as pd
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from ml_platform.core.logger import PlatformLogger


class RedHatCollector:
    """Сборщик данных из Red Hat Security Data API"""
    
    BASE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
    PER_PAGE = 1000
    DEFAULT_DATA_DIR = "cve_data/redhat"
    
    def __init__(self, data_dir: Optional[str] = None, rate_limit_delay: float = 1.0):
        """
        Инициализация сборщика Red Hat
        
        Args:
            data_dir: Директория для сохранения данных
            rate_limit_delay: Задержка между запросами (секунды)
        """
        self.data_dir = Path(data_dir or self.DEFAULT_DATA_DIR)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.full_data_dir = self.data_dir / "full"
        self.full_data_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limit_delay = rate_limit_delay
        self.logger = PlatformLogger.get_logger()
    
    def download_all_cves(self, max_pages: Optional[int] = None) -> int:
        """
        Скачивание всех CVE из Red Hat API
        
        Args:
            max_pages: Максимальное количество страниц (None = все)
            
        Returns:
            Количество скачанных страниц
        """
        page = 1
        total_pages = 0
        
        self.logger.info("Начало скачивания CVE из Red Hat API")
        
        while True:
            if max_pages and page > max_pages:
                self.logger.info(f"Достигнут лимит страниц: {max_pages}")
                break
            
            self.logger.info(f"Скачивание страницы {page}...")
            
            try:
                url = f"{self.BASE_URL}?per_page={self.PER_PAGE}&page={page}&isCompressed=false"
                response = requests.get(url, timeout=30)
                
                if response.status_code != 200:
                    self.logger.warning(f"Ошибка {response.status_code} — завершаем скачивание")
                    break
                
                data = response.json()
                
                # Если данных нет — выходим
                if not data:
                    self.logger.info("Больше данных нет")
                    break
                
                # Сохранение файла
                file_path = self.full_data_dir / f"page_{page}.json"
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                
                self.logger.info(f"  → Сохранено {len(data)} записей в {file_path}")
                total_pages += 1
                
                # Уважаем API — делаем паузу
                time.sleep(self.rate_limit_delay)
                
                page += 1
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Ошибка при скачивании страницы {page}: {e}")
                break
            except Exception as e:
                self.logger.error(f"Неожиданная ошибка на странице {page}: {e}")
                break
        
        self.logger.info(f"✅ Все страницы скачаны! Всего: {total_pages} страниц")
        return total_pages
    
    def load_json_files(self) -> List[Dict[str, Any]]:
        """
        Загрузка всех JSON файлов из директории
        
        Returns:
            Список всех записей CVE
        """
        file_paths = sorted(glob.glob(str(self.full_data_dir / "page_*.json")))
        
        if not file_paths:
            self.logger.warning(f"Не найдено JSON файлов в {self.full_data_dir}")
            return []
        
        all_records = []
        
        self.logger.info(f"Загрузка {len(file_paths)} JSON файлов...")
        
        for path in file_paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for item in data:
                        # Извлекаем описание (пробуем разные поля)
                        description = (
                            item.get('bugzilla_description', '') or
                            item.get('description', '') or
                            (item.get('details', [''])[0] if isinstance(item.get('details', []), list) and item.get('details') else '')
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
                        
                        record = {
                            'cve_id': item.get('CVE', ''),
                            'description': str(description) if description else '',
                            'severity': severity,
                            'cvss3': cvss3_score,
                            'public_date': item.get('public_date', ''),
                            'raw_data': item  # Сохраняем полные данные
                        }
                        
                        all_records.append(record)
            
            except Exception as e:
                self.logger.error(f"Ошибка при загрузке файла {path}: {e}")
                continue
        
        self.logger.info(f"Загружено {len(all_records)} записей CVE")
        return all_records
    
    def create_dataframe(self, records: Optional[List[Dict[str, Any]]] = None) -> pd.DataFrame:
        """
        Создание DataFrame из записей
        
        Args:
            records: Список записей (если None, загружает из файлов)
            
        Returns:
            DataFrame с данными CVE
        """
        if records is None:
            records = self.load_json_files()
        
        if not records:
            self.logger.warning("Нет данных для создания DataFrame")
            return pd.DataFrame()
        
        # Создаем DataFrame без raw_data для CSV
        df_data = []
        for record in records:
            df_data.append({
                'cve_id': record.get('cve_id', ''),
                'description': record.get('description', ''),
                'severity': record.get('severity', ''),
                'cvss3': record.get('cvss3'),
                'public_date': record.get('public_date', '')
            })
        
        df = pd.DataFrame(df_data)
        self.logger.info(f"✅ Создан DataFrame с {len(df)} записями")
        
        return df
    
    def save_to_csv(self, df: Optional[pd.DataFrame] = None, filename: str = "redhat_all_cve.csv") -> str:
        """
        Сохранение DataFrame в CSV
        
        Args:
            df: DataFrame (если None, создается из файлов)
            filename: Имя файла
            
        Returns:
            Путь к сохраненному файлу
        """
        if df is None:
            df = self.create_dataframe()
        
        if df.empty:
            self.logger.warning("DataFrame пуст, нечего сохранять")
            return ""
        
        file_path = self.data_dir / filename
        df.to_csv(file_path, index=False, encoding='utf-8')
        
        self.logger.info(f"✅ Данные сохранены в {file_path}")
        return str(file_path)
    
    def normalize_cve_data(self, redhat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Нормализация данных Red Hat CVE для единого формата
        
        Args:
            redhat_data: Сырые данные из Red Hat API
            
        Returns:
            Нормализованные данные
        """
        cve_id = redhat_data.get('CVE', '')
        
        # Извлечение описания
        description = (
            redhat_data.get('bugzilla_description', '') or
            redhat_data.get('description', '') or
            (redhat_data.get('details', [''])[0] if isinstance(redhat_data.get('details', []), list) and redhat_data.get('details') else '')
        )
        
        # Извлечение CVSS
        cvss_v3 = None
        cvss3_data = redhat_data.get('cvss3', {})
        
        if isinstance(cvss3_data, dict) and cvss3_data.get('cvss3_base_score'):
            cvss_v3 = {
                "version": "3.1",
                "base_score": float(cvss3_data.get('cvss3_base_score', 0)),
                "vector_string": cvss3_data.get('cvss3_scoring_vector', ''),
                "severity": redhat_data.get('threat_severity', '')
            }
        
        # Даты
        published = redhat_data.get('public_date', '')
        
        # Затронутые продукты
        affected_products = []
        affected_releases = redhat_data.get('affected_release', [])
        for release in affected_releases:
            if isinstance(release, dict):
                product = release.get('product_name', '')
                version = release.get('release_date', '')
                if product:
                    affected_products.append({
                        "vendor": "Red Hat",
                        "product": product,
                        "version": version
                    })
        
        return {
            "cve_id": cve_id,
            "description": description,
            "published_date": published,
            "last_modified": published,  # Red Hat не предоставляет отдельное поле
            "cvss_v3": cvss_v3,
            "affected_products": affected_products,
            "severity": redhat_data.get('threat_severity', ''),
            "source": "Red Hat",
            "raw_data": redhat_data
        }
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение конкретного CVE по ID (из скачанных данных)
        
        Args:
            cve_id: Идентификатор CVE
            
        Returns:
            Данные CVE или None
        """
        records = self.load_json_files()
        
        for record in records:
            if record.get('cve_id') == cve_id:
                return record.get('raw_data')
        
        return None
    
    def get_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Получение недавних CVE
        
        Args:
            days: Количество дней назад
            
        Returns:
            Список недавних CVE
        """
        records = self.load_json_files()
        
        if not records:
            return []
        
        cutoff_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff_date = cutoff_date.replace(day=cutoff_date.day - days)
        
        recent_cves = []
        
        for record in records:
            public_date_str = record.get('public_date', '')
            if public_date_str:
                try:
                    public_date = datetime.fromisoformat(public_date_str.replace('Z', '+00:00'))
                    if public_date >= cutoff_date:
                        recent_cves.append(record.get('raw_data', {}))
                except:
                    continue
        
        return recent_cves


# Пример использования
if __name__ == "__main__":
    collector = RedHatCollector()
    
    # Скачивание всех CVE
    print("Скачивание CVE из Red Hat...")
    pages = collector.download_all_cves(max_pages=5)  # Для теста ограничим 5 страницами
    print(f"Скачано страниц: {pages}")
    
    # Создание DataFrame
    print("\nСоздание DataFrame...")
    df = collector.create_dataframe()
    print(f"Записей в DataFrame: {len(df)}")
    
    # Сохранение в CSV
    print("\nСохранение в CSV...")
    csv_path = collector.save_to_csv(df)
    print(f"Сохранено в: {csv_path}")
    
    # Показываем первые строки
    if not df.empty:
        print("\nПервые 5 записей:")
        print(df.head())
