"""
Загрузчик официальных CVE JSON файлов с cve.org
Использует официальный формат CVE JSON 5.x
"""
import logging
import json
import requests
from typing import Dict, List, Optional, Any, Iterator
from datetime import datetime, timedelta
from pathlib import Path
import gzip
from services.cve_json5_adapter import cve_json5_adapter

logger = logging.getLogger(__name__)


class CVEJSONLoader:
    """
    Загрузчик CVE JSON файлов с официального источника
    
    Источники:
    - https://www.cve.org/Downloads
    - Официальные JSON файлы CVE
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.base_url = "https://www.cve.org/Downloads"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Vulnerability-Manager/1.0 (CVE JSON Loader)'
        })
        self.timeout = 300  # 5 минут для больших файлов
    
    def load_cve_json_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Загрузка CVE JSON файла с диска
        
        Args:
            file_path: Путь к JSON файлу (может быть .gz)
            
        Returns:
            Список CVE записей
        """
        cves = []
        try:
            file_path_obj = Path(file_path)
            
            # Определяем формат файла
            if file_path_obj.suffix == '.gz':
                # Распаковываем gzip
                with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                # Обычный JSON
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            
            # Обработка разных форматов
            if isinstance(data, dict):
                # Если это объект с полями CVERecords
                if 'CVERecords' in data:
                    cves = data['CVERecords']
                elif 'cveRecords' in data:
                    cves = data['cveRecords']
                elif 'dataType' in data and data.get('dataType') == 'CVE_RECORD':
                    # Одна запись
                    cves = [data]
            elif isinstance(data, list):
                # Список записей
                cves = data
            
            self.logger.info(f"✅ Загружено {len(cves)} CVE записей из {file_path}")
            return cves
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка загрузки файла {file_path}: {e}", exc_info=True)
            return []
    
    def download_cve_json_file(self, url: str, save_path: Optional[str] = None) -> Optional[str]:
        """
        Скачивание CVE JSON файла
        
        Args:
            url: URL файла для скачивания
            save_path: Путь для сохранения (опционально)
            
        Returns:
            Путь к сохраненному файлу или None при ошибке
        """
        try:
            self.logger.info(f"📥 Скачивание CVE JSON файла: {url}")
            
            response = self.session.get(url, timeout=self.timeout, stream=True)
            response.raise_for_status()
            
            # Определяем путь для сохранения
            if not save_path:
                filename = url.split('/')[-1]
                save_path = f"/tmp/{filename}"
            
            # Сохраняем файл
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            self.logger.info(f"✅ Файл сохранен: {save_path} ({Path(save_path).stat().st_size / 1024 / 1024:.2f} MB)")
            return save_path
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка скачивания файла {url}: {e}", exc_info=True)
            return None
    
    def parse_cve_records(self, cve_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Парсинг списка CVE записей
        
        Args:
            cve_records: Список CVE записей в формате JSON 5.x
            
        Returns:
            Список нормализованных данных уязвимостей
        """
        parsed_cves = []
        
        for idx, cve_record in enumerate(cve_records, 1):
            try:
                parsed = cve_json5_adapter.parse_cve_record(cve_record)
                if parsed:
                    parsed_cves.append(parsed)
                
                if idx % 100 == 0:
                    self.logger.debug(f"Обработано {idx}/{len(cve_records)} CVE записей")
                    
            except Exception as e:
                self.logger.error(f"Ошибка парсинга CVE записи {idx}: {e}")
        
        self.logger.info(f"✅ Распарсено {len(parsed_cves)} из {len(cve_records)} CVE записей")
        return parsed_cves
    
    def get_cve_by_id(self, cve_id: str, cve_records: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Получить конкретную CVE запись по ID
        
        Args:
            cve_id: CVE ID (например, CVE-2024-1234)
            cve_records: Список CVE записей
            
        Returns:
            CVE запись или None
        """
        for record in cve_records:
            metadata = record.get('cveMetadata', {})
            if metadata.get('cveId') == cve_id:
                return cve_json5_adapter.parse_cve_record(record)
        return None
    
    def filter_cves_by_date(
        self, 
        cve_records: List[Dict[str, Any]], 
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Фильтрация CVE по дате публикации
        
        Args:
            cve_records: Список CVE записей
            start_date: Начальная дата
            end_date: Конечная дата
            
        Returns:
            Отфильтрованный список
        """
        filtered = []
        
        for record in cve_records:
            metadata = record.get('cveMetadata', {})
            date_published_str = metadata.get('datePublished')
            
            if not date_published_str:
                continue
            
            try:
                date_published = datetime.fromisoformat(date_published_str.replace('Z', '+00:00'))
                
                if start_date and date_published < start_date:
                    continue
                if end_date and date_published > end_date:
                    continue
                
                filtered.append(record)
            except Exception as e:
                self.logger.debug(f"Ошибка парсинга даты для CVE: {e}")
        
        return filtered
    
    def get_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Получить недавние CVE (за последние N дней)
        
        Args:
            days: Количество дней
            
        Returns:
            Список CVE записей
        """
        # TODO: Реализовать загрузку с официального API
        # Пока это заглушка - нужно узнать актуальные URL для загрузки
        
        self.logger.warning("⚠️ get_recent_cves() требует реализации загрузки с официального API")
        self.logger.info(f"💡 Используйте load_cve_json_file() для загрузки файлов с cve.org")
        
        return []
    
    def load_and_parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Загрузить и распарсить CVE JSON файл
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            Список нормализованных CVE данных
        """
        # Загружаем записи
        cve_records = self.load_cve_json_file(file_path)
        
        if not cve_records:
            return []
        
        # Парсим
        parsed_cves = self.parse_cve_records(cve_records)
        
        return parsed_cves


# Глобальный экземпляр
_cve_json_loader_instance = None

def get_cve_json_loader():
    """Получить экземпляр CVEJSONLoader"""
    global _cve_json_loader_instance
    if _cve_json_loader_instance is None:
        _cve_json_loader_instance = CVEJSONLoader()
    return _cve_json_loader_instance

cve_json_loader = get_cve_json_loader()

