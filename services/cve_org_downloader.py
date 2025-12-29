"""
Сервис для автоматического скачивания всех CVE данных с cve.org
Использует официальный GitHub репозиторий CVEProject/cvelistV5
Обеспечивает ежедневное обновление ~380,000 CVE записей
"""
import logging
import os
import subprocess
import shutil
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator
from datetime import datetime
import requests
import gzip
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class CVEOrgDownloader:
    """
    Сервис для скачивания всех CVE данных с официального источника
    
    Источники:
    - GitHub: https://github.com/CVEProject/cvelistV5 (основной)
    - CVE.org Downloads: https://www.cve.org/Downloads (альтернативный)
    """
    
    def __init__(self, storage_path: str = "/tmp/cve_data"):
        """
        Инициализация загрузчика
        
        Args:
            storage_path: Путь для хранения клонированного репозитория
        """
        self.logger = logging.getLogger(__name__)
        self.storage_path = Path(storage_path)
        self.repo_url = "https://github.com/CVEProject/cvelistV5.git"
        self.repo_path = self.storage_path / "cvelistV5"
        self.timeout = 600  # 10 минут для операций
        
        # Создаем директорию для хранения
        self.storage_path.mkdir(parents=True, exist_ok=True)
    
    def clone_repository(self, force: bool = False) -> bool:
        """
        Клонирование репозитория CVE
        
        Args:
            force: Если True, пересоздает репозиторий при наличии
            
        Returns:
            True при успехе, False при ошибке
        """
        try:
            # Если репозиторий существует и force=True, удаляем
            if self.repo_path.exists() and force:
                self.logger.info(f"🗑️ Удаление существующего репозитория: {self.repo_path}")
                shutil.rmtree(self.repo_path)
            
            # Если репозиторий уже существует, используем его
            if self.repo_path.exists() and (self.repo_path / ".git").exists():
                self.logger.info(f"✅ Репозиторий уже существует: {self.repo_path}")
                return True
            
            self.logger.info(f"📥 Клонирование репозитория CVE: {self.repo_url}")
            self.logger.info(f"   Путь: {self.repo_path}")
            
            # Клонируем репозиторий (только последний коммит для экономии места)
            result = subprocess.run(
                ["git", "clone", "--depth", "1", self.repo_url, str(self.repo_path)],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                self.logger.error(f"❌ Ошибка клонирования: {result.stderr}")
                return False
            
            self.logger.info(f"✅ Репозиторий успешно клонирован")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"❌ Таймаут при клонировании репозитория")
            return False
        except Exception as e:
            self.logger.error(f"❌ Ошибка клонирования репозитория: {e}", exc_info=True)
            return False
    
    def update_repository(self) -> bool:
        """
        Обновление существующего репозитория (git pull)
        
        Returns:
            True при успехе, False при ошибке
        """
        try:
            if not (self.repo_path / ".git").exists():
                self.logger.warning("⚠️ Репозиторий не найден, выполняем клонирование...")
                return self.clone_repository(force=False)
            
            self.logger.info(f"🔄 Обновление репозитория: {self.repo_path}")
            
            # Переходим в директорию репозитория и обновляем
            result = subprocess.run(
                ["git", "pull"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                self.logger.error(f"❌ Ошибка обновления: {result.stderr}")
                return False
            
            self.logger.info(f"✅ Репозиторий успешно обновлен")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"❌ Таймаут при обновлении репозитория")
            return False
        except Exception as e:
            self.logger.error(f"❌ Ошибка обновления репозитория: {e}", exc_info=True)
            return False
    
    def get_cve_file_paths(self) -> List[Path]:
        """
        Получить список всех CVE JSON файлов из репозитория
        
        Returns:
            Список путей к CVE файлам
        """
        cve_files = []
        
        try:
            # CVE файлы находятся в структуре: cvelistV5/cves/YYYY/XXXXNNNN.json
            # Или в корне: cvelistV5/YYYY/XXXXNNNN.json
            cve_dir = self.repo_path / "cves"
            if not cve_dir.exists():
                # Пробуем найти директорию с годами в корне
                year_dirs = [d for d in self.repo_path.iterdir() if d.is_dir() and d.name.isdigit() and len(d.name) == 4]
                if year_dirs:
                    # Если есть директории с годами в корне, используем корень
                    cve_dir = self.repo_path
                else:
                    # Альтернативная структура - используем корень репозитория
                    cve_dir = self.repo_path
            
            # Рекурсивно ищем все JSON файлы
            for json_file_path in cve_dir.rglob("*.json"):
                # Пропускаем файлы метаданных
                json_file_str = str(json_file_path)
                json_file_name = json_file_path.name  # Path объект всегда имеет атрибут name
                if "schema" in json_file_str.lower() or "README" in json_file_name:
                    continue
                cve_files.append(json_file_path)
            
            self.logger.info(f"📁 Найдено {len(cve_files)} CVE JSON файлов")
            return sorted(cve_files)
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка поиска CVE файлов: {e}", exc_info=True)
            return []
    
    def load_cve_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Загрузка одного CVE файла
        
        Args:
            file_path: Путь к JSON файлу
            
        Returns:
            CVE запись (dict) или None при ошибке
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Если загруженный data - это список, берем первый элемент
            if isinstance(data, list):
                if len(data) > 0:
                    data = data[0]
                else:
                    return None
            
            # Проверяем, что это словарь (ожидаемый формат CVE JSON 5.x)
            if not isinstance(data, dict):
                self.logger.debug(f"⚠️ Неожиданный формат данных в {file_path}: {type(data)}")
                return None
            
            return data
        except Exception as e:
            self.logger.debug(f"⚠️ Ошибка загрузки файла {file_path}: {e}")
            return None
    
    def iterate_cve_files(self, max_files: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """
        Итерация по всем CVE файлам
        
        Args:
            max_files: Максимальное количество файлов для обработки (None = все)
            
        Yields:
            CVE записи в формате JSON 5.x
        """
        cve_files = self.get_cve_file_paths()
        
        if max_files:
            cve_files = cve_files[:max_files]
        
        processed = 0
        for file_path in cve_files:
            cve_data = self.load_cve_file(file_path)
            if cve_data:
                yield cve_data
                processed += 1
                
                if processed % 1000 == 0:
                    self.logger.info(f"📊 Обработано {processed}/{len(cve_files)} CVE файлов")
    
    def get_total_cve_count(self) -> int:
        """
        Получить общее количество CVE в репозитории
        
        Returns:
            Количество CVE файлов
        """
        cve_files = self.get_cve_file_paths()
        return len(cve_files)
    
    def download_all_cves(self, max_cves: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Скачать все CVE записи
        
        Args:
            max_cves: Максимальное количество CVE для загрузки (None = все)
            
        Returns:
            Список всех CVE записей
        """
        all_cves = []
        
        try:
            self.logger.info(f"📥 Начало загрузки всех CVE записей...")
            
            # Получаем общее количество
            total_count = self.get_total_cve_count()
            self.logger.info(f"📊 Всего найдено CVE файлов: {total_count}")
            
            if max_cves:
                self.logger.info(f"⚠️ Ограничение: загружаем только {max_cves} CVE")
            
            # Итерация по файлам
            for idx, cve_data in enumerate(self.iterate_cve_files(max_files=max_cves), 1):
                all_cves.append(cve_data)
                
                if idx % 5000 == 0:
                    self.logger.info(f"📥 Загружено {idx}/{total_count if not max_cves else min(max_cves, total_count)} CVE")
            
            self.logger.info(f"✅ Загружено {len(all_cves)} CVE записей")
            return all_cves
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка загрузки CVE: {e}", exc_info=True)
            return all_cves


# Глобальный экземпляр
_cve_org_downloader_instance = None

def get_cve_org_downloader(storage_path: str = "/tmp/cve_data") -> CVEOrgDownloader:
    """Получить экземпляр CVEOrgDownloader"""
    global _cve_org_downloader_instance
    if _cve_org_downloader_instance is None:
        _cve_org_downloader_instance = CVEOrgDownloader(storage_path=storage_path)
    return _cve_org_downloader_instance

