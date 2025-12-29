"""
Парсер NVD по ключевым словам
Адаптирован из pars/NVD (keywords).txt
"""
import logging
import re
import json
import zipfile
from typing import Dict, Any, List
import requests
from io import BytesIO

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class NVDKeywordsParser(BaseLegacyParser):
    """
    Парсер NVD по ключевым словам из словаря
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("NVDKeywords", vulnerability_repo)
        self.nvd_feed_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip'
    
    def parse(self, limit: int = 100, keywords: List[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Парсинг NVD по ключевым словам
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            keywords: Список ключевых слов для фильтрации (если None, используется словарь из БД)
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг NVD по ключевым словам (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            # Получаем ключевые слова
            if keywords is None:
                # Пытаемся получить из БД (если есть таблица dictionary)
                keywords = []
                try:
                    # Используем connection напрямую, так как это psycopg connection
                    with self.vulnerability_repo.connection.cursor() as cursor:
                        cursor.execute("SELECT word FROM dictionary")
                        records = cursor.fetchall()
                        keywords = [re.sub(r"[^а-яА-ЯёЁa-zA-Z0-9-./#!@: ]", "", str(x[0])) for x in records if x[0]]
                        keywords = list(set(keywords))  # Убираем дубликаты
                except:
                    self.logger.warning("⚠️ Не удалось получить ключевые слова из БД, используем пустой список")
                    keywords = []
            
            if not keywords:
                self.logger.warning("⚠️ Нет ключевых слов для фильтрации")
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': ['Нет ключевых слов для фильтрации']
                }
            
            # Загружаем NVD feed
            try:
                self.logger.info("📥 Загрузка NVD feed...")
                response = requests.get(self.nvd_feed_url, timeout=60, stream=True)
                response.raise_for_status()
                
                # Распаковываем ZIP
                zip_file = zipfile.ZipFile(BytesIO(response.content))
                json_file_name = [f for f in zip_file.namelist() if f.endswith('.json')][0]
                json_data = json.loads(zip_file.read(json_file_name).decode('utf-8'))
            except Exception as e:
                self.logger.error(f"❌ Ошибка загрузки NVD feed: {e}")
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': [f'Ошибка загрузки NVD feed: {e}']
                }
            
            # Фильтруем по ключевым словам
            filtered_cves = []
            
            for item in json_data.get('CVE_Items', []):
                if len(filtered_cves) >= limit:
                    break
                
                cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                if not cve_id:
                    continue
                
                # Получаем описание
                description = ''
                try:
                    description_data = item.get('cve', {}).get('description', {}).get('description_data', [])
                    if description_data:
                        description = description_data[0].get('value', '')
                except:
                    pass
                
                # Проверяем наличие ключевых слов в описании
                description_lower = description.lower()
                for keyword in keywords:
                    if keyword.lower() in description_lower:
                        # Получаем CVSS score
                        cvss = 3.0  # По умолчанию
                        try:
                            impact = item.get('impact', {})
                            base_metric_v3 = impact.get('baseMetricV3', {})
                            cvss_v3 = base_metric_v3.get('cvssV3', {})
                            cvss = float(cvss_v3.get('baseScore', 3.0))
                        except:
                            try:
                                base_metric_v2 = impact.get('baseMetricV2', {})
                                cvss_v2 = base_metric_v2.get('cvssV2', {})
                                cvss = float(cvss_v2.get('baseScore', 3.0))
                            except:
                                pass
                        
                        filtered_cves.append({
                            'cve_id': cve_id,
                            'description': description,
                            'cvss': cvss,
                            'link': f'https://nvd.nist.gov/vuln/detail/{cve_id}'
                        })
                        break  # Нашли совпадение, переходим к следующему CVE
            
            # Создаем уязвимости
            for cve_data in filtered_cves:
                cve_id = cve_data['cve_id']
                description = cve_data['description']
                cvss = cve_data['cvss']
                link = cve_data['link']
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"NVD: {cve_id}",
                    description=description or f"NVD vulnerability {cve_id}",
                    cvss_score=cvss,
                    source='NVD',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ NVD Keywords: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга NVD Keywords: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

