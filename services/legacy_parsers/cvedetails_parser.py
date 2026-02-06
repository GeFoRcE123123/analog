"""
Парсер для обновления словаря ключевых слов из CVE Details
Адаптирован из pars/CVE Details (keywords).txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser

logger = logging.getLogger(__name__)


class CVEDetailsParser(BaseLegacyParser):
    """
    Парсер для обновления словаря ключевых слов из CVE Details
    Этот парсер не создает уязвимости, а обновляет словарь
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("CVEDetails", vulnerability_repo)
        self.base_url = 'https://www.cvedetails.com/top-50-product-cvssscore-distribution.php'
    
    def parse(self, **kwargs) -> Dict[str, Any]:
        """
        Парсинг и обновление словаря ключевых слов
        
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info("🔍 Начинаем парсинг CVE Details для обновления словаря")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            try:
                response = requests.get(self.base_url, timeout=30)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                self.logger.warning(f"⚠️ Не удалось получить данные: {e}")
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': [f'Не удалось получить данные: {e}']
                }
            
            names = []
            prices = []
            
            # Парсим таблицу продуктов
            try:
                table = soup.find('table', {'class': 'grid'})
                if table:
                    tbody = table.find('tbody')
                    if tbody:
                        rows = tbody.findChildren('tr')
                        i = 2  # Начинаем с третьей строки (пропускаем заголовки)
                        while i < len(rows):
                            try:
                                cells = rows[i].findChildren('td')
                                if len(cells) >= 15:
                                    name_elem = cells[1].findChildren('a')[0]
                                    price_elem = cells[14]
                                    
                                    name = name_elem.text.strip()
                                    price = float(price_elem.text) * 10  # Умножаем на 10 как в оригинале
                                    
                                    names.append(name)
                                    prices.append(price)
                                    i += 1
                                else:
                                    break
                            except:
                                i += 1
                                continue
            except Exception as e:
                self.logger.warning(f"⚠️ Ошибка парсинга таблицы: {e}")
            
            # Обновляем словарь в БД
            updated_count = 0
            inserted_count = 0
            
            try:
                with self.vulnerability_repo.connection.cursor() as cursor:
                    for name, price in zip(names, prices):
                        # Проверяем существование
                        cursor.execute("SELECT word FROM dictionary WHERE word = %s", (name,))
                        record = cursor.fetchone()
                        
                        if record is None:
                            # Вставляем новую запись
                            cursor.execute(
                                "INSERT INTO dictionary (word, price) VALUES (%s, %s)",
                                (name, price)
                            )
                            inserted_count += 1
                        else:
                            # Обновляем существующую
                            cursor.execute(
                                "UPDATE dictionary SET price = %s WHERE word = %s",
                                (price, name)
                            )
                            updated_count += 1
                    
                    self.vulnerability_repo.connection.commit()
            except Exception as e:
                self.logger.warning(f"⚠️ Ошибка обновления словаря: {e}")
                # Если таблицы dictionary нет, это не критично
                if 'relation "dictionary" does not exist' not in str(e):
                    self.errors.append(f'Ошибка обновления словаря: {e}')
            
            self.parsed_count = len(names)
            self.saved_count = inserted_count + updated_count
            
            self.logger.info(f"✅ CVE Details: обработано {self.parsed_count} записей, вставлено {inserted_count}, обновлено {updated_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга CVE Details: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

