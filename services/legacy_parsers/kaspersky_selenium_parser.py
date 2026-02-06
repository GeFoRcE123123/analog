"""
Парсер уязвимостей Kaspersky с использованием Selenium
Парсит advisories с страницы: https://support.kaspersky.ru/vulnerability/list-of-advisories/12430#120825
"""
import logging
import re
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import TimeoutException, NoSuchElementException, StaleElementReferenceException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    logging.warning("Selenium не установлен. Установите: pip install selenium")

try:
    import undetected_chromedriver as uc
    UNDETECTED_AVAILABLE = True
except ImportError:
    UNDETECTED_AVAILABLE = False
    logging.warning("undetected-chromedriver не установлен. Рекомендуется: pip install undetected-chromedriver")

from services.legacy_parsers.base_legacy_parser import BaseLegacyParser

logger = logging.getLogger(__name__)


class KasperskySeleniumParser(BaseLegacyParser):
    """
    Парсер уязвимостей Kaspersky с использованием Selenium
    """
    
    BASE_URL = "https://support.kaspersky.ru/vulnerability/list-of-advisories/12430#120825"
    
    def __init__(self, vulnerability_repo, headless: bool = False, use_undetected: bool = True):
        """
        Инициализация парсера
        
        Args:
            vulnerability_repo: Репозиторий для сохранения уязвимостей
            headless: Запускать браузер в headless режиме
            use_undetected: Использовать undetected-chromedriver
        """
        super().__init__("Kaspersky Selenium", vulnerability_repo)
        self.headless = headless
        self.use_undetected = use_undetected and UNDETECTED_AVAILABLE
        self.driver = None
        
    def _init_driver(self) -> webdriver.Chrome:
        """Инициализация веб-драйвера"""
        if not SELENIUM_AVAILABLE:
            raise ImportError("Selenium не установлен. Установите: pip install selenium")
        
        if self.use_undetected:
            logger.info("Использование undetected-chromedriver")
            options = uc.ChromeOptions()
            if self.headless:
                options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option('useAutomationExtension', False)
            options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            driver = uc.Chrome(options=options, version_main=None)
        else:
            logger.info("Использование стандартного Chrome WebDriver")
            options = Options()
            if self.headless:
                options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option('useAutomationExtension', False)
            options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            driver = webdriver.Chrome(options=options)
        
        driver.implicitly_wait(5)
        return driver
    
    def _close_driver(self):
        """Закрытие веб-драйвера"""
        if self.driver:
            try:
                self.driver.quit()
            except Exception as e:
                logger.error(f"Ошибка при закрытии драйвера: {e}")
            finally:
                self.driver = None
    
    def _parse_advisory_date(self, text: str) -> Optional[datetime]:
        """Парсинг даты из текста advisory"""
        # Паттерны для дат типа "Advisory issued on November 24, 2025"
        patterns = [
            r'Advisory issued on (\w+) (\d+), (\d{4})',
            r'(\d{1,2})[./](\d{1,2})[./](\d{4})',
            r'(\d{4})-(\d{1,2})-(\d{1,2})',
        ]
        
        months = {
            'january': 1, 'february': 2, 'march': 3, 'april': 4,
            'may': 5, 'june': 6, 'july': 7, 'august': 8,
            'september': 9, 'october': 10, 'november': 11, 'december': 12,
            'январь': 1, 'февраль': 2, 'март': 3, 'апрель': 4,
            'май': 5, 'июнь': 6, 'июль': 7, 'август': 8,
            'сентябрь': 9, 'октябрь': 10, 'ноябрь': 11, 'декабрь': 12
        }
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    if 'issued on' in text.lower():
                        # Формат "November 24, 2025"
                        month_name = match.group(1).lower()
                        day = int(match.group(2))
                        year = int(match.group(3))
                        month = months.get(month_name)
                        if month:
                            return datetime(year, month, day)
                    else:
                        # Формат "YYYY-MM-DD" или "DD/MM/YYYY"
                        parts = match.groups()
                        if len(parts) == 3:
                            if len(parts[0]) == 4:  # YYYY-MM-DD
                                return datetime(int(parts[0]), int(parts[1]), int(parts[2]))
                            else:  # DD/MM/YYYY
                                return datetime(int(parts[2]), int(parts[1]), int(parts[0]))
                except (ValueError, IndexError) as e:
                    logger.warning(f"Ошибка парсинга даты '{text}': {e}")
                    continue
        
        return None
    
    def _parse_advisory_details(self, element) -> Dict[str, Any]:
        """Парсинг деталей одной advisory"""
        try:
            details = {
                'date': None,
                'description': '',
                'affected_applications': [],
                'recommendations': '',
                'cve_id': None
            }
            
            # Получаем весь текст элемента
            text = element.text
            
            # Парсинг даты
            date_match = re.search(r'Advisory issued on (.+?)(?:\n|$)', text, re.IGNORECASE)
            if date_match:
                date_text = date_match.group(1)
                details['date'] = self._parse_advisory_date(date_text)
            
            # Парсинг описания (Issue/Description секция)
            desc_patterns = [
                r'Issue[:\s]+(.+?)(?=Cause|Impact|Scope|Affected)',
                r'Description[:\s]+(.+?)(?=Cause|Impact|Scope|Affected)',
            ]
            for pattern in desc_patterns:
                match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                if match:
                    details['description'] = match.group(1).strip()
                    break
            
            # Парсинг CVE ID (если есть)
            cve_match = re.search(r'(CVE-\d{4}-\d{4,})', text, re.IGNORECASE)
            if cve_match:
                details['cve_id'] = cve_match.group(1).upper()
            
            # Парсинг таблицы Affected Applications
            try:
                # Ищем таблицу с заголовками Application, Version, Recommendations
                table = element.find_element(By.TAG_NAME, "table")
                rows = table.find_elements(By.TAG_NAME, "tr")
                
                if len(rows) > 1:  # Есть заголовок
                    for row in rows[1:]:  # Пропускаем заголовок
                        cells = row.find_elements(By.TAG_NAME, "td")
                        if len(cells) >= 2:
                            app_info = {
                                'application': cells[0].text.strip() if len(cells) > 0 else '',
                                'version': cells[1].text.strip() if len(cells) > 1 else '',
                                'recommendations': cells[2].text.strip() if len(cells) > 2 else ''
                            }
                            details['affected_applications'].append(app_info)
            except NoSuchElementException:
                # Таблица не найдена, пытаемся парсить текстовый формат
                app_pattern = r'Application[:\s]+(.+?)(?:\n|Version)'
                version_pattern = r'Version[:\s]+(.+?)(?:\n|Recommendations)'
                recommendations_pattern = r'Recommendations[:\s]+(.+?)(?:\n|$)'
                
                app_match = re.search(app_pattern, text, re.IGNORECASE)
                version_match = re.search(version_pattern, text, re.IGNORECASE)
                rec_match = re.search(recommendations_pattern, text, re.IGNORECASE)
                
                if app_match or version_match:
                    details['affected_applications'].append({
                        'application': app_match.group(1).strip() if app_match else '',
                        'version': version_match.group(1).strip() if version_match else '',
                        'recommendations': rec_match.group(1).strip() if rec_match else ''
                    })
            
            # Парсинг Recommendations (общих рекомендаций, не из таблицы)
            rec_patterns = [
                r'Recommendations[:\s]+(.+?)(?=Acknowledgments|$)',
                r'When installing[^:]+:\s*(.+?)(?=Acknowledgments|$)',
            ]
            for pattern in rec_patterns:
                match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                if match:
                    details['recommendations'] = match.group(1).strip()
                    break
            
            return details
            
        except Exception as e:
            logger.error(f"Ошибка парсинга advisory: {e}", exc_info=True)
            return {}
    
    def _click_advisory(self, element, wait_timeout: int = 10) -> bool:
        """Клик на advisory для раскрытия деталей"""
        try:
            # Прокручиваем к элементу
            self.driver.execute_script("arguments[0].scrollIntoView(true);", element)
            time.sleep(0.5)
            
            # Пытаемся кликнуть на элемент
            element.click()
            time.sleep(1)  # Ждем загрузки контента
            
            return True
        except Exception as e:
            logger.warning(f"Ошибка при клике на advisory: {e}")
            # Пробуем через JavaScript
            try:
                self.driver.execute_script("arguments[0].click();", element)
                time.sleep(1)
                return True
            except Exception as e2:
                logger.error(f"Ошибка при клике через JavaScript: {e2}")
                return False
    
    def parse(self, limit: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        """
        Основной метод парсинга
        
        Args:
            limit: Максимальное количество advisory для парсинга (None = все)
            **kwargs: Дополнительные параметры
            
        Returns:
            Dict с ключами: parsed, saved, errors
        """
        if not SELENIUM_AVAILABLE:
            return {
                'parsed': 0,
                'saved': 0,
                'errors': ['Selenium не установлен. Установите: pip install selenium']
            }
        
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            # Инициализация драйвера
            logger.info("Инициализация веб-драйвера...")
            self.driver = self._init_driver()
            
            # Открытие страницы
            logger.info(f"Открытие страницы: {self.BASE_URL}")
            self.driver.get(self.BASE_URL)
            
            # Ожидание загрузки страницы
            wait = WebDriverWait(self.driver, 15)
            logger.info("Ожидание загрузки контента...")
            time.sleep(3)  # Дополнительная задержка для загрузки JS
            
            # Поиск списка advisories
            # Пробуем различные селекторы
            advisory_selectors = [
                "//ul[contains(@class, 'advisory') or contains(@class, 'list')]//li",
                "//div[contains(@class, 'advisory')]//a[contains(text(), 'Advisory issued')]",
                "//a[contains(text(), 'Advisory issued')]",
                "//div[contains(@class, 'accordion')]//div[contains(@class, 'item')]",
                "//div[@class='advisory-item']",
            ]
            
            advisories = []
            for selector in advisory_selectors:
                try:
                    if selector.startswith("//"):
                        advisories = self.driver.find_elements(By.XPATH, selector)
                    else:
                        advisories = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    
                    if advisories:
                        logger.info(f"Найдено {len(advisories)} advisories с селектором: {selector}")
                        break
                except Exception as e:
                    logger.debug(f"Селектор {selector} не сработал: {e}")
                    continue
            
            if not advisories:
                # Пробуем найти любые кликабельные элементы с текстом "Advisory"
                logger.warning("Не найдено advisories стандартными селекторами, пробуем альтернативные методы...")
                try:
                    all_elements = self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Advisory issued')]")
                    advisories = [elem.find_element(By.XPATH, "./..") for elem in all_elements if elem.is_displayed()]
                except Exception as e:
                    logger.error(f"Не удалось найти advisories: {e}")
                    return {
                        'parsed': 0,
                        'saved': 0,
                        'errors': [f'Не найдено advisories на странице: {e}']
                    }
            
            if not advisories:
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': ['Не найдено advisories на странице']
                }
            
            # Ограничение количества
            if limit:
                advisories = advisories[:limit]
            
            logger.info(f"Начало парсинга {len(advisories)} advisories...")
            
            # Парсинг каждой advisory
            for idx, advisory_element in enumerate(advisories, 1):
                try:
                    logger.info(f"Парсинг advisory {idx}/{len(advisories)}...")
                    
                    # Клик на advisory для раскрытия
                    if not self._click_advisory(advisory_element):
                        logger.warning(f"Не удалось кликнуть на advisory {idx}")
                        continue
                    
                    # Парсинг деталей
                    details = self._parse_advisory_details(advisory_element)
                    
                    if not details or not details.get('description'):
                        logger.warning(f"Не удалось извлечь детали из advisory {idx}")
                        continue
                    
                    # Создание объекта Vulnerability
                    cve_id = details.get('cve_id') or f"KASPERSKY-{details.get('date', datetime.now()).strftime('%Y%m%d')}-{idx}"
                    
                    # Формирование описания
                    description_parts = [details.get('description', '')]
                    
                    if details.get('affected_applications'):
                        description_parts.append("\n\nAffected Applications:")
                        for app in details['affected_applications']:
                            app_text = f"{app.get('application', '')} {app.get('version', '')}"
                            if app.get('recommendations'):
                                app_text += f" - {app['recommendations']}"
                            description_parts.append(f"- {app_text}")
                    
                    if details.get('recommendations'):
                        description_parts.append(f"\nRecommendations: {details['recommendations']}")
                    
                    description = "\n".join(description_parts)
                    
                    # Формирование заголовка
                    title = f"Kaspersky Security Advisory"
                    if details.get('cve_id'):
                        title = f"{details['cve_id']} - {title}"
                    if details.get('date'):
                        title += f" ({details['date'].strftime('%Y-%m-%d')})"
                    
                    # Ссылка на advisory
                    link = self.BASE_URL
                    try:
                        # Пытаемся найти ссылку
                        link_elem = advisory_element.find_element(By.XPATH, ".//a[@href]")
                        href = link_elem.get_attribute('href')
                        if href:
                            link = urljoin(self.BASE_URL, href)
                    except NoSuchElementException:
                        pass
                    
                    # Создание Vulnerability объекта
                    vulnerability = self._create_vulnerability(
                        cve_id=cve_id,
                        title=title,
                        description=description,
                        cvss_score=0.0,  # CVSS не всегда доступен
                        source='Kaspersky',
                        link=link,
                        etc_data={
                            'advisory_date': details.get('date').isoformat() if details.get('date') else None,
                            'affected_applications': details.get('affected_applications', []),
                            'raw_text': advisory_element.text[:500] if advisory_element else None
                        }
                    )
                    
                    # Сохранение в БД
                    if self.vulnerability_repo.save_vulnerability(vulnerability):
                        self.saved_count += 1
                        logger.info(f"✅ Сохранено: {cve_id}")
                    else:
                        logger.warning(f"⚠️ Не удалось сохранить: {cve_id}")
                    
                    self.parsed_count += 1
                    
                    # Небольшая задержка между запросами
                    time.sleep(1)
                    
                except Exception as e:
                    error_msg = f"Ошибка парсинга advisory {idx}: {e}"
                    logger.error(error_msg, exc_info=True)
                    self.errors.append(error_msg)
                    continue
            
            logger.info(f"✅ Парсинг завершен: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
        except Exception as e:
            error_msg = f"Критическая ошибка парсинга: {e}"
            logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
        
        finally:
            # Закрытие драйвера
            self._close_driver()
        
        return {
            'parsed': self.parsed_count,
            'saved': self.saved_count,
            'errors': self.errors
        }

