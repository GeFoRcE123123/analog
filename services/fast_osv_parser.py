import json
import logging
import time
import random
import re
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from models.entities import Vulnerability
from services.data_manager import DataManager
from services.vulnerability_analyzer import vulnerability_analyzer

logger = logging.getLogger(__name__)


class FastOSVParser:
    """Оптимизированный парсер OSV с фокусом на AI/нейросети"""

    def __init__(self, max_workers: int = 10, max_pages: int = 10):
        self.base_url = "https://osv.dev/list"
        self.max_workers = max_workers
        self.max_pages = max_pages
        self.session = self._create_session_with_retry()
        self.driver = None
        self.keywords = self._load_ai_keywords()

    def _create_session_with_retry(self):
        """Создает session с retry логикой и задержками"""
        session = requests.Session()

        # Retry стратегия
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            backoff_factor=1.5
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _request_with_delay(self, url, **kwargs):
        """Добавляет случайные задержки между запросами"""
        delay = random.uniform(1.0, 3.0)
        time.sleep(delay)

        if 'timeout' not in kwargs:
            kwargs['timeout'] = (10, 30)

        return self.session.get(url, **kwargs)

    def _load_ai_keywords(self) -> Dict[str, int]:
        """Расширенный список ключевых слов для AI/нейросетей"""
        return {
            # Core AI/ML Terms
            "AI": 95, "Artificial Intelligence": 96, "Machine Learning": 97, "Deep Learning": 96,
            "Neural Network": 98, "Neural": 95, "LLM": 99, "Large Language Model": 99,
            "Transformer": 97, "Generative AI": 98, "Foundation Model": 95, "AI Model": 96,

            # AI Platforms & Frameworks
            "TensorFlow": 98, "PyTorch": 98, "Keras": 95, "Hugging Face": 99, "HuggingFace": 99,
            "OpenAI": 99, "GPT": 99, "ChatGPT": 99, "DALL-E": 95, "Stable Diffusion": 97,
            "Midjourney": 90, "Anthropic": 95, "Claude": 95, "Bard": 90, "Gemini": 90,
            "LangChain": 98, "LlamaIndex": 97, "AutoGPT": 96, "Auto-GPT": 96,

            # AI Security Specific
            "Prompt Injection": 99, "Jailbreak": 98, "Adversarial": 97, "Model Extraction": 96,
            "Data Poisoning": 95, "Membership Inference": 94, "Model Inversion": 93,
            "Backdoor Attack": 92, "Training Data": 91, "Fine-tuning": 90,

            # AI Components & Techniques
            "Embedding": 85, "Attention": 86, "Layer": 84, "Parameter": 83, "Weight": 83,
            "Gradient": 82, "Backpropagation": 81, "Optimizer": 80, "Loss Function": 79,

            # AI Applications
            "Computer Vision": 88, "NLP": 87, "Natural Language": 87, "Speech Recognition": 85,
            "Recommendation": 84, "Autonomous": 86, "Self-driving": 85, "Robotics": 83,

            # AI Infrastructure
            "GPU": 82, "CUDA": 81, "TPU": 83, "Model Serving": 85, "Inference": 86,
            "Training": 87, "Dataset": 84, "Benchmark": 79,

            # General Security (для контекста)
            "Security": 85, "Vulnerability": 90, "Exploit": 88, "Attack": 87,
            "Remote Code Execution": 92, "RCE": 92, "SQL Injection": 90, "XSS": 89,
            "Buffer Overflow": 86, "Privilege Escalation": 85
        }

    def _get_all_vulnerability_links(self) -> List[str]:
        """Получение ВСЕХ ссылок на уязвимости с пагинацией"""
        links = set()

        try:
            # Используем Selenium для получения динамического контента
            driver = self._get_selenium_driver()
            driver.get(self.base_url)

            # Ждем загрузки
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "a[href*='/vulnerability/']"))
            )

            page_count = 0
            max_pages = self.max_pages

            while page_count < max_pages:
                logger.info(f"🔍 Парсинг страницы {page_count + 1}")

                # Получаем ссылки с текущей страницы
                page_links = self._extract_links_from_page(driver.page_source)
                new_links = page_links - links

                if not new_links:
                    logger.info("📭 Новых ссылок не найдено, завершаем парсинг")
                    break

                links.update(new_links)
                logger.info(f"📥 Добавлено {len(new_links)} новых ссылок, всего: {len(links)}")

                # Пытаемся перейти на следующую страницу
                if not self._go_to_next_page(driver):
                    logger.info("⏹️ Следующая страница не найдена, завершаем парсинг")
                    break

                page_count += 1
                time.sleep(1)  # Небольшая задержка между страницами

            driver.quit()
            logger.info(f"🎯 Всего собрано {len(links)} уникальных ссылок")
            return list(links)

        except Exception as e:
            logger.error(f"Ошибка при получении ссылок: {e}")
            try:
                if driver:
                    driver.quit()
            except:
                pass
            return list(links)

    def _get_selenium_driver(self):
        """Создание Selenium драйвера"""
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)

        service = Service()
        driver = webdriver.Chrome(service=service, options=options)
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

        return driver

    def _extract_links_from_page(self, page_source: str) -> set:
        """Извлечение ссылок из HTML страницы"""
        soup = BeautifulSoup(page_source, 'html.parser')
        links = set()

        vulnerability_links = soup.find_all('a', href=lambda href: href and '/vulnerability/' in href)

        for link in vulnerability_links:
            href = link.get('href')
            if href:
                full_url = urljoin(self.base_url, href)
                if full_url != self.base_url:
                    links.add(full_url)

        return links

    def _go_to_next_page(self, driver) -> bool:
        """Переход на следующую страницу"""
        try:
            # Ищем кнопку "Next" или "Load more"
            next_buttons = [
                "//button[contains(., 'Next')]",
                "//button[contains(., 'Load more')]",
                "//a[contains(., 'Next')]",
                "//button[contains(@class, 'next')]",
                "//a[contains(@class, 'next')]"
            ]

            for xpath in next_buttons:
                try:
                    button = WebDriverWait(driver, 3).until(
                        EC.element_to_be_clickable((By.XPATH, xpath))
                    )
                    driver.execute_script("arguments[0].click();", button)
                    time.sleep(2)  # Ждем загрузки
                    return True
                except:
                    continue

            return False

        except Exception as e:
            logger.warning(f"Не удалось найти следующую страницу: {e}")
            return False

    def _parse_all_vulnerabilities(self, links: List[str]) -> List[Dict[str, Any]]:
        """Параллельный парсинг ВСЕХ уязвимостей"""
        vulnerabilities = []

        # Используем все доступные воркеры
        max_concurrent = min(self.max_workers, len(links))

        logger.info(f"⚡ Параллельная обработка {len(links)} уязвимостей с {max_concurrent} потоками")

        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Запускаем ВСЕ задачи параллельно
            future_to_link = {
                executor.submit(self._parse_single_vulnerability_fast, link): link
                for link in links
            }

            completed = 0
            for future in as_completed(future_to_link):
                link = future_to_link[future]
                try:
                    result = future.result(timeout=20)
                    if result and not result.get('error'):
                        vulnerabilities.append(result)
                        completed += 1
                        if completed % 10 == 0:
                            logger.info(f"📄 Обработано {completed}/{len(links)} уязвимостей")
                    else:
                        logger.warning(f"⚠️ Пропущена уязвимость: {link}")
                except Exception as e:
                    logger.error(f"❌ Ошибка при обработке {link}: {e}")

        return vulnerabilities

    def _parse_single_vulnerability_fast(self, url: str) -> Dict[str, Any]:
        """Быстрый парсинг одной уязвимости"""
        try:
            # Используем requests для скорости
            response = self._request_with_delay(url)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')

            # Извлекаем данные
            details = {
                'url': url,
                'id': self._extract_id_fast(soup, url),
                'description': self._extract_description_fast(soup),
                'cves': self._extract_cves_fast(soup),
                'packages': self._extract_packages_fast(soup),
                'date': self._extract_date_fast(soup),
                'full_text': soup.get_text()
            }

            return details

        except Exception as e:
            logger.error(f"Ошибка при парсинге {url}: {e}")
            return {'url': url, 'error': str(e)}

    def _extract_id_fast(self, soup: BeautifulSoup, url: str) -> str:
        """Извлечение ID уязвимости"""
        # Из URL
        url_parts = url.split('/')
        if len(url_parts) > 1:
            return url_parts[-1]

        # Из заголовка
        title = soup.find('h1')
        if title:
            return title.get_text(strip=True)[:100]

        return "Unknown"

    def _extract_description_fast(self, soup: BeautifulSoup) -> str:
        """Извлечение описания"""
        # Ищем в мета-тегах
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            return meta_desc.get('content')[:500]

        # Ищем в контенте
        content_selectors = [
            "div[data-testid='summary']",
            ".description",
            ".vulnerability-description",
            "main p",
            ".content p",
            ".summary",
            "[class*='description']"
        ]

        for selector in content_selectors:
            element = soup.select_one(selector)
            if element:
                text = element.get_text(strip=True)
                if text and len(text) > 10:
                    return text[:500]

        return "Описание не найдено"

    def _extract_cves_fast(self, soup: BeautifulSoup) -> List[str]:
        """Извлечение CVE"""
        text = soup.get_text()
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, text)
        return list(set(cves))

    def _extract_packages_fast(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Извлечение пакетов"""
        packages = []

        # Ищем в таблицах
        tables = soup.find_all('table')
        for table in tables:
            rows = table.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) >= 2:
                    pkg_name = cells[0].get_text(strip=True)
                    pkg_version = cells[1].get_text(strip=True)
                    if pkg_name and pkg_name.lower() not in ['package', 'name']:
                        packages.append({'name': pkg_name, 'version': pkg_version})

        return packages

    def _extract_date_fast(self, soup: BeautifulSoup) -> str:
        """Извлечение даты"""
        time_element = soup.find('time')
        if time_element and time_element.get('datetime'):
            return time_element.get('datetime')

        # Ищем в тексте
        text = soup.get_text()
        date_patterns = [
            r'Published:\s*(\d{4}-\d{2}-\d{2})',
            r'Date:\s*(\d{4}-\d{2}-\d{2})',
            r'(\d{4}-\d{2}-\d{2})'
        ]

        for pattern in date_patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)

        return datetime.now().strftime("%Y-%m-%d")

    def _filter_by_ai_keywords(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Фильтрация по AI/нейросетевым ключевым словам"""
        filtered = []

        for vuln in vulnerabilities:
            if vuln.get('error'):
                continue

            # Используем полный текст для лучшего поиска
            search_text = vuln.get('full_text', '').lower()
            search_text += " " + vuln.get('description', '').lower()
            search_text += " " + vuln.get('id', '').lower()
            search_text += " " + " ".join([pkg.get('name', '').lower() for pkg in vuln.get('packages', [])])
            search_text += " " + " ".join(vuln.get('cves', []))

            # Проверяем AI ключевые слова
            found_keywords = []
            for keyword, score in self.keywords.items():
                # Ищем точные совпадения слов
                if re.search(r'\b' + re.escape(keyword.lower()) + r'\b', search_text):
                    found_keywords.append({'keyword': keyword, 'score': score})

            if found_keywords:
                vuln['matched_keywords'] = found_keywords
                vuln['total_score'] = sum(kw['score'] for kw in found_keywords)
                vuln['keyword_matches'] = len(found_keywords)
                filtered.append(vuln)

                logger.info(
                    f"🎯 Найдена AI уязвимость: {vuln.get('id')} - {[kw['keyword'] for kw in found_keywords[:3]]}")

        # Сортируем по score и количеству совпадений
        filtered.sort(key=lambda x: (x.get('total_score', 0), x.get('keyword_matches', 0)), reverse=True)

        logger.info(f"🔍 Найдено {len(filtered)} AI-уязвимостей из {len(vulnerabilities)}")
        return filtered

    def parse_vulnerabilities_fast_with_status(self, progress_manager):
        """Парсинг уязвимостей с обновлением прогресса"""
        try:
            logger.info("🚀 Запуск парсера с отслеживанием статуса")

            # Получаем ссылки
            vulnerability_links = self._get_all_vulnerability_links()
            logger.info(f"📥 Найдено {len(vulnerability_links)} ссылок на уязвимости")

            if not vulnerability_links:
                return []

            # Параллельный парсинг
            vulnerabilities = self._parse_all_vulnerabilities(vulnerability_links)

            # Фильтрация по AI ключевым словам
            filtered_vulnerabilities = self._filter_by_ai_keywords(vulnerabilities)

            logger.info(f"📊 Результат: {len(vulnerabilities)} всего, {len(filtered_vulnerabilities)} AI-уязвимостей")

            return filtered_vulnerabilities

        except Exception as e:
            logger.error(f"❌ Ошибка при парсинге: {e}")
            return []


class FastVulnerabilityManager:
    """Быстрый менеджер для сохранения уязвимостей"""

    def __init__(self):
        self.data_manager = DataManager()
        self.logger = logging.getLogger(__name__)

    def save_vulnerabilities_fast(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Быстрое сохранение уязвимостей в БД"""
        saved_count = 0
        skipped_count = 0

        self.logger.info(f"💾 Сохранение {len(vulnerabilities)} AI уязвимостей в БД...")

        for vulnerability in vulnerabilities:
            try:
                # Проверяем дубликаты по заголовку
                existing = self.data_manager.get_vulnerability_by_title(vulnerability.title)
                if existing:
                    skipped_count += 1
                    continue

                # Сохраняем в БД
                if self.data_manager.add_vulnerability(vulnerability):
                    saved_count += 1
                    self.logger.info(f"✅ Сохранена AI уязвимость: {vulnerability.title}")
                else:
                    skipped_count += 1

            except Exception as e:
                self.logger.error(f"Ошибка сохранения уязвимости: {e}")
                skipped_count += 1

        self.logger.info(f"🎯 Итог: Сохранено {saved_count}, Пропущено {skipped_count}")
        return {'saved': saved_count, 'skipped': skipped_count}


def fast_parse_ai_vulnerabilities_with_status(progress_manager, on_vulnerability_parsed=None) -> Dict[str, any]:
    """Быстрая функция парсинга AI уязвимостей с поддержкой callback в реальном времени"""
    try:
        logger.info("🚀 Запуск AI-парсера OSV с реальным временем")

        # Инициализация парсера
        parser = FastOSVParser(max_workers=8, max_pages=5)
        manager = FastVulnerabilityManager()

        # Шаг 1: Инициализация
        progress_manager.update_progress(10, "Инициализация AI-парсера...", "initialization")
        time.sleep(0.5)

        # Шаг 2: Сбор ссылок
        progress_manager.update_progress(25, "Сбор ссылок на уязвимости...", "collecting_links")
        vulnerability_links = parser._get_all_vulnerability_links()

        if not vulnerability_links:
            return {'success': False, 'message': 'Не найдено ссылок на уязвимости', 'count': 0}

        progress_manager.update_progress(35, f"Найдено {len(vulnerability_links)} ссылок", "links_found")

        # Шаг 3: Парсинг уязвимостей
        progress_manager.update_progress(45, "Парсинг деталей уязвимостей...", "parsing_details")
        vuln_data = parser._parse_all_vulnerabilities(vulnerability_links)

        if not vuln_data:
            return {'success': False, 'message': 'Не удалось распарсить уязвимости', 'count': 0}

        progress_manager.update_progress(65, f"Обработано {len(vuln_data)} уязвимостей", "parsed")

        # Шаг 4: Фильтрация AI уязвимостей
        progress_manager.update_progress(75, "Фильтрация AI уязвимостей...", "filtering_ai")
        filtered_vulnerabilities = parser._filter_by_ai_keywords(vuln_data)

        if not filtered_vulnerabilities:
            return {'success': False, 'message': 'Не найдено AI уязвимостей', 'count': 0}

        progress_manager.update_progress(80, f"Найдено {len(filtered_vulnerabilities)} AI уязвимостей", "ai_found")

        # Шаг 5: Конвертация в объекты с callback
        progress_manager.update_progress(85, "Создание объектов уязвимостей...", "creating_objects")

        vulnerabilities = []
        for data in filtered_vulnerabilities:
            try:
                title = data.get('id', 'Unknown Vulnerability')
                analysis = vulnerability_analyzer.analyze_vulnerability(data)

                vulnerability = Vulnerability(
                    id=0,
                    title=title[:200],
                    description=analysis['description'],
                    severity=analysis['severity'],
                    cvss_score=analysis['cvss_score'],
                    risk_level=analysis['risk_level'],
                    category=analysis['category'],
                    created_date=datetime.now(),
                    status='new'
                )

                vulnerabilities.append(vulnerability)

                # Вызываем callback если передан - В РЕАЛЬНОМ ВРЕМЕНИ!
                if on_vulnerability_parsed:
                    vuln_info = {
                        'title': title,
                        'severity': analysis['severity'],
                        'cvss_score': analysis['cvss_score'],
                        'description': analysis['description'],
                        'category': analysis['category'],
                        'timestamp': datetime.now().isoformat(),
                        'status': 'new'
                    }
                    on_vulnerability_parsed(vuln_info)

                logger.info(f"🎯 Analyzed: {title} -> {analysis['severity']} (CVSS: {analysis['cvss_score']})")

            except Exception as e:
                logger.error(f"Ошибка конвертации уязвимости: {e}")
                continue

        # Шаг 6: Сохранение в БД
        progress_manager.update_progress(90, "Сохранение в базу данных...", "saving")
        result = manager.save_vulnerabilities_fast(vulnerabilities)

        # Финальная статистика
        progress_manager.update_vulnerability_stats(
            found=len(vuln_data),
            saved=result['saved']
        )

        progress_manager.update_progress(95, "Финальная обработка...", "finalizing")

        return {
            'success': True,
            'message': f'Успешно сохранено {result["saved"]} AI уязвимостей',
            'count': result['saved'],
            'details': result
        }

    except Exception as e:
        logger.error(f"❌ Ошибка AI парсинга: {e}")
        return {'success': False, 'message': str(e), 'count': 0}


def fast_parse_ai_vulnerabilities() -> Dict[str, any]:
    """Быстрая функция парсинга AI уязвимостей"""
    try:
        logger.info("🚀 Запуск AI-парсера OSV")

        # Инициализация парсера с фокусом на AI
        parser = FastOSVParser(max_workers=15, max_pages=20)
        manager = FastVulnerabilityManager()

        # Парсинг AI уязвимостей
        vuln_data = parser.parse_vulnerabilities_fast_with_status(None)

        if not vuln_data:
            return {'success': False, 'message': 'Не найдено AI уязвимостей', 'count': 0}

        # Конвертация в объекты
        vulnerabilities = []
        for data in vuln_data:
            try:
                title = data.get('id', 'Unknown Vulnerability')
                analysis = vulnerability_analyzer.analyze_vulnerability(data)

                vulnerability = Vulnerability(
                    id=0,
                    title=title[:200],
                    description=analysis['description'],
                    severity=analysis['severity'],
                    cvss_score=analysis['cvss_score'],
                    risk_level=analysis['risk_level'],
                    category=analysis['category'],
                    created_date=datetime.now(),
                    status='new'
                )
                vulnerabilities.append(vulnerability)
            except Exception as e:
                logger.error(f"Ошибка конвертации уязвимости: {e}")
                continue

        # Сохранение в БД
        result = manager.save_vulnerabilities_fast(vulnerabilities)

        return {
            'success': True,
            'message': f'Успешно сохранено {result["saved"]} AI уязвимостей',
            'count': result['saved'],
            'details': result
        }

    except Exception as e:
        logger.error(f"❌ Ошибка AI парсинга: {e}")
        return {'success': False, 'message': str(e), 'count': 0}