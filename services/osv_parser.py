import json
import logging
import time
from urllib.parse import urljoin
import re
import os
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException
from bs4 import BeautifulSoup


import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.entities import Vulnerability
from services.data_manager import DataManager


# --- Настройка логирования ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Конфигурация Selenium ---
CHROMEDRIVER_PATH = None
BASE_URL = "https://osv.dev/list"

# --- Конфигурация папок ---
BASE_DATA_DIR = "vulnerability_data"
HTML_DIR = os.path.join(BASE_DATA_DIR, "html_pages")
JSON_DIR = os.path.join(BASE_DATA_DIR, "json_data")
SCREENSHOTS_DIR = os.path.join(BASE_DATA_DIR, "screenshots")
DEBUG_DIR = os.path.join(BASE_DATA_DIR, "debug")


class OSVParser:
    def __init__(self):
        self.base_url = BASE_URL
        self.timeout = 30
        self.max_pages = 3
        self.keywords = KEYWORDS
        self.logger = logging.getLogger(__name__)
        self.driver = None

    def _get_webdriver(self):
        """Создает и возвращает экземпляр WebDriver."""
        options = Options()
        # options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)

        service = Service()
        driver = webdriver.Chrome(service=service, options=options)
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        return driver

    def parse_vulnerabilities(self) -> List[Vulnerability]:
        """Основной метод парсинга уязвимостей"""
        vulnerabilities = []

        try:
            # Инициализируем WebDriver
            self.driver = self._get_webdriver()

            self.logger.info(f"Открытие главной страницы: {self.base_url}")
            self.driver.get(self.base_url)
            time.sleep(5)

            # Получаем ссылки на уязвимости
            vulnerability_links = get_vulnerability_links_selenium(self.driver, max_pages=self.max_pages)
            self.logger.info(f"Найдено ссылок: {len(vulnerability_links)}")

            # Парсим детали и создаем объекты Vulnerability
            for i, link in enumerate(vulnerability_links):
                self.logger.info(f"Обработка уязвимости {i + 1}/{len(vulnerability_links)}: {link}")
                try:
                    vulnerability_details = get_vulnerability_details_selenium(self.driver, link)

                    # Пропускаем уязвимости с ошибками
                    if vulnerability_details.get('error'):
                        continue

                    # Преобразуем в объект Vulnerability
                    vulnerability = self._create_vulnerability_object(vulnerability_details)
                    vulnerabilities.append(vulnerability)

                except Exception as e:
                    self.logger.error(f"Ошибка при обработке {link}: {e}")
                    continue

            self.logger.info(f"Парсинг завершен! Получено {len(vulnerabilities)} уязвимостей")

        except Exception as e:
            self.logger.error(f"Критическая ошибка при парсинге: {e}")
        finally:
            # Закрываем WebDriver
            if self.driver:
                self.logger.info("Закрытие браузера...")
                self.driver.quit()

        return vulnerabilities

    def _create_vulnerability_object(self, vuln_data: Dict) -> Vulnerability:
        """Создание объекта Vulnerability из данных парсера"""
        title = vuln_data.get('id', 'Unknown Vulnerability')
        description = vuln_data.get('description', 'No description available')

        severity, cvss_score, risk_level = self._calculate_severity(title, description)
        category = self._determine_category(title, description)

        return Vulnerability(
            id=0,
            title=title[:200],
            description=description[:1000],
            severity=severity,
            cvss_score=cvss_score,
            risk_level=risk_level,
            category=category,
            created_date=datetime.now()
        )

    def _calculate_severity(self, title: str, description: str) -> tuple:
        """Определение severity на основе ключевых слов"""
        text = f"{title} {description}".lower()
        max_score = 0

        for keyword, score in self.keywords.items():
            if keyword.lower() in text:
                max_score = max(max_score, score)

        if max_score >= 80:
            return 'critical', max_score / 10.0, 'high'
        elif max_score >= 60:
            return 'high', max_score / 10.0, 'high'
        elif max_score >= 40:
            return 'medium', max_score / 10.0, 'medium'
        else:
            return 'low', max_score / 10.0, 'low'

    def _determine_category(self, title: str, description: str) -> str:
        """Определение категории уязвимости"""
        text = f"{title} {description}".lower()

        categories = {
            'web': ['web', 'xss', 'sql', 'csrf', 'http', 'api'],
            'system': ['system', 'linux', 'windows', 'kernel', 'os'],
            'network': ['network', 'tcp', 'udp', 'dns', 'ip'],
            'application': ['app', 'application', 'software', '7-zip', 'adobe']
        }

        for category, keywords in categories.items():
            if any(keyword in text for keyword in keywords):
                return category

        return 'other'

    def get_parsing_status(self) -> dict:
        """Получить статус парсинга"""
        return {
            'status': 'ready',
            'base_url': self.base_url,
            'max_pages': self.max_pages,
            'keywords_count': len(self.keywords)
        }


class VulnerabilityDBManager:
    """Менеджер для сохранения уязвимостей в БД системы."""

    def __init__(self):
        self.data_manager = DataManager()
        self.logger = logging.getLogger(__name__)

    def save_vulnerabilities_to_db(self, vulnerabilities_data: List[Dict]) -> Dict[str, int]:
        """Сохраняет спарсенные уязвимости в БД системы."""
        saved_count = 0
        skipped_count = 0
        error_count = 0

        self.logger.info(f"Начало сохранения {len(vulnerabilities_data)} уязвимостей в БД системы...")

        for vuln_data in vulnerabilities_data:
            try:
                # Пропускаем уязвимости с ошибками
                if vuln_data.get('error'):
                    skipped_count += 1
                    continue

                # Преобразуем данные парсера в объект Vulnerability
                vulnerability = self._create_vulnerability_from_parsed_data(vuln_data)

                # Сохраняем в БД через DataManager
                if self.data_manager.add_vulnerability(vulnerability):
                    saved_count += 1
                    self.logger.info(f"✓ Уязвимость сохранена в БД: {vulnerability.title}")
                else:
                    skipped_count += 1
                    self.logger.info(f"↷ Уязвимость пропущена (дубликат): {vulnerability.title}")

            except Exception as e:
                error_count += 1
                vuln_id = vuln_data.get('id', 'unknown')
                self.logger.error(f"✗ Ошибка сохранения уязвимости {vuln_id}: {e}")

        self.logger.info("=== РЕЗУЛЬТАТЫ СОХРАНЕНИЯ В БД ===")
        self.logger.info(f"Успешно сохранено: {saved_count}")
        self.logger.info(f"Пропущено (дубликаты/ошибки): {skipped_count}")
        self.logger.info(f"Ошибок обработки: {error_count}")
        self.logger.info(f"Всего обработано: {len(vulnerabilities_data)}")

        return {
            "saved": saved_count,
            "skipped": skipped_count,
            "errors": error_count,
            "total_processed": len(vulnerabilities_data)
        }

    def _create_vulnerability_from_parsed_data(self, vuln_data: Dict) -> Vulnerability:
        """Создает объект Vulnerability из данных парсера."""

        # Определяем severity на основе ключевых слов
        severity, cvss_score, risk_level = self._calculate_severity_from_data(vuln_data)

        # Определяем категорию
        category = self._determine_category_from_data(vuln_data)

        # Формируем описание
        description = self._build_description(vuln_data)

        # Создаем объект Vulnerability
        return Vulnerability(
            id=0,  # ID будет присвоен при сохранении в БД
            title=vuln_data.get('id', 'Unknown Vulnerability')[:200],
            description=description[:1000],
            severity=severity,
            cvss_score=round(cvss_score, 1),
            risk_level=risk_level,
            category=category,
            created_date=datetime.now(),
            status='new'
        )

    def _calculate_severity_from_data(self, vuln_data: Dict) -> tuple:
        """Определяет severity на основе данных уязвимости."""
        search_text = ""
        search_text += vuln_data.get('id', '') + " "
        search_text += vuln_data.get('description', '') + " "
        search_text += " ".join([pkg.get('name', '') for pkg in vuln_data.get('packages', [])]) + " "
        search_text += " ".join(vuln_data.get('cves', [])) + " "

        max_score = 0
        for keyword, score in KEYWORDS.items():
            if re.search(r'\b' + re.escape(keyword) + r'\b', search_text, re.IGNORECASE):
                max_score = max(max_score, score)

        # Если нет совпадений с ключевыми словами, используем средний балл
        if max_score == 0:
            max_score = 50

        if max_score >= 80:
            return 'critical', max_score / 10.0, 'high'
        elif max_score >= 60:
            return 'high', max_score / 10.0, 'high'
        elif max_score >= 40:
            return 'medium', max_score / 10.0, 'medium'
        else:
            return 'low', max_score / 10.0, 'low'

    def _determine_category_from_data(self, vuln_data: Dict) -> str:
        """Определяет категорию уязвимости."""
        search_text = ""
        search_text += vuln_data.get('id', '') + " "
        search_text += vuln_data.get('description', '') + " "
        search_text += " ".join([pkg.get('name', '') for pkg in vuln_data.get('packages', [])])

        categories = {
            'web': ['web', 'xss', 'sql', 'csrf', 'http', 'api', 'browser', 'injection'],
            'system': ['system', 'linux', 'windows', 'kernel', 'os', 'ubuntu', 'debian', 'operating'],
            'network': ['network', 'tcp', 'udp', 'dns', 'ip', 'router', 'switch', 'protocol'],
            'application': ['app', 'application', 'software', '7-zip', 'adobe', 'package', 'library'],
            'ai': ['ai', 'neural', 'learning', 'model', 'llm', 'transformer', 'prompt', 'machine learning']
        }

        search_text_lower = search_text.lower()
        for category, keywords in categories.items():
            if any(keyword in search_text_lower for keyword in keywords):
                return category

        return 'other'

    def _build_description(self, vuln_data: Dict) -> str:
        """Строит полное описание уязвимости."""
        description_parts = []

        # Основное описание
        main_desc = vuln_data.get('description', '')
        if main_desc and main_desc != "Описание не найдено":
            description_parts.append(main_desc)

        # CVE
        cves = vuln_data.get('cves', [])
        if cves:
            description_parts.append(f"CVE: {', '.join(cves)}")

        # Пакеты
        packages = vuln_data.get('packages', [])
        if packages:
            package_names = [f"{pkg.get('name', '')} {pkg.get('version', '')}".strip() for pkg in packages]
            description_parts.append(f"Affected packages: {', '.join(package_names)}")

        # Дата
        date = vuln_data.get('date', '')
        if date and date != "Дата не найдена":
            description_parts.append(f"Published: {date}")

        # URL
        url = vuln_data.get('url', '')
        if url:
            description_parts.append(f"Source: {url}")

        return ". ".join(description_parts)


def integrate_with_vulnerability_manager(vulnerabilities_data: List[Dict]):
    """Интегрирует спарсенные данные с системой Vulnerability Manager."""
    logger.info("=== ИНТЕГРАЦИЯ С VULNERABILITY MANAGER ===")

    try:
        db_manager = VulnerabilityDBManager()
        result = db_manager.save_vulnerabilities_to_db(vulnerabilities_data)

        return result

    except Exception as e:
        logger.error(f"Ошибка интеграции с Vulnerability Manager: {e}")
        return {"saved": 0, "skipped": 0, "errors": len(vulnerabilities_data),
                "total_processed": len(vulnerabilities_data)}
# --- Настройка логирования ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Конфигурация Selenium ---
CHROMEDRIVER_PATH = None
BASE_URL = "https://osv.dev/list"

# --- Конфигурация папок ---
BASE_DATA_DIR = "vulnerability_data"
HTML_DIR = os.path.join(BASE_DATA_DIR, "html_pages")
JSON_DIR = os.path.join(BASE_DATA_DIR, "json_data")
SCREENSHOTS_DIR = os.path.join(BASE_DATA_DIR, "screenshots")
DEBUG_DIR = os.path.join(BASE_DATA_DIR, "debug")

# --- Ключевые слова для фильтрации ---
KEYWORDS = {
    # --- Core AI/ML Terms ---
    "Neural Network": 95,
    "Deep Learning": 92,
    "Machine Learning": 94,
    "AI Model": 96,
    "Large Language Model": 99,
    "LLM": 99,
    "Transformer": 90,
    "Generative AI": 98,
    "Foundation Model": 95,
    "AI Inference": 93,
    "Model Serving": 91,
    "Prompt Injection": 99,
    "Jailbreak": 97,
    "Adversarial Example": 96,
    "Adversarial Attack": 96,
    "Model Extraction": 95,
    "Model Inversion": 92,
    "Membership Inference": 90,
    "Data Poisoning": 93,
    "Backdoor Attack": 91,
    "Training Data Leak": 94,
    "Overfitting Exploit": 85,
    "Side-Channel Attack AI": 88,
    "Model Stealing": 95,
    "AI Red Teaming": 90,
    "AI Penetration Testing": 92,
    "AI Security": 99,
    "ML Security": 97,

    # --- AI Platforms & Frameworks (часто упоминаются в CVE/адвисориях) ---
    "TensorFlow": 94,
    "PyTorch": 95,
    "ONNX": 90,
    "Hugging Face": 98,
    "LangChain": 97,
    "LlamaIndex": 96,
    "AutoGPT": 95,
    "Transformers": 93,
    "Diffusion Model": 90,
    "Stable Diffusion": 92,
    "Whisper": 88,
    "OpenAI API": 99,
    "Azure AI": 93,
    "Google Vertex AI": 91,
    "AWS SageMaker": 92,
    "IBM Watson": 87,
    "NVIDIA Triton": 90,
    "TensorFlow Serving": 92,
    "TorchServe": 91,
    "MLflow": 86,
    "Kubeflow": 88,
    "Ray Serve": 87,

    # --- AI-as-a-Service & API Vulnerabilities ---
    "AI API": 97,
    "Inference API": 96,
    "REST API AI": 95,
    "AI Endpoint": 94,
    "Cloud AI": 93,
    "AIaaS": 92,
    "Prompt Engineering": 90,
    "Input Manipulation": 93,
    "API Abuse": 96,
    "Rate Limit Bypass": 94,
    "LLM API": 98,

    # --- Web Scraping & Automation (в контексте уязвимостей) ---
    "Web Scraping": 99,
    "Scraping Bot": 95,
    "Headless Browser": 94,
    "Puppeteer": 93,
    "Playwright": 94,
    "Selenium": 93,
    "Browser Automation": 92,
    "CAPTCHA Solver": 97,
    "Anti-bot Bypass": 98,
    "Behavioral Fingerprinting": 90,
    "Fingerprint Spoofing": 92,
    "Dynamic Content Scraping": 93,
    "LLM Scraping": 98,
    "AI-Powered Scraper": 96,
    "Scraping Detection Evasion": 97,
    "Web Crawler AI": 94,
    "Intelligent Scraper": 93,
    "Scrapy": 90,
    "BeautifulSoup": 85,
    "Requests-HTML": 84,

    # --- Enterprise & Industrial Systems (где может быть ИИ) ---
    "Fortinet": 85,
    "Cisco": 88,
    "Siemens": 87,
    "Schneider Electric": 86,
    "Moxa": 84,
    "HP": 85,
    "Dell": 83,
    "Broadcom": 82,
    "SAP": 86,
    "Autodesk": 80,
    "TeamViewer": 81,
    "Splunk": 83,
    "Qualcomm": 82,
    "MongoDB": 87,
    "Red Hat": 89,
    "SUSE": 86,
    "Ubuntu": 88,
    "Debian": 87,
    "Adobe": 85,

    # --- Уязвимости в инфраструктуре, связанной с ИИ ---
    "Docker": 90,
    "Kubernetes": 92,
    "Container Escape": 91,
    "Model Registry": 85,
    "ML Pipeline": 87,
    "Feature Store": 83,
    "AI Proxy": 88,
    "Model Zoo": 84,
    "Weights Leak": 90,
    "Checkpoint Exposure": 92,
    ".bin file exposure": 88,
    "HF Token Leak": 95,
    "API Key Leak": 96,

    # --- Специфические атаки и векторы ---
    "Indirect Prompt Injection": 98,
    "Retrieval-Augmented Generation": 94,
    "RAG Injection": 96,
    "Tool Use Exploitation": 93,
    "Agent Jailbreak": 95,
    "LLM DoS": 90,
    "Token Smuggling": 92,
    "Training Data Extraction": 94,
    "Model Memorization": 91,
    "Privacy Attack ML": 90,

    # --- Emerging Threats (2024–2025) ---
    "AI Supply Chain": 93,
    "Poisoned Model": 92,
    "Trojaned Model": 91,
    "Malicious Package AI": 94,
    "npm AI": 90,
    "PyPI AI": 92,
    "Malicious LLM Plugin": 95,
    "AI Plugin Injection": 96,
    "LangChain Exploit": 97,
    "Vector DB Leak": 93,
    "ChromaDB": 88,
    "Pinecone": 87,
    "Weaviate": 86,
    "FAISS": 85,

    # --- Обход защиты сайтов (часто в bounty-отчётах) ---
    "Cloudflare Bypass": 95,
    "Akamai Bypass": 92,
    "PerimeterX Evasion": 90,
    "Datadome Detection": 89,
    "FingerprintJS": 88,
    "Canvas Fingerprinting": 87,
    "WebGL Fingerprint": 86,
    "Headless Detection": 93,
    "Automation Detection": 92,
    "Bot Mitigation Bypass": 96,

    # --- Дополнительные термины из CVE и адвисорий ---
    "Remote Code Execution AI": 97,
    "Server-Side Prompt Injection": 99,
    "SSRF via LLM": 96,
    "Insecure Deserialization AI": 90,
    "Model Deserialization": 89,
    "Pickled Model": 91,
    "Unsafe YAML Load": 88,
    "Template Injection LLM": 95,
    "Output Parser Exploit": 92,
    "Guardrail Bypass": 94
}

class FileManager:
    """Менеджер для работы с файлами и папками."""

    def __init__(self, base_dir: str = BASE_DATA_DIR):
        self.base_dir = Path(base_dir)
        self.setup_directories()

    def setup_directories(self):
        """Создает необходимые директории."""
        directories = [
            self.base_dir,
            self.base_dir / "html_pages",
            self.base_dir / "json_data",
            self.base_dir / "screenshots",
            self.base_dir / "debug",
            self.base_dir / "html_pages" / "list_pages",
            self.base_dir / "html_pages" / "vulnerability_pages",
            self.base_dir / "json_data" / "raw",
            self.base_dir / "json_data" / "filtered",
            self.base_dir / "json_data" / "stats"
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Создана директория: {directory}")

    def save_html(self, content: str, filename: str, subfolder: str = ""):
        """Сохраняет HTML контент в файл."""
        if subfolder:
            file_path = self.base_dir / "html_pages" / subfolder / f"{filename}.html"
        else:
            file_path = self.base_dir / "html_pages" / f"{filename}.html"

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.debug(f"HTML сохранен: {file_path}")
            return str(file_path)
        except Exception as e:
            logger.error(f"Ошибка сохранения HTML {filename}: {e}")
            return None

    def save_json(self, data: Any, filename: str, subfolder: str = ""):
        """Сохраняет JSON данные в файл."""
        if subfolder:
            file_path = self.base_dir / "json_data" / subfolder / f"{filename}.json"
        else:
            file_path = self.base_dir / "json_data" / f"{filename}.json"

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.debug(f"JSON сохранен: {file_path}")
            return str(file_path)
        except Exception as e:
            logger.error(f"Ошибка сохранения JSON {filename}: {e}")
            return None

    def save_screenshot(self, driver, filename: str):
        """Сохраняет скриншот."""
        file_path = self.base_dir / "screenshots" / f"{filename}.png"
        try:
            driver.save_screenshot(str(file_path))
            logger.debug(f"Скриншот сохранен: {file_path}")
            return str(file_path)
        except Exception as e:
            logger.error(f"Ошибка сохранения скриншота {filename}: {e}")
            return None

    def get_timestamp(self):
        """Возвращает timestamp для имен файлов."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def list_saved_files(self, file_type: str = "all"):
        """Возвращает список сохраненных файлов."""
        files = {}

        if file_type in ["all", "html"]:
            html_files = list(self.base_dir.rglob("*.html"))
            files["html"] = [str(f) for f in html_files]

        if file_type in ["all", "json"]:
            json_files = list(self.base_dir.rglob("*.json"))
            files["json"] = [str(f) for f in json_files]

        if file_type in ["all", "screenshots"]:
            screenshot_files = list(self.base_dir.rglob("*.png"))
            files["screenshots"] = [str(f) for f in screenshot_files]

        return files


# Инициализируем менеджер файлов
file_manager = FileManager()


def hide_distracting_elements(driver):
    """Скрывает отвлекающие элементы на странице."""
    hide_script = """
    const distractingSelectors = [
        'header', 'footer', 'nav', 
        '.ad', '.banner', '.popup',
        '.cookie-consent', '.newsletter',
        '.social-share', '.related-articles',
        '.advertisement', '.ads', '[class*="ad"]',
        '.sidebar', '.social-media',
        '.recommendations', '.related-posts'
    ];

    distractingSelectors.forEach(selector => {
        const elements = document.querySelectorAll(selector);
        elements.forEach(element => {
            element.style.display = 'none';
        });
    });

    const mainContent = document.querySelector('.main-content, .content, main, .container');
    if (mainContent) {
        mainContent.style.margin = '0';
        mainContent.style.padding = '20px';
        mainContent.style.maxWidth = '100%';
        mainContent.style.width = '100%';
    }

    const fixedElements = document.querySelectorAll('*[style*="fixed"]');
    fixedElements.forEach(el => el.style.display = 'none');
    """
    try:
        driver.execute_script(hide_script)
        logger.debug("Отвлекающие элементы скрыты")
    except Exception as e:
        logger.warning(f"Не удалось скрыть отвлекающие элементы: {e}")


def get_webdriver():
    """Создает и возвращает экземпляр WebDriver."""
    options = Options()
    # options.add_argument("--headless")  # Раскомментируйте для headless режима
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)

    service = Service(CHROMEDRIVER_PATH) if CHROMEDRIVER_PATH else Service()
    driver = webdriver.Chrome(service=service, options=options)
    driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

    return driver


def extract_clean_text(element):
    """Извлекает чистый текст из элемента, убирая лишние части."""
    if not element:
        return ""

    text = element.get_text(strip=True)

    # Убираем текст "See a problem..." и подобные
    patterns_to_remove = [
        r'See a problem.*',
        r'Please try reporting it.*',
        r'to the source first.*'
    ]

    for pattern in patterns_to_remove:
        text = re.sub(pattern, '', text, flags=re.IGNORECASE | re.DOTALL)

    return text.strip()


def parse_vulnerability_details_bs(soup, url):
    """Парсит детали одной уязвимости с помощью BeautifulSoup."""
    logger.info(f"Парсинг деталей уязвимости: {url}")

    details = {"url": url}

    # --- Извлечение ID уязвимости ---
    title_elem = soup.select_one("h1")
    if title_elem:
        # Убираем лишний текст из ID
        raw_id = title_elem.get_text(strip=True)
        # Оставляем только ID (первую часть до лишнего текста)
        clean_id = re.split(r'See a problem|Please try', raw_id, flags=re.IGNORECASE)[0].strip()
        details["id"] = clean_id
    else:
        details["id"] = "Не найден ID"

    # --- Извлечение описания ---
    description_elem = soup.select_one(
        "div[data-testid='summary'], .description, .vulnerability-description, .summary, "
        "main p, .content p, [class*='description']"
    )
    details["description"] = extract_clean_text(description_elem) or "Описание не найдено"

    # --- Извлечение CVE ---
    page_text = soup.get_text()
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cve_matches = re.findall(cve_pattern, page_text)
    details["cves"] = sorted(list(set(cve_matches)))

    # --- Извлечение пакетов ---
    packages = []

    # Ищем таблицы с затронутыми пакетами
    affected_tables = soup.select(
        "table[data-testid='affected-packages'], "
        "table.affected-packages, "
        "table.packages, "
        "table:has(th:contains('Package')), "
        "table:has(th:contains('Affected'))"
    )

    for table in affected_tables:
        rows = table.select("tbody tr, tr")
        for row in rows:
            cells = row.select("td")
            if len(cells) >= 2:
                pkg_name = cells[0].get_text(strip=True)
                pkg_version = cells[1].get_text(strip=True)
                if pkg_name and pkg_name.lower() not in ['package', 'name', 'component']:
                    packages.append({"name": pkg_name, "version": pkg_version})

    # Если таблиц нет, ищем списки пакетов
    if not packages:
        package_lists = soup.select(
            "ul.packages, ol.packages, "
            "[class*='package'], [class*='affected']"
        )
        for pkg_list in package_lists:
            items = pkg_list.select("li")
            for item in items:
                text = item.get_text(strip=True)
                if text and not any(word in text.lower() for word in ['package', 'name', 'component']):
                    packages.append({"name": text, "version": "N/A"})

    details["packages"] = packages

    # --- Извлечение даты ---
    date_elem = soup.select_one("time, [datetime], .date, .published-date, .modified-date")
    if date_elem:
        details["date"] = date_elem.get('datetime') or extract_clean_text(date_elem)
    else:
        # Ищем дату в тексте
        date_patterns = [
            r'Published:\s*(\d{4}-\d{2}-\d{2}|\w+ \d{1,2}, \d{4})',
            r'Date:\s*(\d{4}-\d{2}-\d{2}|\w+ \d{1,2}, \d{4})',
            r'Modified:\s*(\d{4}-\d{2}-\d{2}|\w+ \d{1,2}, \d{4})'
        ]
        for pattern in date_patterns:
            date_match = re.search(pattern, page_text, re.IGNORECASE)
            if date_match:
                details["date"] = date_match.group(1)
                break
        else:
            details["date"] = "Дата не найдена"

    logger.info(f"Спаршены детали: {details.get('id', 'N/A')}")
    return details


def debug_page_content(driver, page_number):
    """Диагностическая функция для анализа содержимого страницы."""
    logger.info(f"=== ДИАГНОСТИКА СТРАНИЦЫ {page_number} ===")

    # Сохраняем HTML для анализа
    page_source = driver.page_source
    file_manager.save_html(page_source, f"debug_page_{page_number}", "debug")

    # Анализируем различные элементы
    soup = BeautifulSoup(page_source, 'html.parser')

    # Ищем все возможные контейнеры с уязвимостями
    possible_containers = soup.find_all(['div', 'section', 'ul', 'ol'], class_=True)
    logger.info(f"Найдено контейнеров с классами: {len(possible_containers)}")

    # Ищем все ссылки
    all_links = soup.find_all('a', href=True)
    vulnerability_links = [a for a in all_links if '/vulnerability/' in a['href']]
    logger.info(f"Всего ссылок: {len(all_links)}, из них на уязвимости: {len(vulnerability_links)}")

    # Ищем кнопку Load more
    buttons = soup.find_all('button')
    load_more_buttons = [btn for btn in buttons if 'load more' in btn.get_text().lower()]
    logger.info(f"Найдено кнопок: {len(buttons)}, из них Load more: {len(load_more_buttons)}")

    logger.info("=== КОНЕЦ ДИАГНОСТИКИ ===")


def filter_by_keywords(vulnerabilities: List[Dict]) -> List[Dict]:
    """Фильтрует уязвимости по ключевым словам."""
    filtered = []

    for vuln in vulnerabilities:
        # Собираем весь текст для анализа
        search_text = ""
        search_text += vuln.get('id', '') + " "
        search_text += vuln.get('description', '') + " "
        search_text += " ".join([pkg.get('name', '') for pkg in vuln.get('packages', [])]) + " "
        search_text += " ".join(vuln.get('cves', [])) + " "

        # Ищем ключевые слова
        found_keywords = []
        for keyword, price in KEYWORDS.items():
            if re.search(r'\b' + re.escape(keyword) + r'\b', search_text, re.IGNORECASE):
                found_keywords.append({
                    "keyword": keyword,
                    "price": price,
                    "matches": re.findall(r'\b' + re.escape(keyword) + r'\b', search_text, re.IGNORECASE)
                })

        if found_keywords:
            vuln_copy = vuln.copy()
            vuln_copy["matched_keywords"] = found_keywords
            vuln_copy["total_price"] = sum(kw["price"] for kw in found_keywords)
            filtered.append(vuln_copy)

    return filtered


def get_vulnerability_links_selenium(driver, max_pages=None):
    """Извлекает ссылки на отдельные уязвимости с помощью Selenium."""
    links = set()
    current_page = 1

    while True:
        logger.info(f"Парсинг страницы уязвимостей {current_page}...")

        # Диагностика содержимого страницы
        debug_page_content(driver, current_page)

        # Скрываем отвлекающие элементы перед парсингом
        hide_distracting_elements(driver)

        # Ждем загрузки контента
        try:
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "a[href*='/vulnerability/']"))
            )
            logger.info("Ссылки на уязвимости загружены")
        except TimeoutException:
            logger.warning("Таймаут ожидания ссылок на уязвимости.")
            break

        # Получаем HTML-код страницы и сохраняем
        page_source = driver.page_source
        file_manager.save_html(page_source, f"list_page_{current_page}", "list_pages")

        soup = BeautifulSoup(page_source, 'html.parser')

        # Ищем ссылки на уязвимости
        vulnerability_items = soup.select("a[href*='/vulnerability/']")
        logger.info(f"Найдено {len(vulnerability_items)} ссылок")

        # Обрабатываем найденные ссылки
        new_links_count = 0
        for item in vulnerability_items:
            href = item.get('href')
            if href:
                full_url = urljoin(BASE_URL, href)
                if full_url != BASE_URL and full_url not in links:
                    links.add(full_url)
                    new_links_count += 1

        logger.info(f"На текущей странице найдено {new_links_count} новых ссылок, всего: {len(links)}")

        # Проверяем ограничение по страницам
        if max_pages and current_page >= max_pages:
            logger.info(f"Достигнуто максимальное количество страниц ({max_pages}).")
            break

        # Пробуем найти и кликнуть кнопку "Load more"
        try:
            load_more_button = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.XPATH,
                                            "//button[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'load more')]"))
            )
            logger.info("Найдена кнопка 'Load more', кликаем...")
            driver.execute_script("arguments[0].click();", load_more_button)
            current_page += 1
            time.sleep(1)
        except TimeoutException:
            logger.info("Кнопка 'Load more' не найдена. Возможно, достигнута последняя страница.")
            break
        except Exception as e:
            logger.error(f"Ошибка при работе с кнопкой: {e}")
            break

    logger.info(f"Всего найдено {len(links)} уникальных ссылок на уязвимости.")
    return list(links)


def get_vulnerability_details_selenium(driver, url):
    """Получает HTML страницы уязвимости и передает его в BS4 для парсинга."""
    logger.info(f"Получение деталей уязвимости: {url}")

    try:
        driver.get(url)
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        time.sleep(2)

        # Скрываем отвлекающие элементы
        hide_distracting_elements(driver)
        time.sleep(1)

        # Получаем HTML-код страницы и сохраняем
        page_source = driver.page_source
        vuln_id = url.split('/')[-1] if '/' in url else "unknown"
        file_manager.save_html(page_source, f"vuln_{vuln_id}", "vulnerability_pages")

        soup = BeautifulSoup(page_source, 'html.parser')

        return parse_vulnerability_details_bs(soup, url)

    except Exception as e:
        logger.error(f"Ошибка при получении деталей {url}: {e}")
        return {"url": url, "error": str(e)}


def main():
    """Основная функция."""
    driver = get_webdriver()
    session_timestamp = file_manager.get_timestamp()

    try:
        logger.info(f"Открытие главной страницы: {BASE_URL}")
        driver.get(BASE_URL)
        time.sleep(5)

        # Сохраняем скриншот главной страницы
        file_manager.save_screenshot(driver, f"main_page_{session_timestamp}")

        # Скрываем отвлекающие элементы
        hide_distracting_elements(driver)

        # Получаем ссылки на уязвимости
        vulnerability_links = get_vulnerability_links_selenium(driver, max_pages=3)

        logger.info(f"Найдено ссылок: {len(vulnerability_links)}")

        # Парсим детали
        all_vulnerabilities = []
        for i, link in enumerate(vulnerability_links):
            logger.info(f"Обработка уязвимости {i + 1}/{len(vulnerability_links)}: {link}")
            try:
                vulnerability_details = get_vulnerability_details_selenium(driver, link)
                all_vulnerabilities.append(vulnerability_details)
            except Exception as e:
                logger.error(f"Ошибка при обработке {link}: {e}")
                continue

        # Фильтруем по ключевым словам
        filtered_vulnerabilities = filter_by_keywords(all_vulnerabilities)

        # Сортируем по цене (по убыванию)
        filtered_vulnerabilities.sort(key=lambda x: x.get('total_price', 0), reverse=True)

        # Сохраняем все результаты в JSON
        file_manager.save_json(all_vulnerabilities, f"all_vulnerabilities_{session_timestamp}", "raw")
        file_manager.save_json(filtered_vulnerabilities, f"filtered_vulnerabilities_{session_timestamp}", "filtered")

        # Сохраняем статистику
        stats = {
            "session_timestamp": session_timestamp,
            "total_vulnerabilities": len(all_vulnerabilities),
            "filtered_vulnerabilities": len(filtered_vulnerabilities),
            "keywords_used": KEYWORDS,
            "processing_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "top_keywords": {}
        }

        # Собираем статистику по ключевым словам
        keyword_stats = {}
        for vuln in filtered_vulnerabilities:
            for kw_match in vuln.get('matched_keywords', []):
                keyword = kw_match['keyword']
                if keyword not in keyword_stats:
                    keyword_stats[keyword] = 0
                keyword_stats[keyword] += 1

        stats["top_keywords"] = dict(sorted(keyword_stats.items(), key=lambda x: x[1], reverse=True)[:10])

        file_manager.save_json(stats, f"parsing_stats_{session_timestamp}", "stats")

        # Показываем список сохраненных файлов
        saved_files = file_manager.list_saved_files()
        logger.info("=== СОХРАНЕННЫЕ ФАЙЛЫ ===")
        for file_type, files in saved_files.items():
            logger.info(f"{file_type.upper()}: {len(files)} файлов")
            for file_path in files[:3]:  # Показываем первые 3 файла каждого типа
                logger.info(f"  - {file_path}")

        logger.info(f"Парсинг завершен!")
        logger.info(f"Всего обработано: {len(all_vulnerabilities)} уязвимостей")
        logger.info(f"Отфильтровано по ключевым словам: {len(filtered_vulnerabilities)} уязвимостей")
        logger.info(f"Результаты сохранены в папке: {BASE_DATA_DIR}")

    except Exception as e:
        logger.error(f"Произошла критическая ошибка: {e}")
    finally:
        logger.info("Закрытие браузера...")
        driver.quit()


if __name__ == "__main__":
    main()