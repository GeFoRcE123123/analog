import requests
import threading
import time
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
import json
from models.entities import NVDVulnerability, NVDMetrics, NVDWeakness, NVDReference, NVDConfiguration


class MultiThreadedNVDParser:
    """
    Многопоточный парсер для получения уязвимостей из NVD API
    """

    def __init__(self, api_key: str = None, max_workers: int = 10, requests_per_second: int = 5):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.max_workers = max_workers
        self.requests_per_second = requests_per_second
        self.last_request_time = 0
        self.request_lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

        # Ключевые слова для поиска уязвимостей связанных с нейросетями
        self.ai_keywords = [
            'ai', 'artificial intelligence', 'machine learning', 'neural network',
            'deep learning', 'tensorflow', 'pytorch', 'keras', 'scikit-learn',
            'computer vision', 'nlp', 'natural language processing',
            'reinforcement learning', 'generative ai', 'gpt', 'transformer',
            'convolutional', 'recurrent', 'lstm', 'gan', 'autoencoder',
            'llm', 'large language model', 'openai', 'huggingface', 'anthropic',
            'neural', 'deepmind', 'ai model', 'ml model', 'stable diffusion',
            'midjourney', 'dall-e', 'chatgpt', 'bard', 'claude'
        ]

    def _rate_limit(self):
        """Ограничение частоты запросов для соблюдения лимитов NVD API"""
        with self.request_lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            min_interval = 1.0 / self.requests_per_second

            if time_since_last < min_interval:
                time.sleep(min_interval - time_since_last)

            self.last_request_time = time.time()

    def _make_request(self, params: Dict) -> Optional[Dict]:
        """Выполнение API запроса с ограничением частоты и обработкой ошибок"""
        self._rate_limit()

        headers = {'User-Agent': 'VulnerabilityManager/1.0'}
        if self.api_key:
            headers['apiKey'] = self.api_key

        try:
            response = requests.get(self.base_url, params=params, headers=headers, timeout=30)

            # Проверяем статус ответа
            if response.status_code == 403:
                print("Ошибка: Доступ запрещен. Проверьте API ключ или попробуйте позже.")
                return None
            elif response.status_code == 429:
                print("Превышен лимит запросов. Уменьшаем частоту...")
                time.sleep(60)  # Ждем 1 минуту
                return self._make_request(params)  # Рекурсивный повтор

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ошибка запроса к NVD API: {e}")
            return None

    def _parse_metrics(self, metrics_data: Dict) -> NVDMetrics:
        """Парсинг метрик CVSS"""
        cvss_v2 = None
        cvss_v3 = None
        cvss_v4 = None

        if 'cvssMetricV2' in metrics_data:
            for metric in metrics_data['cvssMetricV2']:
                cvss_data = metric.get('cvssData', {})
                cvss_v2 = {
                    'version': '2.0',
                    'vectorString': cvss_data.get('vectorString'),
                    'baseScore': cvss_data.get('baseScore'),
                    'baseSeverity': metric.get('baseSeverity'),
                    'exploitabilityScore': metric.get('exploitabilityScore'),
                    'impactScore': metric.get('impactScore')
                }
                break

        if 'cvssMetricV31' in metrics_data:
            for metric in metrics_data['cvssMetricV31']:
                cvss_data = metric.get('cvssData', {})
                cvss_v3 = {
                    'version': '3.1',
                    'vectorString': cvss_data.get('vectorString'),
                    'baseScore': cvss_data.get('baseScore'),
                    'baseSeverity': cvss_data.get('baseSeverity'),
                    'exploitabilityScore': metric.get('exploitabilityScore'),
                    'impactScore': metric.get('impactScore')
                }
                break

        if 'cvssMetricV40' in metrics_data:
            for metric in metrics_data['cvssMetricV40']:
                cvss_data = metric.get('cvssData', {})
                cvss_v4 = {
                    'version': '4.0',
                    'vectorString': cvss_data.get('vectorString'),
                    'baseScore': cvss_data.get('baseScore'),
                    'baseSeverity': cvss_data.get('baseSeverity')
                }
                break

        return NVDMetrics(cvss_v2=cvss_v2, cvss_v3=cvss_v3, cvss_v4=cvss_v4)

    def _is_ai_related(self, vulnerability_data: Dict) -> Tuple[bool, float]:
        """Определение, относится ли уязвимость к нейросетям/ИИ"""
        descriptions = vulnerability_data.get('descriptions', [])
        combined_text = ' '.join([
            desc.get('value', '').lower()
            for desc in descriptions
        ])

        confidence = 0.0
        matches_found = 0

        # Проверка конфигураций на наличие AI-продуктов
        configurations = vulnerability_data.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe_match in cpe_matches:
                    criteria = cpe_match.get('criteria', '').lower()
                    for keyword in self.ai_keywords:
                        if keyword in criteria:
                            matches_found += 1
                            confidence = min(confidence + 0.3, 1.0)

        # Проверка описаний на ключевые слова
        for keyword in self.ai_keywords:
            if keyword in combined_text:
                matches_found += 1
                confidence = min(confidence + 0.2, 1.0)

        # Проверка ссылок
        references = vulnerability_data.get('references', [])
        for ref in references:
            url = (getattr(ref, 'url', None) or (ref.get('url', '') if isinstance(ref, dict) else '')).lower()
            for keyword in self.ai_keywords:
                if keyword in url:
                    matches_found += 1
                    confidence = min(confidence + 0.1, 1.0)

        is_ai_related = confidence >= 0.3  # Порог уверенности
        return is_ai_related, confidence

    def _parse_vulnerability_data(self, vuln_data: Dict) -> Optional[NVDVulnerability]:
        """Парсинг данных об уязвимости из NVD"""
        try:
            cve_data = vuln_data.get('cve', {})

            # Основная информация
            cve_id = cve_data.get('id', '')
            if not cve_id:
                return None

            # Парсинг дат
            published_str = cve_data.get('published', '')
            last_modified_str = cve_data.get('lastModified', '')

            try:
                published = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                last_modified = datetime.fromisoformat(last_modified_str.replace('Z', '+00:00'))
            except ValueError:
                published = datetime.now()
                last_modified = datetime.now()

            # Парсинг метрик
            metrics_data = cve_data.get('metrics', {})
            metrics = self._parse_metrics(metrics_data)

            # Парсинг слабостей
            weaknesses = []
            for weakness in cve_data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    weaknesses.append(NVDWeakness(
                        source=weakness.get('source', ''),
                        type=weakness.get('type', ''),
                        description=desc.get('value', ''),
                        cwe_id=desc.get('cweId', '')
                    ))

            # Парсинг ссылок
            references = []
            for ref in cve_data.get('references', []):
                references.append(NVDReference(
                    url=ref.get('url', ''),
                    source=ref.get('source', ''),
                    tags=ref.get('tags', [])
                ))

            # Парсинг конфигураций
            configurations = []
            for config in cve_data.get('configurations', []):
                configurations.append(NVDConfiguration(
                    nodes=config.get('nodes', []),
                    operator=config.get('operator', '')
                ))

            # Проверка на отношение к нейросетям
            is_ai_related, ai_confidence = self._is_ai_related(cve_data)

            # Проверка флагов
            has_kev = cve_data.get('cisaExploitAdd') is not None
            has_cert_alerts = any('CERT' in (getattr(ref, 'source', None) or (ref.get('source', '') if isinstance(ref, dict) else '')) for ref in references)

            return NVDVulnerability(
                cve_id=cve_id,
                source_identifier=cve_data.get('sourceIdentifier', ''),
                published=published,
                last_modified=last_modified,
                vuln_status=cve_data.get('vulnStatus', ''),
                descriptions=cve_data.get('descriptions', []),
                metrics=metrics,
                weaknesses=weaknesses,
                configurations=configurations,
                references=references,
                vendor_comments=cve_data.get('vendorComments', []),
                is_ai_related=is_ai_related,
                ai_confidence=ai_confidence,
                has_kev=has_kev,
                has_cert_alerts=has_cert_alerts
            )

        except Exception as e:
            self.logger.error(f"Ошибка парсинга уязвимости: {e}")
            return None

    def _fetch_vulnerabilities_chunk(self, start_index: int, results_per_page: int = 2000) -> List[NVDVulnerability]:
        """Получение части уязвимостей (для многопоточности)"""
        params = {
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }

        print(f"Загрузка уязвимостей с индекса {start_index}")

        data = self._make_request(params)
        if not data:
            return []

        vulnerabilities_data = data.get('vulnerabilities', [])
        parsed_vulnerabilities = []

        for vuln_data in vulnerabilities_data:
            parsed_vuln = self._parse_vulnerability_data(vuln_data)
            if parsed_vuln:
                parsed_vulnerabilities.append(parsed_vuln)

        print(f"Загружено {len(parsed_vulnerabilities)} уязвимостей с индекса {start_index}")
        return parsed_vulnerabilities

    def get_all_vulnerabilities(self) -> Tuple[List[NVDVulnerability], List[NVDVulnerability]]:
        """Получение всех уязвимостей с использованием многопоточности"""
        print("Начало загрузки всех уязвимостей из NVD...")

        # Сначала получаем общее количество
        test_params = {'resultsPerPage': 1}
        test_data = self._make_request(test_params)

        if not test_data:
            print("Ошибка: не удалось подключиться к NVD API")
            return [], []

        total_results = test_data.get('totalResults', 0)
        results_per_page = 2000  # Максимальное значение по документации

        print(f"Всего уязвимостей в NVD: {total_results}")

        # Создаем задачи для многопоточной загрузки
        all_vulnerabilities = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []

            for start_index in range(0, total_results, results_per_page):
                future = executor.submit(self._fetch_vulnerabilities_chunk, start_index, results_per_page)
                futures.append(future)

            # Собираем результаты
            for future in as_completed(futures):
                try:
                    chunk_result = future.result()
                    all_vulnerabilities.extend(chunk_result)
                    print(f"Получен чанк с {len(chunk_result)} уязвимостями")
                except Exception as e:
                    print(f"Ошибка при загрузке чанка: {e}")

        # Разделяем на AI и обычные уязвимости
        ai_vulnerabilities = [v for v in all_vulnerabilities if v.is_ai_related]
        regular_vulnerabilities = [v for v in all_vulnerabilities if not v.is_ai_related]

        print(f"\n=== РЕЗУЛЬТАТЫ ПАРСИНГА ===")
        print(f"Всего загружено уязвимостей: {len(all_vulnerabilities)}")
        print(f"Уязвимостей связанных с нейросетями: {len(ai_vulnerabilities)}")
        print(f"Обычных уязвимостей: {len(regular_vulnerabilities)}")
        print(f"Процент AI уязвимостей: {len(ai_vulnerabilities) / len(all_vulnerabilities) * 100:.2f}%")

        return all_vulnerabilities, ai_vulnerabilities

    def get_recent_vulnerabilities(self, days: int = 30) -> Tuple[List[NVDVulnerability], List[NVDVulnerability]]:
        """Получение уязвимостей за последние N дней"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        start_str = start_date.strftime('%Y-%m-%d')
        end_str = end_date.strftime('%Y-%m-%d')

        print(f"Загрузка уязвимостей за последние {days} дней ({start_str} - {end_str})")

        params = {
            'pubStartDate': f"{start_str}T00:00:00.000Z",
            'pubEndDate': f"{end_str}T23:59:59.999Z",
            'resultsPerPage': 2000
        }

        all_vulnerabilities = []
        start_index = 0

        while True:
            params['startIndex'] = start_index
            data = self._make_request(params)

            if not data:
                break

            vulnerabilities_data = data.get('vulnerabilities', [])
            if not vulnerabilities_data:
                break

            for vuln_data in vulnerabilities_data:
                parsed_vuln = self._parse_vulnerability_data(vuln_data)
                if parsed_vuln:
                    all_vulnerabilities.append(parsed_vuln)

            print(f"Загружено {len(vulnerabilities_data)} уязвимостей")

            # Проверяем, есть ли еще данные
            if len(vulnerabilities_data) < params['resultsPerPage']:
                break

            start_index += params['resultsPerPage']

        ai_vulnerabilities = [v for v in all_vulnerabilities if v.is_ai_related]

        print(f"\n=== РЕЗУЛЬТАТЫ ПАРСИНГА ЗА {days} ДНЕЙ ===")
        print(f"Всего уязвимостей: {len(all_vulnerabilities)}")
        print(f"Уязвимостей связанных с нейросетями: {len(ai_vulnerabilities)}")

        return all_vulnerabilities, ai_vulnerabilities