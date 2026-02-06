import os
import json
from typing import Dict, List, Any, Optional
import requests
import time
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()


class ShodanAPI:
    """
    Обертка для Shodan API с кэшированием и rate limiting
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('SHODAN_API_KEY')
        if not self.api_key:
            raise ValueError("SHODAN_API_KEY не установлен в .env файле")

        self.base_url = "https://api.shodan.io"
        self.cache_dir = Path("data/cache/shodan")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limit_delay = 1.0  # Задержка в секундах между запросами

    def _get_cache_path(self, query: str) -> Path:
        """Получение пути к кэшу для запроса"""
        safe_query = "".join(c for c in query if c.isalnum() or c in ['_', '-'])
        safe_query = safe_query[:100]  # Ограничение длины имени файла
        return self.cache_dir / f"{safe_query}.json"

    def _load_from_cache(self, query: str) -> Optional[Dict]:
        """Загрузка результатов из кэша"""
        cache_path = self._get_cache_path(query)
        if cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Ошибка при загрузке кэша: {e}")
        return None

    def _save_to_cache(self, query: str, data: Dict):
        """Сохранение результатов в кэш"""
        cache_path = self._get_cache_path(query)
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Ошибка при сохранении кэша: {e}")

    def search(self, query: str, max_results: int = 100, use_cache: bool = True) -> Dict[str, Any]:
        """
        Поиск хостов в Shodan

        Args:
            query: Поисковый запрос Shodan
            max_results: Максимальное количество результатов
            use_cache: Использовать кэш

        Returns:
            Словарь с результатами поиска
        """
        if use_cache:
            cached_results = self._load_from_cache(query)
            if cached_results:
                print(f"Результаты для '{query}' загружены из кэша")
                return cached_results

        print(f"Выполнение поиска в Shodan: {query}")

        headers = {
            'User-Agent': 'OSINT-Neural-Network/1.0'
        }

        params = {
            'key': self.api_key,
            'query': query,
            'max_results': max_results
        }

        try:
            # Соблюдение rate limits
            time.sleep(self.rate_limit_delay)

            response = requests.get(
                f"{self.base_url}/shodan/host/search",
                headers=headers,
                params=params,
                timeout=30
            )

            response.raise_for_status()
            results = response.json()

            if use_cache:
                self._save_to_cache(query, results)

            return results

        except requests.exceptions.RequestException as e:
            print(f"Ошибка при запросе к Shodan API: {e}")
            return {
                'error': str(e),
                'query': query,
                'results': []
            }

    def host_info(self, ip: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Получение подробной информации о хосте

        Args:
            ip: IP адрес хоста
            use_cache: Использовать кэш

        Returns:
            Словарь с информацией о хосте
        """
        if use_cache:
            cached_info = self._load_from_cache(f"host_{ip}")
            if cached_info:
                print(f"Информация о хосте {ip} загружена из кэша")
                return cached_info

        print(f"Получение информации о хосте: {ip}")

        headers = {
            'User-Agent': 'OSINT-Neural-Network/1.0'
        }

        params = {
            'key': self.api_key
        }

        try:
            time.sleep(self.rate_limit_delay)

            response = requests.get(
                f"{self.base_url}/shodan/host/{ip}",
                headers=headers,
                params=params,
                timeout=30
            )

            response.raise_for_status()
            host_info = response.json()

            if use_cache:
                self._save_to_cache(f"host_{ip}", host_info)

            return host_info

        except requests.exceptions.RequestException as e:
            print(f"Ошибка при получении информации о хосте {ip}: {e}")
            return {
                'error': str(e),
                'ip': ip
            }

    def analyze_vulnerabilities(self, query: str, max_results: int = 50) -> Dict[str, Any]:
        """
        Анализ уязвимостей для заданного запроса

        Args:
            query: Поисковый запрос
            max_results: Максимальное количество результатов

        Returns:
            Словарь с анализом уязвимостей
        """
        print(f"Анализ уязвимостей для запроса: {query}")

        # Сначала выполняем поиск
        search_results = self.search(query, max_results, use_cache=True)

        if 'error' in search_results:
            return search_results

        # Анализируем результаты
        vulnerability_analysis = {
            'total_hosts': len(search_results.get('matches', [])),
            'vulnerable_hosts': [],
            'vulnerability_summary': {},
            'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }

        for match in search_results.get('matches', []):
            ip = match.get('ip_str', 'unknown')
            port = match.get('port', 0)
            vulns = match.get('vulns', {})

            if vulns:
                host_vulns = []
                for cve_id, vuln_data in vulns.items():
                    cvss = vuln_data.get('cvss', 0)
                    severity = self._get_severity(cvss)

                    host_vulns.append({
                        'cve_id': cve_id,
                        'cvss': cvss,
                        'severity': severity,
                        'summary': vuln_data.get('summary', '')
                    })

                    # Обновление статистики
                    vulnerability_analysis['severity_counts'][severity] += 1

                    # Обновление summary
                    if cve_id not in vulnerability_analysis['vulnerability_summary']:
                        vulnerability_analysis['vulnerability_summary'][cve_id] = {
                            'count': 0,
                            'cvss': cvss,
                            'severity': severity,
                            'summary': vuln_data.get('summary', '')
                        }
                    vulnerability_analysis['vulnerability_summary'][cve_id]['count'] += 1

                vulnerability_analysis['vulnerable_hosts'].append({
                    'ip': ip,
                    'port': port,
                    'vulnerabilities': host_vulns
                })

        return vulnerability_analysis

    def _get_severity(self, cvss: float) -> str:
        """Определение уровня серьезности по CVSS"""
        if cvss >= 9.0:
            return 'critical'
        elif cvss >= 7.0:
            return 'high'
        elif cvss >= 4.0:
            return 'medium'
        else:
            return 'low'

    def generate_osint_report(self, target: str, include_vulnerabilities: bool = True) -> Dict[str, Any]:
        """
        Генерация полного OSINT отчета для цели

        Args:
            target: Организация или домен
            include_vulnerabilities: Включать анализ уязвимостей

        Returns:
            Полный отчет в структурированном формате
        """
        print(f"Генерация OSINT отчета для: {target}")

        report = {
            'target': target,
            'timestamp': time.time(),
            'summary': {},
            'findings': [],
            'vulnerabilities': {},
            'recommendations': []
        }

        # 1. Поиск по организации
        org_query = f'org:"{target}"'
        org_results = self.search(org_query, max_results=100)

        if 'error' not in org_results:
            report['summary']['total_hosts'] = org_results.get('total', 0)
            report['summary']['services'] = self._analyze_services(org_results)

        # 2. Поиск веб-серверов
        web_query = f'org:"{target}" http.title:""'
        web_results = self.search(web_query, max_results=50)

        if 'error' not in web_results and web_results.get('matches'):
            report['findings'].append({
                'type': 'web_servers',
                'count': len(web_results['matches']),
                'sample_hosts': [match['ip_str'] for match in web_results['matches'][:5]]
            })

        # 3. Анализ уязвимостей если требуется
        if include_vulnerabilities:
            vuln_analysis = self.analyze_vulnerabilities(org_query, max_results=50)
            report['vulnerabilities'] = vuln_analysis

            # Генерация рекомендаций
            self._generate_recommendations(report)

        return report

    def _analyze_services(self, results: Dict) -> Dict[str, int]:
        """Анализ сервисов из результатов поиска"""
        services = {}

        for match in results.get('matches', []):
            port = match.get('port')
            product = match.get('product', 'unknown')

            key = f"{port}/{product}" if product else str(port)
            services[key] = services.get(key, 0) + 1

        return dict(sorted(services.items(), key=lambda x: x[1], reverse=True)[:10])

    def _generate_recommendations(self, report: Dict):
        """Генерация рекомендаций на основе анализа"""
        vulns = report.get('vulnerabilities', {})
        severity_counts = vulns.get('severity_counts', {})

        recommendations = []

        if severity_counts.get('critical', 0) > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Немедленно закройте критические уязвимости',
                'details': f'Найдено {severity_counts["critical"]} критических уязвимостей'
            })

        if severity_counts.get('high', 0) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Приоритетное исправление высокоуровневых уязвимостей',
                'details': f'Найдено {severity_counts["high"]} высокоуровневых уязвимостей'
            })

        if report['summary'].get('total_hosts', 0) > 50:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Проведите инвентаризацию инфраструктуры',
                'details': 'Обнаружено большое количество хостов, требуется полная инвентаризация'
            })

        report['recommendations'] = recommendations


def main():
    """Тестовая функция для проверки интеграции"""
    try:
        shodan_api = ShodanAPI()

        # Тестовый поиск
        print("\n=== Тестовый поиск в Shodan ===")
        test_query = "org:\"example.com\""
        results = shodan_api.search(test_query, max_results=5)

        print(f"Найдено хостов: {results.get('total', 0)}")

        # Тестовый анализ уязвимостей
        print("\n=== Анализ уязвимостей ===")
        vuln_analysis = shodan_api.analyze_vulnerabilities(test_query, max_results=10)

        if 'error' not in vuln_analysis:
            print(f"Всего хостов с уязвимостями: {len(vuln_analysis.get('vulnerable_hosts', []))}")
            print(f"Критические уязвимости: {vuln_analysis.get('severity_counts', {}).get('critical', 0)}")

        # Тестовая генерация отчета
        print("\n=== Генерация OSINT отчета ===")
        report = shodan_api.generate_osint_report("example.com")

        print(f"Отчет сгенерирован для: {report['target']}")
        print(f"Всего хостов: {report['summary'].get('total_hosts', 0)}")
        print(f"Рекомендаций: {len(report['recommendations'])}")

        # Сохранение отчета в файл
        with open('example_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print("Отчет сохранен в example_report.json")

    except Exception as e:
        print(f"Ошибка при тестировании: {e}")


if __name__ == "__main__":
    main()
