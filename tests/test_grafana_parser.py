"""
Тесты для парсера Grafana Security Advisories
"""

import unittest
from unittest.mock import Mock, patch
import sys
from pathlib import Path

# Добавить корневую директорию в PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.parsers.grafana_parser import GrafanaSecurityParser
from services.parsers.grafana_mapper import GrafanaDataMapper


class TestGrafanaParser(unittest.TestCase):
    """Тесты для GrafanaSecurityParser"""
    
    def setUp(self):
        """Инициализация перед каждым тестом"""
        self.parser = GrafanaSecurityParser(cache_enabled=False, rate_limit_delay=0.1)
    
    def test_parse_severity(self):
        """Тест парсинга severity"""
        # Критический
        result = self.parser.parse_severity("● Critical (9.1)")
        self.assertEqual(result['level'], 'Critical')
        self.assertEqual(result['score'], 9.1)
        
        # Высокий
        result = self.parser.parse_severity("● High (7.5)")
        self.assertEqual(result['level'], 'High')
        self.assertEqual(result['score'], 7.5)
        
        # Средний
        result = self.parser.parse_severity("● Medium (5.0)")
        self.assertEqual(result['level'], 'Medium')
        self.assertEqual(result['score'], 5.0)
        
        # Низкий
        result = self.parser.parse_severity("● Low (2.1)")
        self.assertEqual(result['level'], 'Low')
        self.assertEqual(result['score'], 2.1)
        
        # Пустая строка
        result = self.parser.parse_severity("")
        self.assertEqual(result['level'], 'UNKNOWN')
        self.assertIsNone(result['score'])


class TestGrafanaMapper(unittest.TestCase):
    """Тесты для GrafanaDataMapper"""
    
    def setUp(self):
        """Инициализация перед каждым тестом"""
        self.mapper = GrafanaDataMapper()
    
    def test_parse_severity(self):
        """Тест парсинга severity"""
        result = self.mapper._parse_severity("● Critical (9.1)")
        self.assertEqual(result['level'], 'Critical')
        self.assertEqual(result['score'], 9.1)
    
    def test_map_severity(self):
        """Тест маппинга severity"""
        self.assertEqual(self.mapper._map_severity('critical'), 'CRITICAL')
        self.assertEqual(self.mapper._map_severity('Critical'), 'CRITICAL')
        self.assertEqual(self.mapper._map_severity('high'), 'HIGH')
        self.assertEqual(self.mapper._map_severity('medium'), 'MEDIUM')
        self.assertEqual(self.mapper._map_severity('low'), 'LOW')
        self.assertEqual(self.mapper._map_severity(''), 'UNKNOWN')
    
    def test_calculate_severity_from_score(self):
        """Тест определения severity по score"""
        self.assertEqual(self.mapper._calculate_severity_from_score(9.5), 'CRITICAL')
        self.assertEqual(self.mapper._calculate_severity_from_score(9.0), 'CRITICAL')
        self.assertEqual(self.mapper._calculate_severity_from_score(8.5), 'HIGH')
        self.assertEqual(self.mapper._calculate_severity_from_score(7.0), 'HIGH')
        self.assertEqual(self.mapper._calculate_severity_from_score(5.5), 'MEDIUM')
        self.assertEqual(self.mapper._calculate_severity_from_score(4.0), 'MEDIUM')
        self.assertEqual(self.mapper._calculate_severity_from_score(2.5), 'LOW')
    
    def test_detect_software_type(self):
        """Тест определения типа ПО"""
        self.assertEqual(
            self.mapper._detect_software_type('Grafana'),
            'Прикладное ПО'
        )
        self.assertEqual(
            self.mapper._detect_software_type('Grafana Databricks Plugin'),
            'Плагин'
        )
        self.assertEqual(
            self.mapper._detect_software_type('Grafana Image Renderer'),
            'Компонент'
        )
        self.assertEqual(
            self.mapper._detect_software_type('Pyroscope'),
            'Прикладное ПО'
        )
    
    def test_parse_cvss_vector(self):
        """Тест парсинга CVSS вектора"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        score = 9.1
        
        result = self.mapper._parse_cvss_vector(vector, score)
        
        self.assertEqual(result['version'], '3.1')
        self.assertEqual(result['vectorString'], vector)
        self.assertEqual(result['baseScore'], 9.1)
        self.assertEqual(result['baseSeverity'], 'CRITICAL')
        self.assertEqual(result['attackVector'], 'NETWORK')
        self.assertEqual(result['attackComplexity'], 'LOW')
        self.assertEqual(result['privilegesRequired'], 'NONE')
        self.assertEqual(result['userInteraction'], 'NONE')
        self.assertEqual(result['scope'], 'UNCHANGED')
        self.assertEqual(result['confidentialityImpact'], 'HIGH')
        self.assertEqual(result['integrityImpact'], 'HIGH')
        self.assertEqual(result['availabilityImpact'], 'NONE')
    
    def test_expand_metric(self):
        """Тест расшифровки CVSS метрик"""
        # Attack Vector
        self.assertEqual(self.mapper._expand_metric('AV', 'N'), 'NETWORK')
        self.assertEqual(self.mapper._expand_metric('AV', 'L'), 'LOCAL')
        
        # Attack Complexity
        self.assertEqual(self.mapper._expand_metric('AC', 'L'), 'LOW')
        self.assertEqual(self.mapper._expand_metric('AC', 'H'), 'HIGH')
        
        # Privileges Required
        self.assertEqual(self.mapper._expand_metric('PR', 'N'), 'NONE')
        self.assertEqual(self.mapper._expand_metric('PR', 'L'), 'LOW')
        
        # User Interaction
        self.assertEqual(self.mapper._expand_metric('UI', 'N'), 'NONE')
        self.assertEqual(self.mapper._expand_metric('UI', 'R'), 'REQUIRED')
    
    def test_format_affected_versions(self):
        """Тест форматирования версий"""
        # Пустой список
        result = self.mapper._format_affected_versions([])
        self.assertEqual(result, "Информация о версиях отсутствует")
        
        # Список строк
        versions = [">=1.15.2 <1.16.0", ">=1.16.1"]
        result = self.mapper._format_affected_versions(versions)
        self.assertIn("1.15.2", result)
        self.assertIn("1.16.1", result)
    
    def test_parse_date(self):
        """Тест парсинга дат"""
        from datetime import datetime
        
        # ISO формат
        result = self.mapper._parse_date("2026-01-02")
        self.assertIsInstance(result, datetime)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 2)
        
        # Пустая строка
        result = self.mapper._parse_date("")
        self.assertIsNone(result)
        
        # Дефис
        result = self.mapper._parse_date("—")
        self.assertIsNone(result)
        
        # None
        result = self.mapper._parse_date(None)
        self.assertIsNone(result)
    
    def test_map_to_db_format_basic(self):
        """Тест базового маппинга"""
        grafana_data = {
            'cve_id': 'CVE-2025-41118',
            'advisory_title': 'Test Advisory',
            'product': 'Grafana',
            'severity_text': '● High (7.5)',
            'summary': 'Test summary',
            'published_date': '2026-01-02'
        }
        
        db_data = self.mapper.map_to_db_format(grafana_data)
        
        # Проверить основные поля
        self.assertEqual(db_data['cve_id'], 'CVE-2025-41118')
        self.assertEqual(db_data['title'], 'Test Advisory')
        self.assertEqual(db_data['vendor'], 'Grafana Labs')
        self.assertEqual(db_data['product_name'], 'Grafana')
        self.assertEqual(db_data['source'], 'grafana')
        self.assertEqual(db_data['severity'], 'HIGH')
        self.assertEqual(db_data['cvss_score'], 7.5)
        self.assertEqual(db_data['vuln_status'], 'PUBLISHED')
    
    def test_build_references(self):
        """Тест формирования ссылок"""
        grafana_data = {
            'cve_id': 'CVE-2025-41118',
            'credits': 'Thanks to researcher'
        }
        
        refs = self.mapper._build_references(grafana_data)
        
        # Должно быть 2 ссылки
        self.assertEqual(len(refs), 2)
        
        # Первая ссылка - advisory
        self.assertEqual(refs[0]['type'], 'vendor_advisory')
        self.assertIn('cve-2025-41118', refs[0]['url'])
        
        # Вторая ссылка - bug bounty
        self.assertEqual(refs[1]['type'], 'bug_bounty')


class TestIntegration(unittest.TestCase):
    """Интеграционные тесты"""
    
    @unittest.skip("Requires network access")
    def test_fetch_real_advisories(self):
        """Тест получения реальных advisory (требует сеть)"""
        parser = GrafanaSecurityParser(cache_enabled=False, rate_limit_delay=1.0)
        
        # Получить список (только первые 5)
        advisories = parser.fetch_advisories_list()
        
        # Проверить что что-то получили
        self.assertGreater(len(advisories), 0)
        
        # Проверить структуру
        if advisories:
            adv = advisories[0]
            self.assertIn('cve_id', adv)
            self.assertIn('advisory_title', adv)
            self.assertIn('product', adv)


def run_tests():
    """Запустить все тесты"""
    # Создать test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Добавить тесты
    suite.addTests(loader.loadTestsFromTestCase(TestGrafanaParser))
    suite.addTests(loader.loadTestsFromTestCase(TestGrafanaMapper))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Запустить
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Вернуть результат
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)

