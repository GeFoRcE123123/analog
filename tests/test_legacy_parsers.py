"""
Тесты для legacy парсеров из папки pars/
Проверка парсеров: RedHat, Debian, Cisco, Cert, FortiGuard, IBM, и т.д.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from tests.conftest import (
    mock_vulnerability_repo,
    sample_html_content,
    mock_requests_get,
    parser_output_validator
)


class TestLegacyParserBase:
    """Базовые тесты для legacy парсеров"""
    
    def test_base_parser_initialization(self, mock_vulnerability_repo):
        """Проверка инициализации базового парсера"""
        try:
            from services.legacy_parsers.base_legacy_parser import BaseLegacyParser
            
            class TestParser(BaseLegacyParser):
                def parse(self, **kwargs):
                    return {'parsed': 0, 'saved': 0, 'errors': []}
            
            parser = TestParser("TestParser", mock_vulnerability_repo)
            assert parser.name == "TestParser"
            assert parser.vulnerability_repo == mock_vulnerability_repo
        except ImportError:
            pytest.skip("BaseLegacyParser не доступен")
    
    def test_create_vulnerability(self, mock_vulnerability_repo):
        """Проверка создания объекта Vulnerability"""
        try:
            from services.legacy_parsers.base_legacy_parser import BaseLegacyParser
            
            class TestParser(BaseLegacyParser):
                def parse(self, **kwargs):
                    return {'parsed': 0, 'saved': 0, 'errors': []}
            
            parser = TestParser("TestParser", mock_vulnerability_repo)
            vuln = parser._create_vulnerability(
                cve_id="CVE-2024-0001",
                title="Test Vulnerability",
                description="Test description",
                cvss_score=7.5,
                source="test",
                link="https://example.com"
            )
            
            assert vuln.cve_id == "CVE-2024-0001"
            assert vuln.title == "Test Vulnerability"
            assert vuln.cvss_score == 7.5
            assert vuln.severity in ['critical', 'high', 'medium', 'low']
        except ImportError:
            pytest.skip("BaseLegacyParser не доступен")


class TestRedHatLegacyParser:
    """Тесты для RedHat legacy парсера"""
    
    def test_redhat_parser_initialization(self, mock_vulnerability_repo):
        """Проверка инициализации RedHat парсера"""
        try:
            from services.legacy_parsers.redhat_parser import RedHatParser
            parser = RedHatParser(mock_vulnerability_repo)
            assert parser.name == "RedHat"
        except ImportError:
            pytest.skip("RedHatParser не доступен")
    
    def test_redhat_parser_output(self, mock_vulnerability_repo, parser_output_validator):
        """Проверка выходных данных RedHat парсера"""
        try:
            from services.legacy_parsers.redhat_parser import RedHatParser
            parser = RedHatParser(mock_vulnerability_repo)
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = sample_html_content
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response
                
                result = parser.parse(limit=10)
                
                # Проверяем структуру результата
                assert 'parsed' in result
                assert 'saved' in result
                assert 'errors' in result
        except ImportError:
            pytest.skip("RedHatParser не доступен")


class TestCiscoLegacyParser:
    """Тесты для Cisco legacy парсера"""
    
    def test_cisco_parser_initialization(self, mock_vulnerability_repo):
        """Проверка инициализации Cisco парсера"""
        try:
            from services.legacy_parsers.cisco_parser import CiscoParser
            parser = CiscoParser(mock_vulnerability_repo)
            assert parser.name == "Cisco"
        except ImportError:
            pytest.skip("CiscoParser не доступен")
    
    def test_cisco_parser_rss_parsing(self, mock_vulnerability_repo):
        """Проверка парсинга RSS feed Cisco"""
        try:
            from services.legacy_parsers.cisco_parser import CiscoParser
            parser = CiscoParser(mock_vulnerability_repo)
            
            rss_xml = """<?xml version="1.0"?>
            <rss>
                <channel>
                    <item>
                        <title>Cisco Advisory</title>
                        <description>CVE-2024-0001: Test vulnerability</description>
                        <link>https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20240001</link>
                    </item>
                </channel>
            </rss>
            """
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = rss_xml
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response
                
                result = parser.parse(limit=10)
                
                assert 'parsed' in result
                assert 'saved' in result
        except ImportError:
            pytest.skip("CiscoParser не доступен")


class TestDebianLegacyParser:
    """Тесты для Debian legacy парсера"""
    
    def test_debian_parser_initialization(self, mock_vulnerability_repo):
        """Проверка инициализации Debian парсера"""
        try:
            from services.legacy_parsers.debian_parser import DebianParser
            parser = DebianParser(mock_vulnerability_repo)
            assert parser.name == "Debian"
        except ImportError:
            pytest.skip("DebianParser не доступен")


class TestLegacyParserErrorHandling:
    """Тесты для обработки ошибок в legacy парсерах"""
    
    def test_connection_error_handling(self, mock_vulnerability_repo):
        """Проверка обработки ошибок соединения"""
        try:
            from services.legacy_parsers.redhat_parser import RedHatParser
            parser = RedHatParser(mock_vulnerability_repo)
            
            with patch('requests.get') as mock_get:
                import requests
                mock_get.side_effect = requests.ConnectionError("Connection error")
                
                result = parser.parse(limit=10)
                
                # Парсер должен вернуть результат с ошибками
                assert 'errors' in result
                assert len(result['errors']) > 0 or result['parsed'] == 0
        except ImportError:
            pytest.skip("RedHatParser не доступен")
    
    def test_timeout_error_handling(self, mock_vulnerability_repo):
        """Проверка обработки таймаутов"""
        try:
            from services.legacy_parsers.redhat_parser import RedHatParser
            parser = RedHatParser(mock_vulnerability_repo)
            
            with patch('requests.get') as mock_get:
                import requests
                mock_get.side_effect = requests.Timeout("Request timeout")
                
                result = parser.parse(limit=10)
                
                # Парсер должен обработать таймаут
                assert 'errors' in result or result['parsed'] == 0
        except ImportError:
            pytest.skip("RedHatParser не доступен")
    
    def test_invalid_html_handling(self, mock_vulnerability_repo):
        """Проверка обработки некорректного HTML"""
        try:
            from services.legacy_parsers.redhat_parser import RedHatParser
            parser = RedHatParser(mock_vulnerability_repo)
            
            invalid_html = "<html><body><div>Unclosed tags"
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = invalid_html
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response
                
                # BeautifulSoup должен обработать некорректный HTML
                result = parser.parse(limit=10)
                assert 'parsed' in result
        except ImportError:
            pytest.skip("RedHatParser не доступен")


class TestLegacyParserDataValidation:
    """Тесты для валидации данных legacy парсеров"""
    
    def test_cve_id_normalization(self, mock_vulnerability_repo):
        """Проверка нормализации CVE ID"""
        try:
            from services.legacy_parsers.base_legacy_parser import BaseLegacyParser
            
            class TestParser(BaseLegacyParser):
                def parse(self, **kwargs):
                    return {'parsed': 0, 'saved': 0, 'errors': []}
            
            parser = TestParser("TestParser", mock_vulnerability_repo)
            
            test_cases = [
                ("CVE-2024-0001", "CVE-2024-0001"),
                ("cve-2024-0001", "CVE-2024-0001"),
                ("CVE-2024-0001 description", "CVE-2024-0001"),
                ("Some text CVE-2024-0001 more text", "CVE-2024-0001"),
                ("invalid", None)
            ]
            
            for input_cve, expected in test_cases:
                result = parser._normalize_cve_id(input_cve)
                assert result == expected, f"Ожидалось {expected}, получено {result} для '{input_cve}'"
        except ImportError:
            pytest.skip("BaseLegacyParser не доступен")
    
    def test_cvss_extraction(self, mock_vulnerability_repo):
        """Проверка извлечения CVSS score из текста"""
        try:
            from services.legacy_parsers.base_legacy_parser import BaseLegacyParser
            
            class TestParser(BaseLegacyParser):
                def parse(self, **kwargs):
                    return {'parsed': 0, 'saved': 0, 'errors': []}
            
            parser = TestParser("TestParser", mock_vulnerability_repo)
            
            test_cases = [
                ("CVSS: 7.5", 7.5),
                ("Score: 9.0", 9.0),
                ("Base Score: 5.5", 5.5),
                ("No score", 0.0),
                ("", 0.0)
            ]
            
            for input_text, expected in test_cases:
                result = parser._extract_cvss_from_text(input_text)
                assert result == expected, f"Ожидалось {expected}, получено {result} для '{input_text}'"
        except ImportError:
            pytest.skip("BaseLegacyParser не доступен")

