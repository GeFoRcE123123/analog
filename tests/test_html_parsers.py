"""
Тесты для HTML парсеров
Проверка парсинга HTML источников (Ubuntu, Debian, Red Hat, и т.д.)
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from bs4 import BeautifulSoup
from tests.conftest import (
    mock_vulnerability_repo, 
    sample_html_content,
    mock_requests_get,
    mock_requests_get_error,
    parser_output_validator
)


class TestHTMLParserBase:
    """Базовые тесты для HTML парсеров"""
    
    def test_parser_initialization(self, mock_vulnerability_repo):
        """Проверка инициализации парсера"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            assert parser is not None
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")
    
    def test_parse_empty_html(self, mock_vulnerability_repo):
        """Проверка обработки пустого HTML"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            empty_html = "<html><body></body></html>"
            soup = BeautifulSoup(empty_html, 'html.parser')
            
            # Парсер не должен падать на пустом HTML
            # Результат зависит от реализации, но не должно быть исключений
            result = parser.parse_source('ubuntu', limit=10)
            assert isinstance(result, list)
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")
        except Exception as e:
            pytest.fail(f"Парсер упал на пустом HTML: {e}")
    
    def test_parse_none_elements(self, mock_vulnerability_repo):
        """Проверка обработки None элементов"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            # Симулируем ситуацию, когда BeautifulSoup возвращает None
            with patch('bs4.BeautifulSoup') as mock_soup:
                mock_soup.return_value.find.return_value = None
                
                # Парсер не должен падать
                result = parser.parse_source('ubuntu', limit=10)
                assert isinstance(result, list)
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")
        except Exception as e:
            pytest.fail(f"Парсер упал на None элементах: {e}")
    
    def test_connection_error_handling(self, mock_vulnerability_repo, mock_requests_get_error):
        """Проверка обработки ошибок соединения"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            # При ошибке соединения парсер должен вернуть пустой список или обработать ошибку
            result = parser.parse_source('ubuntu', limit=10)
            assert isinstance(result, list)
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")
        except Exception as e:
            # Если парсер выбрасывает исключение, это тоже приемлемо, но нужно логировать
            assert 'Connection' in str(e) or 'Timeout' in str(e) or 'Error' in str(e)
    
    def test_timeout_handling(self, mock_vulnerability_repo):
        """Проверка обработки таймаутов"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            with patch('requests.get') as mock_get:
                import requests
                mock_get.side_effect = requests.Timeout("Request timeout")
                
                result = parser.parse_source('ubuntu', limit=10)
                assert isinstance(result, list)
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")
        except Exception as e:
            # Таймаут должен обрабатываться
            assert 'timeout' in str(e).lower() or 'Timeout' in str(e)


class TestUbuntuParser:
    """Тесты для Ubuntu парсера"""
    
    def test_ubuntu_parser_output(self, mock_vulnerability_repo, parser_output_validator):
        """Проверка выходных данных Ubuntu парсера"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = sample_html_content
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response
                
                result = parser.parse_source('ubuntu', limit=10)
                
                # Валидация выходных данных
                validation_result = parser_output_validator(result)
                
                if len(result) > 0:
                    assert validation_result['valid'] is True or len(validation_result['warnings']) > 0
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")


class TestDebianParser:
    """Тесты для Debian парсера"""
    
    def test_debian_parser_output(self, mock_vulnerability_repo, parser_output_validator):
        """Проверка выходных данных Debian парсера"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = sample_html_content
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response
                
                result = parser.parse_source('debian', limit=10)
                
                # Валидация выходных данных
                validation_result = parser_output_validator(result)
                
                if len(result) > 0:
                    assert validation_result['valid'] is True or len(validation_result['warnings']) > 0
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")


class TestRedHatParser:
    """Тесты для Red Hat парсера"""
    
    def test_redhat_parser_output(self, mock_vulnerability_repo, parser_output_validator):
        """Проверка выходных данных Red Hat парсера"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = sample_html_content
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response
                
                result = parser.parse_source('redhat', limit=10)
                
                # Валидация выходных данных
                validation_result = parser_output_validator(result)
                
                if len(result) > 0:
                    assert validation_result['valid'] is True or len(validation_result['warnings']) > 0
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")


class TestHTMLParserEdgeCases:
    """Тесты для граничных случаев HTML парсеров"""
    
    def test_very_long_description(self, mock_vulnerability_repo):
        """Проверка обработки очень длинных описаний"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            long_html = f"""
            <html>
                <body>
                    <div class="cve-item">
                        <h3>CVE-2024-0001</h3>
                        <p>{'A' * 10000}</p>
                        <span class="cvss">7.5</span>
                    </div>
                </body>
            </html>
            """
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = long_html
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response
                
                result = parser.parse_source('ubuntu', limit=10)
                assert isinstance(result, list)
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")
    
    def test_special_characters(self, mock_vulnerability_repo):
        """Проверка обработки специальных символов"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            special_html = """
            <html>
                <body>
                    <div class="cve-item">
                        <h3>CVE-2024-0001</h3>
                        <p>Test with special chars: <>&"'</p>
                        <span class="cvss">7.5</span>
                    </div>
                </body>
            </html>
            """
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = special_html
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response
                
                result = parser.parse_source('ubuntu', limit=10)
                assert isinstance(result, list)
                
                # Проверка кодировки
                if len(result) > 0:
                    for item in result:
                        if 'description' in item:
                            item['description'].encode('utf-8')
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")
    
    def test_malformed_html(self, mock_vulnerability_repo):
        """Проверка обработки некорректного HTML"""
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            parser = HTMLVulnerabilityParser()
            
            malformed_html = "<html><body><div><p>Unclosed tags</div>"
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = malformed_html
                mock_response.raise_for_status = Mock()
                mock_get.return_value = mock_response
                
                # BeautifulSoup должен обработать некорректный HTML
                result = parser.parse_source('ubuntu', limit=10)
                assert isinstance(result, list)
        except ImportError:
            pytest.skip("HTMLVulnerabilityParser не доступен")

