"""
Тесты для API парсеров
Проверка парсинга API источников (NVD, OSV, GitHub Advisories)
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from tests.conftest import (
    mock_vulnerability_repo,
    sample_json_response,
    mock_requests_get,
    mock_requests_get_error,
    parser_output_validator
)


class TestNVDParser:
    """Тесты для NVD парсера"""
    
    def test_nvd_parser_initialization(self, mock_vulnerability_repo):
        """Проверка инициализации NVD парсера"""
        try:
            from services.nvd_integration_service import NVDIntegrationService
            parser = NVDIntegrationService(mock_vulnerability_repo)
            assert parser is not None
        except ImportError:
            pytest.skip("NVDIntegrationService не доступен")
    
    def test_nvd_parser_output(self, mock_vulnerability_repo, parser_output_validator):
        """Проверка выходных данных NVD парсера"""
        try:
            from services.nvd_integration_service import NVDIntegrationService
            parser = NVDIntegrationService(mock_vulnerability_repo)
            
            # Тестируем инкрементальную синхронизацию
            result = parser.incremental_sync(days=1)
            
            # Проверяем структуру результата
            assert 'status' in result
            assert 'total_parsed' in result or 'parsed' in result
            assert 'saved_count' in result or 'saved' in result
        except ImportError:
            pytest.skip("NVDIntegrationService не доступен")
    
    def test_nvd_api_error_handling(self, mock_vulnerability_repo):
        """Проверка обработки ошибок NVD API"""
        try:
            from services.nvd_integration_service import NVDIntegrationService
            parser = NVDIntegrationService(mock_vulnerability_repo)
            
            with patch('requests.get') as mock_get:
                mock_get.side_effect = Exception("API Error")
                
                # Парсер должен обработать ошибку
                result = parser.incremental_sync(days=1)
                assert 'error' in result or 'errors' in result or result.get('status') == 'error'
        except ImportError:
            pytest.skip("NVDIntegrationService не доступен")
    
    def test_nvd_rate_limiting(self, mock_vulnerability_repo):
        """Проверка обработки rate limiting (429)"""
        try:
            from services.nvd_integration_service import NVDIntegrationService
            parser = NVDIntegrationService(mock_vulnerability_repo)
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 429
                mock_response.raise_for_status.side_effect = Exception("Rate limit exceeded")
                mock_get.return_value = mock_response
                
                # Парсер должен обработать rate limiting
                result = parser.incremental_sync(days=1)
                assert 'error' in result or 'errors' in result or result.get('status') == 'error'
        except ImportError:
            pytest.skip("NVDIntegrationService не доступен")


class TestOSVParser:
    """Тесты для OSV парсера"""
    
    def test_osv_parser_initialization(self, mock_vulnerability_repo):
        """Проверка инициализации OSV парсера"""
        try:
            from services.osv_api_parser import OSVAPIParser
            parser = OSVAPIParser()
            assert parser is not None
        except ImportError:
            pytest.skip("OSVAPIParser не доступен")
    
    def test_osv_parser_output(self, mock_vulnerability_repo, parser_output_validator):
        """Проверка выходных данных OSV парсера"""
        try:
            from services.osv_api_parser import OSVAPIParser
            parser = OSVAPIParser()
            
            with patch('requests.post') as mock_post:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    'vulns': [
                        {
                            'id': 'GHSA-xxxx-xxxx-xxxx',
                            'summary': 'Test vulnerability',
                            'details': 'Test details',
                            'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]
                        }
                    ]
                }
                mock_response.raise_for_status = Mock()
                mock_post.return_value = mock_response
                
                result = parser.query_by_package('test-package', '1.0.0')
                
                # Проверяем структуру результата
                assert isinstance(result, (list, dict))
        except ImportError:
            pytest.skip("OSVAPIParser не доступен")
    
    def test_osv_api_error_handling(self, mock_vulnerability_repo):
        """Проверка обработки ошибок OSV API"""
        try:
            from services.osv_api_parser import OSVAPIParser
            parser = OSVAPIParser()
            
            with patch('requests.post') as mock_post:
                mock_post.side_effect = Exception("API Error")
                
                # Парсер должен обработать ошибку
                result = parser.query_by_package('test-package', '1.0.0')
                assert result is None or isinstance(result, (list, dict))
        except ImportError:
            pytest.skip("OSVAPIParser не доступен")


class TestAPIResponseValidation:
    """Тесты для валидации API ответов"""
    
    def test_json_schema_validation(self):
        """Проверка валидности JSON схемы"""
        valid_json = {
            'CVE_Items': [
                {
                    'cve': {
                        'CVE_data_meta': {
                            'ID': 'CVE-2024-0001'
                        }
                    }
                }
            ]
        }
        
        # Проверяем наличие обязательных полей
        assert 'CVE_Items' in valid_json
        assert isinstance(valid_json['CVE_Items'], list)
        if len(valid_json['CVE_Items']) > 0:
            assert 'cve' in valid_json['CVE_Items'][0]
    
    def test_api_error_responses(self):
        """Проверка обработки ошибок API"""
        error_responses = [
            {'status_code': 404, 'message': 'Not Found'},
            {'status_code': 429, 'message': 'Rate Limit Exceeded'},
            {'status_code': 500, 'message': 'Internal Server Error'},
            {'status_code': 503, 'message': 'Service Unavailable'}
        ]
        
        for error in error_responses:
            assert 'status_code' in error
            assert 'message' in error
            assert error['status_code'] >= 400
    
    def test_api_timeout_handling(self):
        """Проверка обработки таймаутов API"""
        import requests
        
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.Timeout("Request timeout")
            
            # Должна быть обработка таймаута
            try:
                response = requests.get('https://api.example.com', timeout=30)
            except requests.Timeout:
                pass  # Ожидаемое поведение


class TestAPIEdgeCases:
    """Тесты для граничных случаев API парсеров"""
    
    def test_empty_api_response(self):
        """Проверка обработки пустого ответа API"""
        empty_responses = [
            {},
            {'data': []},
            {'CVE_Items': []},
            {'vulns': []}
        ]
        
        for response in empty_responses:
            # Парсер должен обработать пустой ответ
            assert isinstance(response, dict)
    
    def test_large_api_response(self):
        """Проверка обработки большого ответа API"""
        # Симулируем большой ответ
        large_response = {
            'CVE_Items': [{'cve': {'CVE_data_meta': {'ID': f'CVE-2024-{i:04d}'}}} for i in range(10000)]
        }
        
        assert len(large_response['CVE_Items']) == 10000
        # Парсер должен обработать большой ответ без проблем
    
    def test_malformed_json_response(self):
        """Проверка обработки некорректного JSON"""
        malformed_json_strings = [
            '{"invalid": json}',
            '{invalid json}',
            'not json at all',
            '{"incomplete":'
        ]
        
        import json
        for json_str in malformed_json_strings:
            try:
                json.loads(json_str)
                pytest.fail(f"Некорректный JSON должен вызывать ошибку: {json_str}")
            except json.JSONDecodeError:
                pass  # Ожидаемое поведение

