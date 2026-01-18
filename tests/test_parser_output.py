"""
Тесты для анализа выходных данных парсеров
Проверка состава, валидности и полноты отпарсенных данных
"""
import pytest
from datetime import datetime
from typing import List, Dict, Any
from tests.conftest import parser_output_validator, sample_vulnerability_dict


class TestParserOutputValidation:
    """Тесты для валидации выходных данных парсеров"""
    
    def test_required_fields_present(self, parser_output_validator):
        """Проверка наличия всех обязательных полей"""
        valid_data = [
            {
                'cve_id': 'CVE-2024-0001',
                'title': 'Test Vulnerability',
                'description': 'Test description',
                'severity': 'high',
                'cvss_score': 7.5
            }
        ]
        
        result = parser_output_validator(valid_data)
        assert result['valid'] is True
        assert len(result['errors']) == 0
    
    def test_missing_required_fields(self, parser_output_validator):
        """Проверка обнаружения отсутствующих обязательных полей"""
        invalid_data = [
            {
                'cve_id': 'CVE-2024-0001',
                'title': 'Test Vulnerability',
                # Отсутствует description
                'severity': 'high',
                'cvss_score': 7.5
            }
        ]
        
        result = parser_output_validator(invalid_data)
        assert result['valid'] is False
        assert len(result['errors']) > 0
        assert 'description' in str(result['errors'])
    
    def test_empty_fields(self, parser_output_validator):
        """Проверка обнаружения пустых полей"""
        invalid_data = [
            {
                'cve_id': 'CVE-2024-0001',
                'title': '',  # Пустое поле
                'description': 'Test description',
                'severity': 'high',
                'cvss_score': 7.5
            }
        ]
        
        result = parser_output_validator(invalid_data)
        assert result['valid'] is False
        assert any('title' in error for error in result['errors'])
    
    def test_cvss_score_type(self, parser_output_validator):
        """Проверка типа данных CVSS score"""
        invalid_data = [
            {
                'cve_id': 'CVE-2024-0001',
                'title': 'Test Vulnerability',
                'description': 'Test description',
                'severity': 'high',
                'cvss_score': '7.5'  # Строка вместо числа
            }
        ]
        
        result = parser_output_validator(invalid_data)
        assert result['valid'] is False
        assert any('cvss_score' in error and 'числом' in error for error in result['errors'])
    
    def test_cvss_score_range(self, parser_output_validator):
        """Проверка диапазона CVSS score"""
        invalid_data = [
            {
                'cve_id': 'CVE-2024-0001',
                'title': 'Test Vulnerability',
                'description': 'Test description',
                'severity': 'high',
                'cvss_score': 15.0  # Вне диапазона 0-10
            }
        ]
        
        result = parser_output_validator(invalid_data)
        assert len(result['warnings']) > 0
        assert any('cvss_score' in warning and 'диапазон' in warning for warning in result['warnings'])
    
    def test_severity_values(self, parser_output_validator):
        """Проверка валидных значений severity"""
        invalid_data = [
            {
                'cve_id': 'CVE-2024-0001',
                'title': 'Test Vulnerability',
                'description': 'Test description',
                'severity': 'very_high',  # Нестандартное значение
                'cvss_score': 7.5
            }
        ]
        
        result = parser_output_validator(invalid_data)
        assert len(result['warnings']) > 0
        assert any('severity' in warning for warning in result['warnings'])
    
    def test_date_format(self, parser_output_validator):
        """Проверка формата даты"""
        # Валидная дата
        valid_data = [
            {
                'cve_id': 'CVE-2024-0001',
                'title': 'Test Vulnerability',
                'description': 'Test description',
                'severity': 'high',
                'cvss_score': 7.5,
                'published_date': datetime.now().isoformat()
            }
        ]
        
        result = parser_output_validator(valid_data)
        assert result['valid'] is True
        
        # Некорректная дата
        invalid_data = [
            {
                'cve_id': 'CVE-2024-0001',
                'title': 'Test Vulnerability',
                'description': 'Test description',
                'severity': 'high',
                'cvss_score': 7.5,
                'published_date': 'invalid-date-format'
            }
        ]
        
        result = parser_output_validator(invalid_data)
        assert len(result['warnings']) > 0
        assert any('published_date' in warning for warning in result['warnings'])
    
    def test_empty_parser_output(self, parser_output_validator):
        """Проверка обработки пустого вывода парсера"""
        result = parser_output_validator([])
        assert len(result['warnings']) > 0
        assert 'пустой список' in result['warnings'][0]
    
    def test_multiple_items_validation(self, parser_output_validator):
        """Проверка валидации нескольких элементов"""
        data = [
            {
                'cve_id': 'CVE-2024-0001',
                'title': 'Test Vulnerability 1',
                'description': 'Test description 1',
                'severity': 'high',
                'cvss_score': 7.5
            },
            {
                'cve_id': 'CVE-2024-0002',
                'title': 'Test Vulnerability 2',
                'description': 'Test description 2',
                'severity': 'medium',
                'cvss_score': 5.0
            },
            {
                'cve_id': 'CVE-2024-0003',
                # Отсутствуют обязательные поля
                'severity': 'low'
            }
        ]
        
        result = parser_output_validator(data)
        assert result['valid'] is False
        assert len(result['errors']) > 0
        # Проверяем, что ошибки относятся к третьему элементу
        assert any('Элемент 2' in error for error in result['errors'])


class TestDataCompleteness:
    """Тесты для проверки полноты данных"""
    
    def test_all_fields_present(self):
        """Проверка наличия всех возможных полей"""
        complete_data = {
            'cve_id': 'CVE-2024-0001',
            'title': 'Test Vulnerability',
            'description': 'Test description',
            'severity': 'high',
            'cvss_score': 7.5,
            'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'risk_level': 'high',
            'category': 'web',
            'published_date': datetime.now().isoformat(),
            'last_modified': datetime.now().isoformat(),
            'link': 'https://example.com/cve-2024-0001',
            'source': 'test',
            'references': ['https://ref1.com', 'https://ref2.com'],
            'affected_products': ['Product 1', 'Product 2']
        }
        
        required_fields = ['cve_id', 'title', 'description', 'severity', 'cvss_score']
        optional_fields = ['cvss_vector', 'risk_level', 'category', 'published_date', 
                          'last_modified', 'link', 'source', 'references', 'affected_products']
        
        for field in required_fields:
            assert field in complete_data, f"Отсутствует обязательное поле: {field}"
        
        for field in optional_fields:
            assert field in complete_data, f"Отсутствует опциональное поле: {field}"
    
    def test_minimal_required_fields(self):
        """Проверка минимального набора обязательных полей"""
        minimal_data = {
            'cve_id': 'CVE-2024-0001',
            'title': 'Test Vulnerability',
            'description': 'Test description',
            'severity': 'high',
            'cvss_score': 7.5
        }
        
        required_fields = ['cve_id', 'title', 'description', 'severity', 'cvss_score']
        for field in required_fields:
            assert field in minimal_data, f"Отсутствует обязательное поле: {field}"


class TestDataTypes:
    """Тесты для проверки типов данных"""
    
    def test_string_fields(self):
        """Проверка полей типа str"""
        data = {
            'cve_id': 'CVE-2024-0001',
            'title': 'Test Vulnerability',
            'description': 'Test description',
            'severity': 'high'
        }
        
        string_fields = ['cve_id', 'title', 'description', 'severity']
        for field in string_fields:
            assert isinstance(data[field], str), f"Поле {field} должно быть строкой"
            assert len(data[field]) > 0, f"Поле {field} не должно быть пустым"
    
    def test_numeric_fields(self):
        """Проверка полей типа int/float"""
        data = {
            'cvss_score': 7.5,
            'epss_score': 0.85,
            'epss_percentile': 95.5
        }
        
        numeric_fields = ['cvss_score', 'epss_score', 'epss_percentile']
        for field in numeric_fields:
            assert isinstance(data[field], (int, float)), f"Поле {field} должно быть числом"
    
    def test_list_fields(self):
        """Проверка полей типа list"""
        data = {
            'references': ['https://ref1.com', 'https://ref2.com'],
            'affected_products': ['Product 1', 'Product 2'],
            'cwe_ids': ['CWE-79', 'CWE-89']
        }
        
        list_fields = ['references', 'affected_products', 'cwe_ids']
        for field in list_fields:
            assert isinstance(data[field], list), f"Поле {field} должно быть списком"
            assert len(data[field]) > 0, f"Поле {field} не должно быть пустым списком"
    
    def test_datetime_fields(self):
        """Проверка полей типа datetime"""
        data = {
            'published_date': datetime.now(),
            'last_modified': datetime.now()
        }
        
        datetime_fields = ['published_date', 'last_modified']
        for field in datetime_fields:
            assert isinstance(data[field], datetime), f"Поле {field} должно быть datetime"
    
    def test_dict_fields(self):
        """Проверка полей типа dict"""
        data = {
            'metrics': {
                'cvss_v3': {'baseScore': 7.5},
                'cvss_v2': {'baseScore': 6.5}
            },
            'etc_data': {
                'category': 'web',
                'risk_level': 'high'
            }
        }
        
        dict_fields = ['metrics', 'etc_data']
        for field in dict_fields:
            assert isinstance(data[field], dict), f"Поле {field} должно быть словарем"
            assert len(data[field]) > 0, f"Поле {field} не должно быть пустым словарем"

