"""
Конфигурация и фикстуры для тестов парсеров
"""
import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any, List

# Добавляем корень проекта в путь
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from models.entities import Vulnerability
from models.legacy_repositories import LegacyVulnerabilityRepository
from datetime import datetime


@pytest.fixture
def mock_db_connection():
    """Мок соединения с БД"""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.__enter__ = Mock(return_value=mock_cursor)
    mock_cursor.__exit__ = Mock(return_value=None)
    mock_cursor.fetchone.return_value = None
    mock_cursor.fetchall.return_value = []
    return mock_conn


@pytest.fixture
def mock_vulnerability_repo(mock_db_connection):
    """Мок репозитория уязвимостей"""
    repo = LegacyVulnerabilityRepository(mock_db_connection)
    repo.save_vulnerability = Mock(return_value=True)
    repo.get_by_cve_id = Mock(return_value=None)
    repo.get_by_id = Mock(return_value=None)
    return repo


@pytest.fixture
def sample_vulnerability():
    """Пример уязвимости для тестов"""
    return Vulnerability(
        id=0,
        cve_id="CVE-2024-0001",
        title="Test Vulnerability",
        description="This is a test vulnerability description",
        severity="high",
        status="new",
        cvss_score=7.5,
        risk_level="high",
        category="web",
        source_identifier="test",
        created_date=datetime.now(),
        published=datetime.now()
    )


@pytest.fixture
def sample_vulnerability_dict():
    """Пример словаря с данными уязвимости"""
    return {
        'cve_id': 'CVE-2024-0001',
        'title': 'Test Vulnerability',
        'description': 'This is a test vulnerability description',
        'severity': 'high',
        'cvss_score': 7.5,
        'published_date': datetime.now().isoformat(),
        'link': 'https://example.com/cve-2024-0001',
        'source': 'test'
    }


@pytest.fixture
def sample_html_content():
    """Пример HTML контента для тестов"""
    return """
    <html>
        <body>
            <div class="cve-item">
                <h3>CVE-2024-0001</h3>
                <p>Test vulnerability description</p>
                <span class="cvss">7.5</span>
                <a href="https://example.com/cve-2024-0001">Link</a>
            </div>
        </body>
    </html>
    """


@pytest.fixture
def sample_json_response():
    """Пример JSON ответа для тестов"""
    return {
        'CVE_Items': [
            {
                'cve': {
                    'CVE_data_meta': {
                        'ID': 'CVE-2024-0001'
                    },
                    'description': {
                        'description_data': [
                            {
                                'value': 'Test vulnerability description',
                                'lang': 'en'
                            }
                        ]
                    }
                },
                'impact': {
                    'baseMetricV3': {
                        'cvssV3': {
                            'baseScore': 7.5
                        }
                    }
                },
                'publishedDate': '2024-01-01T00:00:00Z'
            }
        ]
    }


@pytest.fixture
def mock_requests_get():
    """Мок для requests.get"""
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '<html><body>Test</body></html>'
        mock_response.json.return_value = {'test': 'data'}
        mock_response.content = b'<html><body>Test</body></html>'
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        yield mock_get


@pytest.fixture
def mock_requests_get_error():
    """Мок для requests.get с ошибкой"""
    with patch('requests.get') as mock_get:
        mock_get.side_effect = Exception("Connection error")
        yield mock_get


@pytest.fixture
def parser_output_validator():
    """Валидатор для проверки выходных данных парсера"""
    def validate(parsed_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Валидация отпарсенных данных
        
        Returns:
            Dict с результатами валидации:
            - valid: bool - все данные валидны
            - errors: List[str] - список ошибок
            - warnings: List[str] - список предупреждений
            - missing_fields: Dict[str, List[int]] - отсутствующие поля по индексам
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'missing_fields': {}
        }
        
        required_fields = ['cve_id', 'title', 'description', 'severity', 'cvss_score']
        optional_fields = ['published_date', 'link', 'source', 'risk_level']
        
        if not parsed_data:
            result['warnings'].append('Парсер вернул пустой список')
            return result
        
        for idx, item in enumerate(parsed_data):
            # Проверка обязательных полей
            for field in required_fields:
                if field not in item:
                    result['valid'] = False
                    result['errors'].append(f"Элемент {idx}: отсутствует обязательное поле '{field}'")
                    if field not in result['missing_fields']:
                        result['missing_fields'][field] = []
                    result['missing_fields'][field].append(idx)
                elif item[field] is None or (isinstance(item[field], str) and not item[field].strip()):
                    result['valid'] = False
                    result['errors'].append(f"Элемент {idx}: поле '{field}' пустое или None")
            
            # Проверка типов данных
            if 'cvss_score' in item:
                if not isinstance(item['cvss_score'], (int, float)):
                    result['valid'] = False
                    result['errors'].append(f"Элемент {idx}: 'cvss_score' должен быть числом, получен {type(item['cvss_score'])}")
                elif item['cvss_score'] < 0 or item['cvss_score'] > 10:
                    result['warnings'].append(f"Элемент {idx}: 'cvss_score' вне диапазона 0-10: {item['cvss_score']}")
            
            if 'severity' in item:
                valid_severities = ['critical', 'high', 'medium', 'low', 'info']
                if item['severity'] not in valid_severities:
                    result['warnings'].append(f"Элемент {idx}: нестандартное значение severity: {item['severity']}")
            
            # Проверка формата даты
            if 'published_date' in item and item['published_date']:
                try:
                    if isinstance(item['published_date'], str):
                        datetime.fromisoformat(item['published_date'].replace('Z', '+00:00'))
                    elif isinstance(item['published_date'], datetime):
                        pass  # Уже datetime
                    else:
                        result['warnings'].append(f"Элемент {idx}: 'published_date' имеет неожиданный тип: {type(item['published_date'])}")
                except (ValueError, AttributeError):
                    result['warnings'].append(f"Элемент {idx}: 'published_date' имеет некорректный формат: {item['published_date']}")
            
            # Проверка кодировки
            for field in ['title', 'description']:
                if field in item and item[field]:
                    try:
                        item[field].encode('utf-8')
                    except UnicodeEncodeError:
                        result['warnings'].append(f"Элемент {idx}: поле '{field}' содержит некорректные символы")
        
        return result
    
    return validate


@pytest.fixture
def auto_fix_helper():
    """Хелпер для автоматического исправления ошибок"""
    def suggest_fix(error_type: str, error_message: str, file_path: str, line_number: int = None) -> Dict[str, Any]:
        """
        Предложение исправления на основе ошибки
        
        Returns:
            Dict с предложением исправления:
            - fix_type: str - тип исправления
            - code: str - исправленный код
            - description: str - описание исправления
        """
        fixes = {
            'AttributeError': {
                'pattern': "'NoneType' object has no attribute",
                'fix': "if element and element.text:",
                'description': "Добавить проверку на None перед доступом к атрибуту"
            },
            'KeyError': {
                'pattern': "key",
                'fix': "data.get('key', default_value)",
                'description': "Использовать .get() вместо прямого доступа к ключу"
            },
            'IndexError': {
                'pattern': "list index out of range",
                'fix': "if len(items) > index:",
                'description': "Добавить проверку длины списка перед доступом по индексу"
            },
            'ConnectionError': {
                'pattern': "Connection",
                'fix': "try:\n    response = requests.get(url, timeout=30)\nexcept (ConnectionError, TimeoutError):\n    return []",
                'description': "Добавить обработку ошибок соединения"
            }
        }
        
        for error, fix_info in fixes.items():
            if error in error_type or fix_info['pattern'] in error_message:
                return {
                    'fix_type': error,
                    'code': fix_info['fix'],
                    'description': fix_info['description'],
                    'file_path': file_path,
                    'line_number': line_number
                }
        
        return {
            'fix_type': 'unknown',
            'code': None,
            'description': f"Неизвестная ошибка: {error_type} - {error_message}",
            'file_path': file_path,
            'line_number': line_number
        }
    
    return suggest_fix

