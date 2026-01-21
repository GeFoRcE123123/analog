"""
Маппинг данных Grafana на структуру БД

Преобразует данные из Grafana Security Advisories в формат БД
с поддержкой БДУ ФСТЭК структуры
"""

from datetime import datetime
from typing import Dict, List, Optional
import re
import logging

logger = logging.getLogger(__name__)


class GrafanaDataMapper:
    """
    Маппер данных Grafana на структуру БД
    """
    
    @staticmethod
    def map_to_db_format(grafana_data: Dict) -> Dict:
        """
        Маппинг данных Grafana на структуру БД
        
        Args:
            grafana_data: Данные из парсера
        
        Returns:
            Dict для сохранения в БД
        """
        # Парсинг severity
        severity_info = GrafanaDataMapper._parse_severity(grafana_data.get('severity_text', ''))
        
        # Парсинг CVSS вектора
        cvss_metrics = GrafanaDataMapper._parse_cvss_vector(
            grafana_data.get('cvss_vector', ''),
            grafana_data.get('cvss_score') or severity_info.get('score')
        )
        
        # Формирование данных для БД
        db_data = {
            # Основные поля
            'cve_id': grafana_data['cve_id'],
            'title': grafana_data.get('advisory_title', ''),
            'description': grafana_data.get('summary', ''),
            
            # БДУ поля: Информация о ПО
            'vendor': 'Grafana Labs',
            'product_name': grafana_data.get('product', ''),
            'affected_versions': GrafanaDataMapper._format_affected_versions(
                grafana_data.get('fixed_versions', [])
            ),
            'software_type': GrafanaDataMapper._detect_software_type(
                grafana_data.get('product', '')
            ),
            
            # Оценка опасности
            'cvss_score': grafana_data.get('cvss_score') or severity_info.get('score'),
            'severity': GrafanaDataMapper._map_severity(severity_info.get('level', '')),
            'risk_level': GrafanaDataMapper._map_severity(severity_info.get('level', '')),
            'metrics': {
                'cvss_v3': cvss_metrics
            } if cvss_metrics else {},
            
            # Даты
            'published_date': GrafanaDataMapper._parse_date(grafana_data.get('published_date')),
            'last_modified_date': GrafanaDataMapper._parse_date(grafana_data.get('updated_date')),
            
            # БДУ поля: Устранение
            'remediation_method': 'Обновление ПО',
            'remediation_info': GrafanaDataMapper._format_remediation_info(grafana_data),
            'remediation_date': GrafanaDataMapper._parse_date(grafana_data.get('published_date')),
            
            # БДУ поля: Эксплуатация
            'exploit_available': False,  # Не указывается в Grafana advisory
            'exploitation_method': GrafanaDataMapper._extract_exploitation_method(
                grafana_data.get('summary', '')
            ),
            
            # Ссылки
            'references': GrafanaDataMapper._build_references(grafana_data),
            
            # Комментарии вендора
            'vendor_comments': {
                'credits': grafana_data.get('credits', ''),
                'source': 'Grafana Labs Security Advisory'
            },
            
            # Метаданные
            'source': 'grafana',
            'vuln_status': 'PUBLISHED'
        }
        
        return db_data
    
    @staticmethod
    def _parse_severity(severity_text: str) -> Dict:
        """Парсинг severity из текста: '● Critical (9.1)'"""
        if not severity_text:
            return {"level": "UNKNOWN", "score": None}
        
        match = re.search(r'(\w+)\s*\((\d+\.\d+)\)', severity_text)
        if match:
            return {
                "level": match.group(1),
                "score": float(match.group(2))
            }
        return {"level": "UNKNOWN", "score": None}
    
    @staticmethod
    def _map_severity(grafana_severity: str) -> str:
        """Маппинг severity на стандартные значения"""
        if not grafana_severity:
            return 'UNKNOWN'
        
        severity_map = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW'
        }
        return severity_map.get(grafana_severity.lower(), 'UNKNOWN')
    
    @staticmethod
    def _parse_cvss_vector(vector_string: str, score: Optional[float]) -> Dict:
        """Парсинг CVSS вектора"""
        if not vector_string:
            return {}
        
        try:
            parts = vector_string.split('/')
            version = parts[0].split(':')[1] if ':' in parts[0] else '3.1'
            
            metrics = {}
            for part in parts[1:]:
                if ':' in part:
                    key, value = part.split(':')
                    metrics[key] = value
            
            # Расшифровка метрик
            return {
                "version": version,
                "vectorString": vector_string,
                "baseScore": score,
                "baseSeverity": GrafanaDataMapper._calculate_severity_from_score(score) if score else None,
                "attackVector": GrafanaDataMapper._expand_metric('AV', metrics.get('AV')),
                "attackComplexity": GrafanaDataMapper._expand_metric('AC', metrics.get('AC')),
                "privilegesRequired": GrafanaDataMapper._expand_metric('PR', metrics.get('PR')),
                "userInteraction": GrafanaDataMapper._expand_metric('UI', metrics.get('UI')),
                "scope": GrafanaDataMapper._expand_metric('S', metrics.get('S')),
                "confidentialityImpact": GrafanaDataMapper._expand_metric('C', metrics.get('C')),
                "integrityImpact": GrafanaDataMapper._expand_metric('I', metrics.get('I')),
                "availabilityImpact": GrafanaDataMapper._expand_metric('A', metrics.get('A'))
            }
        except Exception as e:
            logger.error(f"Error parsing CVSS vector: {e}")
            return {}
    
    @staticmethod
    def _expand_metric(metric_name: str, value: str) -> str:
        """Расшифровка CVSS метрик"""
        if not value:
            return 'UNKNOWN'
        
        mappings = {
            'AV': {'N': 'NETWORK', 'A': 'ADJACENT_NETWORK', 'L': 'LOCAL', 'P': 'PHYSICAL'},
            'AC': {'L': 'LOW', 'H': 'HIGH'},
            'PR': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'},
            'UI': {'N': 'NONE', 'R': 'REQUIRED'},
            'S': {'U': 'UNCHANGED', 'C': 'CHANGED'},
            'C': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'},
            'I': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'},
            'A': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'}
        }
        return mappings.get(metric_name, {}).get(value, value)
    
    @staticmethod
    def _calculate_severity_from_score(score: float) -> str:
        """Определение severity по score"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @staticmethod
    def _detect_software_type(product_name: str) -> str:
        """Определение типа ПО"""
        if not product_name:
            return 'Прикладное ПО'
        
        product_lower = product_name.lower()
        
        if 'plugin' in product_lower:
            return 'Плагин'
        elif 'renderer' in product_lower:
            return 'Компонент'
        else:
            return 'Прикладное ПО'
    
    @staticmethod
    def _format_affected_versions(fixed_versions: List) -> str:
        """Форматирование информации о версиях"""
        if not fixed_versions:
            return "Информация о версиях отсутствует"
        
        versions_str = []
        for v in fixed_versions:
            if isinstance(v, dict):
                versions_str.append(v.get('range', str(v)))
            else:
                versions_str.append(str(v))
        
        return f"Исправлено в версиях: {', '.join(versions_str)}"
    
    @staticmethod
    def _format_remediation_info(grafana_data: Dict) -> str:
        """Форматирование информации об устранении"""
        parts = []
        
        if grafana_data.get('summary'):
            parts.append("## Описание уязвимости")
            parts.append(grafana_data['summary'])
            parts.append("")
        
        if grafana_data.get('fixed_versions'):
            parts.append("## Исправленные версии")
            for version in grafana_data['fixed_versions']:
                parts.append(f"- {version}")
            parts.append("")
        
        parts.append("## Рекомендации")
        parts.append("Рекомендуется обновить продукт до последней версии.")
        parts.append("")
        
        cve_id = grafana_data.get('cve_id', '').lower()
        parts.append("## Дополнительная информация")
        parts.append(f"Официальный advisory: https://grafana.com/security/security-advisories/{cve_id}/")
        
        return '\n'.join(parts)
    
    @staticmethod
    def _extract_exploitation_method(summary: str) -> Optional[str]:
        """Извлечение информации о методе эксплуатации"""
        if not summary:
            return None
        
        # Поиск фраз о методе эксплуатации
        patterns = [
            r'To exploit[^.]*\.',
            r'An attacker[^.]*\.',
            r'Exploitation requires[^.]*\.'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, summary, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return None
    
    @staticmethod
    def _build_references(grafana_data: Dict) -> List[Dict]:
        """Формирование списка ссылок"""
        cve_id = grafana_data.get('cve_id', '').lower()
        
        references = [
            {
                "url": f"https://grafana.com/security/security-advisories/{cve_id}/",
                "type": "vendor_advisory",
                "source": "Grafana Labs"
            }
        ]
        
        if grafana_data.get('credits'):
            references.append({
                "url": "https://grafana.com/security/bug-bounty/",
                "type": "bug_bounty",
                "source": "Grafana Labs"
            })
        
        return references
    
    @staticmethod
    def _parse_date(date_string: Optional[str]) -> Optional[datetime]:
        """Парсинг даты"""
        if not date_string or date_string == '—':
            return None
        
        # ISO формат (YYYY-MM-DD)
        try:
            return datetime.strptime(date_string, '%Y-%m-%d')
        except ValueError:
            pass
        
        # Формат YYYY/MM/DD
        try:
            return datetime.strptime(date_string, '%Y/%m/%d')
        except ValueError:
            pass
        
        logger.warning(f"Could not parse date: {date_string}")
        return None

