"""
Адаптер для официального формата CVE JSON 5.x
Основан на официальной схеме: https://github.com/CVEProject/cve-schema

Структура соответствует CVE Record Format 5.0+
"""
import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class CVEJSON5Adapter:
    """
    Адаптер для преобразования официального формата CVE JSON 5.x
    в внутренний формат системы управления уязвимостями
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_cve_record(self, cve_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Парсинг официального CVE JSON 5.x формата
        
        Args:
            cve_json: CVE запись в формате JSON 5.x
            
        Returns:
            Dict с нормализованными данными уязвимости
        """
        try:
            # Проверка версии формата
            data_version = cve_json.get('dataVersion', '5.0')
            if not data_version.startswith('5.'):
                self.logger.warning(f"Неподдерживаемая версия CVE JSON: {data_version}")
            
            # Извлечение метаданных
            cve_metadata = cve_json.get('cveMetadata', {})
            cve_id = cve_metadata.get('cveId', '')
            
            if not cve_id:
                self.logger.error("CVE ID не найден в метаданных")
                return None
            
            # Извлечение основных данных из CNA контейнера
            containers = cve_json.get('containers', {})
            cna_data = containers.get('cna', {})
            
            # Описания
            descriptions = self._extract_descriptions(cna_data)
            
            # Затронутые продукты
            affected = self._extract_affected(cna_data)
            
            # Ссылки
            references = self._extract_references(cna_data)
            
            # Метрики (CVSS, EPSS и др.)
            metrics = self._extract_metrics(cna_data)
            
            # Решения и обходные пути
            workarounds = self._extract_workarounds(cna_data)
            solutions = self._extract_solutions(cna_data)
            
            # Даты
            date_published = self._parse_date(cve_metadata.get('datePublished'))
            date_updated = self._parse_date(cve_metadata.get('dateUpdated'))
            
            # Формирование результата
            result = {
                'cve_id': cve_id,
                'title': self._generate_title(cve_id, descriptions),
                'description': self._get_primary_description(descriptions),
                'severity': metrics.get('severity', 'medium'),
                'cvss_score': metrics.get('cvss_score', 0.0),
                'cvss_version': metrics.get('cvss_version'),
                'cvss_vector': metrics.get('cvss_vector'),
                'epss_score': metrics.get('epss_score'),
                'affected_products': affected,
                'references': references,
                'workarounds': workarounds,
                'solutions': solutions,
                'published_date': date_published,
                'updated_date': date_updated,
                'state': cve_metadata.get('state', 'PUBLISHED'),
                'assigner_org_id': cve_metadata.get('assignerOrgId'),
                'source': 'cve_json5',
                'raw_data': cve_json  # Сохраняем оригинальные данные
            }
            
            self.logger.debug(f"✅ CVE JSON 5.x распарсен: {cve_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка парсинга CVE JSON 5.x: {e}", exc_info=True)
            return None
    
    def _extract_descriptions(self, cna_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Извлечение описаний"""
        descriptions = []
        try:
            cna_descriptions = cna_data.get('descriptions', [])
            for desc in cna_descriptions:
                descriptions.append({
                    'lang': desc.get('lang', 'en'),
                    'value': desc.get('value', ''),
                    'type': desc.get('type', '')
                })
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения описаний: {e}")
        return descriptions
    
    def _get_primary_description(self, descriptions: List[Dict[str, str]]) -> str:
        """Получить основное описание (английское, первое доступное)"""
        # Ищем английское описание
        for desc in descriptions:
            if desc.get('lang', '').lower() == 'en':
                return desc.get('value', '')
        
        # Если английского нет, берем первое доступное
        if descriptions:
            return descriptions[0].get('value', '')
        
        return ''
    
    def _extract_affected(self, cna_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Извлечение затронутых продуктов"""
        affected = []
        try:
            affected_list = cna_data.get('affected', [])
            for item in affected_list:
                vendor = item.get('vendor', '')
                product = item.get('product', '')
                
                # Извлечение версий
                versions = []
                for version_data in item.get('versions', []):
                    version_info = {
                        'version': version_data.get('version', ''),
                        'versionType': version_data.get('versionType', ''),
                        'status': version_data.get('status', '')
                    }
                    versions.append(version_info)
                
                # Извлечение CPE
                cpes = item.get('cpes', [])
                
                affected.append({
                    'vendor': vendor,
                    'product': product,
                    'versions': versions,
                    'cpes': cpes,
                    'defaultStatus': item.get('defaultStatus'),
                    'platforms': item.get('platforms', [])
                })
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения затронутых продуктов: {e}")
        return affected
    
    def _extract_references(self, cna_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Извлечение ссылок"""
        references = []
        try:
            refs = cna_data.get('references', [])
            for ref in refs:
                references.append({
                    'url': ref.get('url', ''),
                    'name': ref.get('name', ''),
                    'tags': ref.get('tags', [])
                })
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения ссылок: {e}")
        return references
    
    def _extract_metrics(self, cna_data: Dict[str, Any]) -> Dict[str, Any]:
        """Извлечение метрик (CVSS, EPSS и др.)"""
        metrics_result = {
            'severity': 'medium',
            'cvss_score': 0.0,
            'cvss_version': None,
            'cvss_vector': None,
            'epss_score': None
        }
        
        try:
            metrics_list = cna_data.get('metrics', [])
            
            # Ищем CVSS метрики
            for metric in metrics_list:
                # CVSS v3.x
                if 'cvssV3_1' in metric or 'cvssV3_0' in metric:
                    cvss_key = 'cvssV3_1' if 'cvssV3_1' in metric else 'cvssV3_0'
                    cvss_data = metric[cvss_key]
                    cvss_info = cvss_data.get('cvssData', {})
                    
                    metrics_result['cvss_score'] = float(cvss_info.get('baseScore', 0.0))
                    metrics_result['cvss_version'] = cvss_info.get('version', '3.1')
                    metrics_result['cvss_vector'] = cvss_info.get('vectorString')
                    
                    # Определение severity по CVSS
                    base_severity = cvss_info.get('baseSeverity', '').lower()
                    if base_severity:
                        metrics_result['severity'] = base_severity
                    else:
                        metrics_result['severity'] = self._cvss_to_severity(metrics_result['cvss_score'])
                    
                    break  # Используем первую найденную метрику
                
                # CVSS v2
                elif 'cvssV2' in metric:
                    cvss_data = metric['cvssV2']
                    cvss_info = cvss_data.get('cvssData', {})
                    
                    metrics_result['cvss_score'] = float(cvss_info.get('baseScore', 0.0))
                    metrics_result['cvss_version'] = '2.0'
                    metrics_result['cvss_vector'] = cvss_info.get('vectorString')
                    metrics_result['severity'] = self._cvss_to_severity(metrics_result['cvss_score'])
                    
                    break
                
                # EPSS
                elif 'epss' in metric:
                    epss_data = metric['epss']
                    metrics_result['epss_score'] = float(epss_data.get('epss', 0.0))
            
            # Если CVSS не найден, пробуем определить severity из других метрик
            if metrics_result['cvss_score'] == 0.0:
                # Можно добавить логику для других типов метрик
                pass
                
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения метрик: {e}")
        
        return metrics_result
    
    def _cvss_to_severity(self, cvss_score: float) -> str:
        """Конвертация CVSS score в severity"""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score > 0:
            return 'low'
        else:
            return 'medium'
    
    def _extract_workarounds(self, cna_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Извлечение обходных путей"""
        workarounds = []
        try:
            workarounds_list = cna_data.get('workarounds', [])
            for workaround in workarounds_list:
                workarounds.append({
                    'value': workaround.get('value', ''),
                    'type': workaround.get('type', '')
                })
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения обходных путей: {e}")
        return workarounds
    
    def _extract_solutions(self, cna_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Извлечение решений"""
        solutions = []
        try:
            solutions_list = cna_data.get('solutions', [])
            for solution in solutions_list:
                solutions.append({
                    'value': solution.get('value', ''),
                    'type': solution.get('type', '')
                })
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения решений: {e}")
        return solutions
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Парсинг даты из ISO формата"""
        if not date_str:
            return None
        try:
            # ISO 8601 формат: 2024-01-01T00:00:00Z или 2024-01-01T00:00:00.000Z
            date_str = date_str.replace('Z', '+00:00')
            return datetime.fromisoformat(date_str)
        except Exception as e:
            self.logger.debug(f"Ошибка парсинга даты {date_str}: {e}")
            return None
    
    def _generate_title(self, cve_id: str, descriptions: List[Dict[str, str]]) -> str:
        """Генерация заголовка из описания"""
        primary_desc = self._get_primary_description(descriptions)
        if primary_desc:
            # Берем первые 200 символов описания как заголовок
            title = primary_desc[:200].strip()
            # Убираем переносы строк
            title = ' '.join(title.split())
            return title
        return f"CVE {cve_id}"
    
    def to_vulnerability(self, cve_data: Dict[str, Any]) -> Vulnerability:
        """
        Преобразование данных CVE JSON 5.x в объект Vulnerability
        
        Args:
            cve_data: Результат parse_cve_record()
            
        Returns:
            Vulnerability объект
        """
        # Определяем severity
        severity = cve_data.get('severity', 'medium')
        
        # Дата публикации
        published = cve_data.get('published_date') or datetime.now()
        
        # Формируем список затронутых пакетов
        affected_packages = []
        for affected_item in cve_data.get('affected_products', []):
            vendor = affected_item.get('vendor', '')
            product = affected_item.get('product', '')
            if vendor and product:
                affected_packages.append({
                    'vendor': vendor,
                    'product': product,
                    'versions': affected_item.get('versions', [])
                })
        
        # Создаем объект Vulnerability
        vulnerability = Vulnerability(
            id=0,  # БД назначит ID
            title=cve_data.get('title', cve_data.get('cve_id', 'Unknown CVE')),
            description=cve_data.get('description', ''),
            severity=severity,
            status='new',
            assigned_operator=None,
            created_date=published,
            completed_date=None,
            approved=False,
            modifications=0,
            cvss_score=cve_data.get('cvss_score', 0.0),
            risk_level=severity,
            category='cve_json5',
            cve_id=cve_data.get('cve_id')
        )
        
        # Добавляем дополнительные поля
        if cve_data.get('cvss_version'):
            setattr(vulnerability, 'cvss_version', cve_data['cvss_version'])
        if cve_data.get('cvss_vector'):
            setattr(vulnerability, 'cvss_vector', cve_data['cvss_vector'])
        if cve_data.get('epss_score'):
            setattr(vulnerability, 'epss_score', cve_data['epss_score'])
        if affected_packages:
            setattr(vulnerability, 'affected_packages', affected_packages)
        if cve_data.get('references'):
            setattr(vulnerability, 'references', cve_data['references'])
        if cve_data.get('workarounds'):
            setattr(vulnerability, 'workarounds', cve_data['workarounds'])
        if cve_data.get('solutions'):
            setattr(vulnerability, 'solutions', cve_data['solutions'])
        if cve_data.get('raw_data'):
            setattr(vulnerability, 'raw_cve_json5', cve_data['raw_data'])
        
        vulnerability.source_identifier = 'CVE_JSON5'
        
        return vulnerability


# Глобальный экземпляр
_cve_json5_adapter_instance = None

def get_cve_json5_adapter():
    """Получить экземпляр CVEJSON5Adapter"""
    global _cve_json5_adapter_instance
    if _cve_json5_adapter_instance is None:
        _cve_json5_adapter_instance = CVEJSON5Adapter()
    return _cve_json5_adapter_instance

cve_json5_adapter = get_cve_json5_adapter()

