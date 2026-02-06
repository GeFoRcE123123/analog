"""
Система нормализации данных уязвимостей
Обеспечивает унификацию форматов CVSS, CPE, CWE, дат и других данных
"""
import logging
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class NormalizedVulnerability:
    """Нормализованная уязвимость в унифицированном формате"""
    cve_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low
    cvss_score: float  # 0.0 - 10.0
    cvss_version: str  # 2.0, 3.0, 3.1, 4.0
    cvss_vector: Optional[str]
    cwe_ids: List[str]
    cpe_list: List[str]
    affected_products: List[Dict[str, str]]  # [{"vendor": "vendor", "product": "product", "version": "version"}]
    references: List[Dict[str, str]]  # [{"url": "url", "source": "source", "type": "type"}]
    published_date: datetime
    last_modified: datetime
    source: str
    source_id: Optional[str]  # ID в системе источника
    status: str  # new, analyzed, modified, rejected
    tags: List[str]
    is_ai_related: bool
    ai_confidence: float  # 0.0 - 1.0
    has_exploit: bool
    has_poc: bool
    epss_score: Optional[float]  # Exploit Prediction Scoring System
    kev_status: bool  # CISA KEV
    metadata: Dict[str, Any]  # Дополнительные данные


class DataNormalizer:
    """
    Нормализатор данных уязвимостей
    
    Функции:
    - Нормализация CVSS (v2, v3, v4) в единый формат
    - Нормализация CPE в стандартный формат
    - Нормализация CWE кодов
    - Нормализация дат
    - Нормализация severity levels
    - Извлечение affected products из CPE
    """
    
    # Маппинг severity уровней
    SEVERITY_MAPPING = {
        'critical': ['critical', 'cr', 'c'],
        'high': ['high', 'h', 'important', 'important/critical'],
        'medium': ['medium', 'm', 'moderate', 'moderate/important'],
        'low': ['low', 'l', 'minor', 'low/moderate']
    }
    
    # Регулярные выражения для CPE
    CPE_PATTERN = re.compile(
        r'cpe:2\.3:[aho\*\-]+:[aho\*\-]+:[aho\*\-]+:[aho\*\-]+:[aho\*\-]+:[aho\*\-]+:[aho\*\-]+:[aho\*\-]+:[aho\*\-]+:[aho\*\-]+:[aho\*\-]+'
    )
    
    # Регулярное выражение для CVE ID
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}')
    
    def normalize_cvss(self, cvss_data: Any) -> Dict[str, Any]:
        """
        Нормализация CVSS данных
        
        Args:
            cvss_data: CVSS данные в любом формате
            
        Returns:
            Dict с ключами: score, version, vector, severity, base_severity
        """
        if not cvss_data:
            return {
                'score': 0.0,
                'version': None,
                'vector': None,
                'severity': 'unknown',
                'base_severity': None
            }
        
        # Если это словарь
        if isinstance(cvss_data, dict):
            # CVSS v3.x
            if 'version' in cvss_data or 'cvssData' in cvss_data:
                cvss_info = cvss_data.get('cvssData', cvss_data)
                score = cvss_info.get('baseScore') or cvss_info.get('score') or 0.0
                version = cvss_info.get('version') or cvss_data.get('version') or '3.1'
                vector = cvss_info.get('vectorString') or cvss_info.get('vector')
                base_severity = cvss_info.get('baseSeverity') or self._score_to_severity(score)
            
            # CVSS v2
            elif 'baseScore' in cvss_data and 'vectorString' not in cvss_data:
                score = cvss_data.get('baseScore', 0.0)
                version = '2.0'
                vector = None
                base_severity = cvss_data.get('baseSeverity') or self._score_to_severity_v2(score)
            
            else:
                # Попытка извлечь данные напрямую
                score = cvss_data.get('score') or cvss_data.get('baseScore') or 0.0
                version = cvss_data.get('version', '3.1')
                vector = cvss_data.get('vector') or cvss_data.get('vectorString')
                base_severity = cvss_data.get('baseSeverity') or self._score_to_severity(score)
        
        # Если это число (score)
        elif isinstance(cvss_data, (int, float)):
            score = float(cvss_data)
            version = '3.1'
            vector = None
            base_severity = self._score_to_severity(score)
        
        # Если это строка
        elif isinstance(cvss_data, str):
            try:
                score = float(cvss_data)
                version = '3.1'
                vector = None
                base_severity = self._score_to_severity(score)
            except ValueError:
                return {
                    'score': 0.0,
                    'version': None,
                    'vector': None,
                    'severity': 'unknown',
                    'base_severity': None
                }
        else:
            return {
                'score': 0.0,
                'version': None,
                'vector': None,
                'severity': 'unknown',
                'base_severity': None
            }
        
        # Нормализация severity
        severity = self.normalize_severity(base_severity or score)
        
        return {
            'score': float(score),
            'version': version,
            'vector': vector,
            'severity': severity,
            'base_severity': base_severity
        }
    
    def normalize_severity(self, severity_input: Any) -> str:
        """
        Нормализация severity уровня
        
        Args:
            severity_input: Severity в любом формате (строка, число CVSS score)
            
        Returns:
            Нормализованный severity: critical, high, medium, low, unknown
        """
        # Если это число (CVSS score)
        if isinstance(severity_input, (int, float)):
            score = float(severity_input)
            if score >= 9.0:
                return 'critical'
            elif score >= 7.0:
                return 'high'
            elif score >= 4.0:
                return 'medium'
            elif score > 0:
                return 'low'
            else:
                return 'unknown'
        
        # Если это строка
        if isinstance(severity_input, str):
            severity_lower = severity_input.lower().strip()
            
            # Поиск в маппинге
            for normalized, variants in self.SEVERITY_MAPPING.items():
                if severity_lower in variants:
                    return normalized
            
            # Прямое совпадение
            if severity_lower in ['critical', 'high', 'medium', 'low']:
                return severity_lower
        
        return 'unknown'
    
    def normalize_cpe(self, cpe_string: str) -> Optional[str]:
        """
        Нормализация CPE строки
        
        Args:
            cpe_string: CPE строка в любом формате
            
        Returns:
            Нормализованная CPE строка или None
        """
        if not cpe_string:
            return None
        
        # Убираем пробелы
        cpe_string = cpe_string.strip()
        
        # Если это уже валидная CPE 2.3
        if self.CPE_PATTERN.match(cpe_string):
            return cpe_string
        
        # Попытка парсинга других форматов
        # cpe:/a:vendor:product:version
        if cpe_string.startswith('cpe:/'):
            parts = cpe_string.replace('cpe:/', '').split(':')
            if len(parts) >= 2:
                # Преобразуем в формат 2.3
                cpe_23 = f"cpe:2.3:{parts[0]}:{parts[1]}:*:*:*:*:*:*:*:*:*:*"
                return cpe_23
        
        return None
    
    def extract_products_from_cpe(self, cpe_list: List[str]) -> List[Dict[str, str]]:
        """
        Извлечение affected products из списка CPE
        
        Args:
            cpe_list: Список CPE строк
            
        Returns:
            Список словарей с ключами: vendor, product, version
        """
        products = []
        
        for cpe in cpe_list:
            normalized_cpe = self.normalize_cpe(cpe)
            if not normalized_cpe:
                continue
            
            # Парсинг CPE 2.3: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            parts = normalized_cpe.split(':')
            if len(parts) >= 5:
                vendor = parts[2] if parts[2] != '*' else None
                product = parts[3] if parts[3] != '*' else None
                version = parts[4] if parts[4] != '*' else None
                
                if vendor and product:
                    products.append({
                        'vendor': vendor,
                        'product': product,
                        'version': version,
                        'cpe': normalized_cpe
                    })
        
        # Удаление дубликатов
        seen = set()
        unique_products = []
        for product in products:
            key = (product['vendor'], product['product'], product['version'])
            if key not in seen:
                seen.add(key)
                unique_products.append(product)
        
        return unique_products
    
    def normalize_cwe(self, cwe_data: Any) -> List[str]:
        """
        Нормализация CWE кодов
        
        Args:
            cwe_data: CWE данные (строка, список, словарь)
            
        Returns:
            Список нормализованных CWE ID (например, ['CWE-79', 'CWE-89'])
        """
        cwe_list = []
        
        if isinstance(cwe_data, str):
            # Извлечение CWE-XXX из строки
            cwe_pattern = re.compile(r'CWE-(\d+)', re.IGNORECASE)
            matches = cwe_pattern.findall(cwe_data)
            cwe_list = [f"CWE-{match}" for match in matches]
        
        elif isinstance(cwe_data, list):
            for item in cwe_data:
                if isinstance(item, str):
                    if item.startswith('CWE-'):
                        cwe_list.append(item.upper())
                    elif item.isdigit():
                        cwe_list.append(f"CWE-{item}")
                elif isinstance(item, dict):
                    cwe_id = item.get('cweId') or item.get('id') or item.get('value')
                    if cwe_id:
                        if isinstance(cwe_id, str):
                            cwe_list.append(cwe_id.upper() if cwe_id.upper().startswith('CWE-') else f"CWE-{cwe_id}")
                        elif isinstance(cwe_id, int):
                            cwe_list.append(f"CWE-{cwe_id}")
        
        elif isinstance(cwe_data, dict):
            cwe_id = cwe_data.get('cweId') or cwe_data.get('id') or cwe_data.get('value')
            if cwe_id:
                if isinstance(cwe_id, str):
                    cwe_list.append(cwe_id.upper() if cwe_id.upper().startswith('CWE-') else f"CWE-{cwe_id}")
                elif isinstance(cwe_id, int):
                    cwe_list.append(f"CWE-{cwe_id}")
        
        # Удаление дубликатов и сортировка
        return sorted(list(set(cwe_list)))
    
    def normalize_date(self, date_input: Any) -> Optional[datetime]:
        """
        Нормализация даты
        
        Args:
            date_input: Дата в любом формате (строка ISO, timestamp, datetime)
            
        Returns:
            datetime объект или None
        """
        if not date_input:
            return None
        
        # Если это уже datetime
        if isinstance(date_input, datetime):
            return date_input
        
        # Если это timestamp
        if isinstance(date_input, (int, float)):
            try:
                return datetime.fromtimestamp(date_input)
            except (ValueError, OSError):
                return None
        
        # Если это строка
        if isinstance(date_input, str):
            # ISO форматы
            formats = [
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d',
                '%d/%m/%Y',
                '%m/%d/%Y'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_input, fmt)
                except ValueError:
                    continue
            
            # Попытка парсинга с timezone
            try:
                from dateutil import parser
                return parser.parse(date_input)
            except (ImportError, ValueError):
                pass
        
        return None
    
    def normalize_vulnerability(self, raw_data: Dict[str, Any], source: str) -> NormalizedVulnerability:
        """
        Полная нормализация уязвимости из любого источника
        
        Args:
            raw_data: Сырые данные уязвимости
            source: Источник данных (nvd, osv, redhat, etc.)
            
        Returns:
            NormalizedVulnerability объект
        """
        # Извлечение базовых полей
        cve_id = self._extract_cve_id(raw_data)
        title = raw_data.get('title') or raw_data.get('summary') or f"Уязвимость {cve_id}"
        description = raw_data.get('description') or raw_data.get('summary') or ''
        
        # Нормализация CVSS
        cvss_data = self.normalize_cvss(
            raw_data.get('cvss') or 
            raw_data.get('metrics') or 
            raw_data.get('cvssV3') or 
            raw_data.get('cvssV2')
        )
        
        # Нормализация CWE
        cwe_list = self.normalize_cwe(
            raw_data.get('cwe') or 
            raw_data.get('weaknesses') or 
            raw_data.get('cwe_ids')
        )
        
        # Нормализация CPE
        cpe_raw = raw_data.get('cpe') or raw_data.get('configurations') or raw_data.get('affected') or []
        if isinstance(cpe_raw, str):
            cpe_list = [cpe_raw]
        elif isinstance(cpe_raw, list):
            cpe_list = [cpe for cpe in cpe_raw if isinstance(cpe, str)]
        else:
            cpe_list = []
        
        normalized_cpe_list = [self.normalize_cpe(cpe) for cpe in cpe_list if self.normalize_cpe(cpe)]
        
        # Извлечение affected products
        affected_products = self.extract_products_from_cpe(normalized_cpe_list)
        if not affected_products:
            # Попытка извлечь из других полей
            affected = raw_data.get('affected', [])
            if isinstance(affected, list):
                for item in affected:
                    if isinstance(item, dict):
                        affected_products.append({
                            'vendor': item.get('vendor') or item.get('package', {}).get('ecosystem'),
                            'product': item.get('product') or item.get('package', {}).get('name'),
                            'version': item.get('version') or item.get('versions', [None])[0]
                        })
        
        # Нормализация references
        references = self._normalize_references(raw_data.get('references') or raw_data.get('urls') or [])
        
        # Нормализация дат
        published_date = self.normalize_date(raw_data.get('published') or raw_data.get('published_date') or raw_data.get('publishedAt'))
        last_modified = self.normalize_date(raw_data.get('last_modified') or raw_data.get('modified') or raw_data.get('updated') or published_date)
        
        # Дополнительные поля
        tags = raw_data.get('tags') or []
        if isinstance(tags, str):
            tags = [tags]
        
        is_ai_related = raw_data.get('is_ai_related', False)
        ai_confidence = float(raw_data.get('ai_confidence', 0.0))
        
        has_exploit = raw_data.get('has_exploit', False) or raw_data.get('exploited', False)
        has_poc = raw_data.get('has_poc', False) or raw_data.get('poc_available', False)
        epss_score = raw_data.get('epss_score')
        if epss_score is not None:
            epss_score = float(epss_score)
        
        kev_status = raw_data.get('kev_status', False) or raw_data.get('has_kev', False)
        
        # Статус
        status = raw_data.get('status', 'new')
        if status not in ['new', 'analyzed', 'modified', 'rejected']:
            status = 'new'
        
        return NormalizedVulnerability(
            cve_id=cve_id,
            title=title,
            description=description,
            severity=cvss_data['severity'],
            cvss_score=cvss_data['score'],
            cvss_version=cvss_data['version'],
            cvss_vector=cvss_data['vector'],
            cwe_ids=cwe_list,
            cpe_list=normalized_cpe_list,
            affected_products=affected_products,
            references=references,
            published_date=published_date or datetime.now(),
            last_modified=last_modified or datetime.now(),
            source=source,
            source_id=raw_data.get('id') or raw_data.get('cve_id'),
            status=status,
            tags=tags,
            is_ai_related=is_ai_related,
            ai_confidence=ai_confidence,
            has_exploit=has_exploit,
            has_poc=has_poc,
            epss_score=epss_score,
            kev_status=kev_status,
            metadata=raw_data.get('metadata', {})
        )
    
    def _extract_cve_id(self, data: Dict[str, Any]) -> str:
        """Извлечение CVE ID из данных"""
        cve_id = data.get('cve_id') or data.get('id') or data.get('CVE') or data.get('cve')
        if isinstance(cve_id, str):
            match = self.CVE_PATTERN.search(cve_id.upper())
            if match:
                return match.group()
        return 'UNKNOWN-CVE'
    
    def _normalize_references(self, refs: Any) -> List[Dict[str, str]]:
        """Нормализация references"""
        references = []
        
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, str):
                    references.append({
                        'url': ref,
                        'source': 'unknown',
                        'type': 'unknown'
                    })
                elif isinstance(ref, dict):
                    url = ref.get('url') or ref.get('link') or ref.get('href')
                    if url:
                        references.append({
                            'url': url,
                            'source': ref.get('source', 'unknown'),
                            'type': ref.get('type', ref.get('source_type', 'unknown'))
                        })
        
        return references
    
    def _score_to_severity(self, score: float) -> str:
        """Преобразование CVSS v3 score в severity"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        else:
            return 'NONE'
    
    def _score_to_severity_v2(self, score: float) -> str:
        """Преобразование CVSS v2 score в severity"""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        else:
            return 'NONE'


# Глобальный экземпляр нормализатора
normalizer = DataNormalizer()

