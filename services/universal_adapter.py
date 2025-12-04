"""
Универсальный адаптер для преобразования данных из всех парсеров
в унифицированную схему БД
"""

import logging
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class UnifiedVulnerability:
    """Унифицированная структура уязвимости"""
    # Основные поля для таблицы turn
    source: str  # Источник (NVD, OSV, RedHat)
    link: str  # Ссылка на уязвимость
    cve: str  # CVE ID
    joining_date: datetime  # Дата добавления
    name: str  # Название уязвимости
    cvss: float  # CVSS Score
    price_one: float  # Цена (рассчитанная)
    priority: float  # Приоритет
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    etc: Optional[str] = None  # Дополнительная информация
    status: bool = False  # Статус обработки
    
    # Дополнительные данные
    description: str = ""
    cwe_list: Optional[List[str]] = None
    affected_software: Optional[List[str]] = None
    references: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.cwe_list is None:
            self.cwe_list = []
        if self.affected_software is None:
            self.affected_software = []
        if self.references is None:
            self.references = []
        if self.tags is None:
            self.tags = []


class UniversalAdapter:
    """Универсальный адаптер данных"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Словарь для расчета цены/приоритета
        self.severity_weights = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        
        # AI ключевые слова для определения тегов
        self.ai_keywords = [
            'ai', 'artificial intelligence', 'machine learning', 'neural network',
            'deep learning', 'tensorflow', 'pytorch', 'llm', 'gpt', 'transformer'
        ]
    
    def adapt_nvd_data(self, nvd_data: Dict) -> UnifiedVulnerability:
        """Адаптация данных из NVD парсера"""
        try:
            cve_id = nvd_data.get('cve_id', '')
            
            # Извлекаем метрики
            cvss_score = self._extract_cvss_from_nvd(nvd_data.get('metrics', {}))
            
            # Извлекаем описание
            description = self._extract_description_from_nvd(nvd_data.get('descriptions', []))
            
            # Извлекаем CWE
            cwe_list = self._extract_cwe_from_nvd(nvd_data.get('weaknesses', []))
            
            # Извлекаем затронутое ПО
            affected_software = self._extract_software_from_nvd(nvd_data.get('configurations', []))
            
            # Извлекаем ссылки
            references = self._extract_references_from_nvd(nvd_data.get('references', []))
            
            # Определяем теги
            tags = self._determine_tags(description, cve_id, affected_software)
            
            # Рассчитываем цену и приоритет
            price_one, priority = self._calculate_price_priority(cvss_score, tags, cwe_list)
            
            # Парсим даты
            published = self._parse_date(nvd_data.get('published'))
            
            return UnifiedVulnerability(
                source='NVD',
                link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                cve=cve_id,
                joining_date=datetime.now(),
                name=cve_id,
                cvss=cvss_score,
                price_one=price_one,
                priority=priority,
                start_date=published,
                etc=json.dumps({
                    'vuln_status': nvd_data.get('vuln_status'),
                    'source_identifier': nvd_data.get('source_identifier'),
                    'is_ai_related': nvd_data.get('is_ai_related', False),
                    'ai_confidence': nvd_data.get('ai_confidence', 0.0)
                }),
                status=False,
                description=description,
                cwe_list=cwe_list,
                affected_software=affected_software,
                references=references,
                tags=tags
            )
            
        except Exception as e:
            self.logger.error(f"Ошибка адаптации NVD данных: {e}")
            raise
    
    def adapt_osv_data(self, osv_data: Dict) -> UnifiedVulnerability:
        """Адаптация данных из OSV парсера"""
        try:
            vuln_id = osv_data.get('id', 'UNKNOWN')
            
            # Извлекаем CVE из описания или ID
            cve = self._extract_cve_from_osv(vuln_id, osv_data)
            
            # Извлекаем описание
            description = osv_data.get('description', 'No description available')
            
            # Извлекаем пакеты
            packages = osv_data.get('packages', [])
            affected_software = [f"{pkg.get('name', '')} {pkg.get('version', '')}".strip() 
                               for pkg in packages]
            
            # Определяем CVSS из ключевых слов
            cvss_score = self._estimate_cvss_from_keywords(description, vuln_id)
            
            # Определяем теги
            tags = self._determine_tags(description, vuln_id, affected_software)
            
            # Рассчитываем цену и приоритет
            price_one, priority = self._calculate_price_priority(cvss_score, tags, [])
            
            # Дата
            date_str = osv_data.get('date', '')
            published = self._parse_date(date_str) if date_str else datetime.now()
            
            return UnifiedVulnerability(
                source='OSV',
                link=osv_data.get('url', f"https://osv.dev/vulnerability/{vuln_id}"),
                cve=cve or vuln_id,
                joining_date=datetime.now(),
                name=vuln_id,
                cvss=cvss_score,
                price_one=price_one,
                priority=priority,
                start_date=published,
                etc=json.dumps({
                    'matched_keywords': osv_data.get('matched_keywords', []),
                    'total_score': osv_data.get('total_score', 0)
                }),
                status=False,
                description=description,
                cwe_list=[],
                affected_software=affected_software,
                references=[osv_data.get('url', '')],
                tags=tags
            )
            
        except Exception as e:
            self.logger.error(f"Ошибка адаптации OSV данных: {e}")
            raise
    
    def adapt_redhat_data(self, redhat_data: Dict) -> UnifiedVulnerability:
        """Адаптация данных из RedHat парсера"""
        try:
            cve_id = redhat_data.get('cve_id', '')
            
            # Извлекаем метрики
            cvss_score = self._extract_cvss_from_nvd(redhat_data.get('metrics', {}))
            
            # Описание
            description = self._extract_description_from_nvd(redhat_data.get('descriptions', []))
            
            # CWE
            cwe_list = self._extract_cwe_from_nvd(redhat_data.get('weaknesses', []))
            
            # Затронутое ПО
            affected_software = self._extract_software_from_nvd(redhat_data.get('configurations', []))
            
            # Ссылки
            references = self._extract_references_from_nvd(redhat_data.get('references', []))
            
            # Теги
            tags = self._determine_tags(description, cve_id, affected_software)
            tags.append('redhat')
            
            # Цена и приоритет
            price_one, priority = self._calculate_price_priority(cvss_score, tags, cwe_list)
            
            # Дата
            published = self._parse_date(redhat_data.get('published'))
            
            return UnifiedVulnerability(
                source='RedHat',
                link=f"https://access.redhat.com/security/cve/{cve_id}",
                cve=cve_id,
                joining_date=datetime.now(),
                name=cve_id,
                cvss=cvss_score,
                price_one=price_one,
                priority=priority,
                start_date=published,
                etc=json.dumps({
                    'source_identifier': redhat_data.get('source_identifier'),
                    'vuln_status': redhat_data.get('vuln_status')
                }),
                status=False,
                description=description,
                cwe_list=cwe_list,
                affected_software=affected_software,
                references=references,
                tags=tags
            )
            
        except Exception as e:
            self.logger.error(f"Ошибка адаптации RedHat данных: {e}")
            raise
    
    # ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========
    
    def _extract_cvss_from_nvd(self, metrics: Dict) -> float:
        """Извлечение CVSS score из метрик"""
        if not metrics:
            return 0.0
        
        # Приоритет: v4 -> v3 -> v2
        for version in ['cvss_v4', 'cvss_v3', 'cvss_v2']:
            if version in metrics and metrics[version]:
                score = metrics[version].get('baseScore', 0.0)
                return float(score) if score else 0.0
        
        return 0.0
    
    def _extract_description_from_nvd(self, descriptions: List[Dict]) -> str:
        """Извлечение описания из NVD"""
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')[:1000]
        
        if descriptions:
            return descriptions[0].get('value', '')[:1000]
        
        return "No description available"
    
    def _extract_cwe_from_nvd(self, weaknesses: List[Dict]) -> List[str]:
        """Извлечение CWE из NVD"""
        cwe_list = []
        for weakness in weaknesses:
            desc = weakness.get('description', '')
            # Ищем CWE-XXX паттерн
            cwe_matches = re.findall(r'CWE-\d+', desc)
            cwe_list.extend(cwe_matches)
        return list(set(cwe_list))
    
    def _extract_software_from_nvd(self, configurations: List[Dict]) -> List[str]:
        """Извлечение затронутого ПО из конфигураций"""
        software_list = []
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpe_match', [])
                for cpe in cpe_matches:
                    criteria = cpe.get('criteria', '')
                    # Парсим CPE формат: cpe:2.3:a:vendor:product:version
                    parts = criteria.split(':')
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        software_list.append(f"{vendor}:{product}")
        
        return list(set(software_list))
    
    def _extract_references_from_nvd(self, references: List[Dict]) -> List[str]:
        """Извлечение ссылок"""
        return [ref.get('url', '') for ref in references if ref.get('url')]
    
    def _extract_cve_from_osv(self, vuln_id: str, osv_data: Dict) -> Optional[str]:
        """Извлечение CVE ID из OSV данных"""
        # Проверяем список CVE
        cves = osv_data.get('cves', [])
        if cves:
            return cves[0]
        
        # Проверяем, является ли ID самим CVE
        if vuln_id.startswith('CVE-'):
            return vuln_id
        
        # Ищем в описании
        description = osv_data.get('description', '')
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_matches = re.findall(cve_pattern, description)
        if cve_matches:
            return cve_matches[0]
        
        return None
    
    def _estimate_cvss_from_keywords(self, text: str, vuln_id: str) -> float:
        """Оценка CVSS на основе ключевых слов"""
        text_lower = text.lower()
        vuln_id_lower = vuln_id.lower()
        
        # Критичные ключевые слова
        critical_keywords = ['remote code execution', 'rce', 'arbitrary code', 'critical']
        high_keywords = ['privilege escalation', 'authentication bypass', 'sql injection', 'xss']
        medium_keywords = ['information disclosure', 'denial of service', 'dos']
        
        if any(kw in text_lower for kw in critical_keywords):
            return 9.0
        elif any(kw in text_lower for kw in high_keywords):
            return 7.5
        elif any(kw in text_lower for kw in medium_keywords):
            return 5.5
        else:
            return 4.0
    
    def _determine_tags(self, description: str, vuln_id: str, affected_software: List[str]) -> List[str]:
        """Определение тегов для уязвимости"""
        tags = []
        text = f"{description} {vuln_id} {' '.join(affected_software)}".lower()
        
        # AI теги
        if any(kw in text for kw in self.ai_keywords):
            tags.append('ai')
            tags.append('neural_network')
        
        # Теги по типу атаки
        if 'injection' in text:
            tags.append('injection')
        if 'overflow' in text:
            tags.append('overflow')
        if 'xss' in text or 'cross-site' in text:
            tags.append('xss')
        if 'csrf' in text:
            tags.append('csrf')
        if 'rce' in text or 'remote code' in text:
            tags.append('rce')
        
        # Теги по платформе
        if 'linux' in text:
            tags.append('linux')
        if 'windows' in text:
            tags.append('windows')
        if 'web' in text or 'http' in text:
            tags.append('web')
        
        return list(set(tags))
    
    def _calculate_price_priority(self, cvss: float, tags: List[str], cwe_list: List[str]) -> tuple:
        """Расчет цены и приоритета"""
        base_price = cvss * 10  # Базовая цена на основе CVSS
        
        # Увеличиваем за AI
        if 'ai' in tags:
            base_price *= 1.5
        
        # Увеличиваем за критичные атаки
        if 'rce' in tags:
            base_price *= 1.3
        
        # Приоритет (0-100)
        priority = min(cvss * 10, 100)
        
        # Увеличиваем приоритет для AI
        if 'ai' in tags:
            priority = min(priority * 1.2, 100)
        
        return round(base_price, 2), round(priority, 2)
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Парсинг даты из строки"""
        if not date_str:
            return None
        
        try:
            # Убираем Z и парсим
            date_str = str(date_str).replace('Z', '+00:00')
            return datetime.fromisoformat(date_str)
        except (ValueError, TypeError):
            try:
                # Пробуем другие форматы
                return datetime.strptime(str(date_str), '%Y-%m-%d')
            except:
                return None


# Глобальный экземпляр адаптера
universal_adapter = UniversalAdapter()
