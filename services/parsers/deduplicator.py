"""
Система дедупликации уязвимостей
Объединяет дубликаты из разных источников (например, CVE-2023-1234 из NVD и OSV)
"""
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


@dataclass
class DeduplicationResult:
    """Результат дедупликации"""
    is_duplicate: bool
    original_cve_id: str
    confidence: float  # 0.0 - 1.0
    merge_suggestions: Dict[str, Any]  # Предложения по объединению данных
    reasons: List[str]  # Причины, почему это дубликат


class Deduplicator:
    """
    Система дедупликации уязвимостей
    
    Стратегии:
    - По CVE ID (точное совпадение)
    - По описанию (семантическое сходство)
    - По affected products (пересечение продуктов)
    - По CWE кодам (совпадение уязвимостей)
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Кэш уже обработанных уязвимостей
        self._processed_vulns: Dict[str, Dict[str, Any]] = {}
        # Индекс для быстрого поиска
        self._cve_index: Dict[str, str] = {}  # cve_id -> normalized_id
        self._description_index: Dict[str, List[str]] = {}  # normalized_description -> [cve_ids]
    
    def check_duplicate(
        self, 
        vulnerability: Dict[str, Any], 
        existing_vulnerabilities: List[Dict[str, Any]]
    ) -> DeduplicationResult:
        """
        Проверка, является ли уязвимость дубликатом существующих
        
        Args:
            vulnerability: Проверяемая уязвимость
            existing_vulnerabilities: Список существующих уязвимостей
            
        Returns:
            DeduplicationResult
        """
        cve_id = vulnerability.get('cve_id') or vulnerability.get('id', '')
        
        # Стратегия 1: Точное совпадение CVE ID
        for existing in existing_vulnerabilities:
            existing_cve = existing.get('cve_id') or existing.get('id', '')
            if cve_id and existing_cve and cve_id.upper() == existing_cve.upper():
                return DeduplicationResult(
                    is_duplicate=True,
                    original_cve_id=existing_cve,
                    confidence=1.0,
                    merge_suggestions=self._suggest_merge(vulnerability, existing),
                    reasons=['Точное совпадение CVE ID']
                )
        
        # Стратегия 2: Семантическое сходство описаний
        best_match = None
        best_score = 0.0
        
        desc1 = self._normalize_description(vulnerability.get('description', '') or vulnerability.get('summary', ''))
        
        for existing in existing_vulnerabilities:
            existing_cve = existing.get('cve_id') or existing.get('id', '')
            desc2 = self._normalize_description(existing.get('description', '') or existing.get('summary', ''))
            
            similarity = self._calculate_text_similarity(desc1, desc2)
            
            # Дополнительные проверки для повышения confidence
            additional_checks = 0
            
            # Совпадение CWE
            cwe1 = set(self._extract_cwe(vulnerability))
            cwe2 = set(self._extract_cwe(existing))
            if cwe1 and cwe2 and cwe1.intersection(cwe2):
                additional_checks += 0.2
            
            # Совпадение affected products
            products1 = set(self._extract_product_keys(vulnerability))
            products2 = set(self._extract_product_keys(existing))
            if products1 and products2 and products1.intersection(products2):
                additional_checks += 0.2
            
            # Совпадение CVSS score (с небольшой погрешностью)
            cvss1 = vulnerability.get('cvss_score', 0)
            cvss2 = existing.get('cvss_score', 0)
            if cvss1 and cvss2 and abs(float(cvss1) - float(cvss2)) < 0.5:
                additional_checks += 0.1
            
            # Итоговый score
            total_score = min(1.0, similarity * 0.6 + additional_checks)
            
            if total_score > best_score:
                best_score = total_score
                best_match = existing
        
        # Порог для определения дубликата
        if best_score >= 0.7 and best_match:  # 70% порог
            return DeduplicationResult(
                is_duplicate=True,
                original_cve_id=best_match.get('cve_id') or best_match.get('id', ''),
                confidence=best_score,
                merge_suggestions=self._suggest_merge(vulnerability, best_match),
                reasons=[
                    f'Семантическое сходство описаний ({int(best_score * 100)}%)',
                    'Совпадение CWE кодов' if self._extract_cwe(vulnerability) and self._extract_cwe(best_match) else '',
                    'Совпадение affected products' if self._extract_product_keys(vulnerability) and self._extract_product_keys(best_match) else ''
                ]
            )
        
        # Не дубликат
        return DeduplicationResult(
            is_duplicate=False,
            original_cve_id='',
            confidence=0.0,
            merge_suggestions={},
            reasons=[]
        )
    
    def merge_vulnerabilities(
        self, 
        primary: Dict[str, Any], 
        secondary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Объединение двух уязвимостей в одну
        
        Args:
            primary: Основная уязвимость (приоритет)
            secondary: Вторичная уязвимость (дополняет primary)
            
        Returns:
            Объединенная уязвимость
        """
        merged = primary.copy()
        
        # Объединение источников
        sources = set([primary.get('source', '')])
        if secondary.get('source'):
            sources.add(secondary.get('source'))
        merged['sources'] = list(sources)
        
        # Объединение описаний (берем более полное)
        desc1 = primary.get('description', '') or primary.get('summary', '')
        desc2 = secondary.get('description', '') or secondary.get('summary', '')
        if len(desc2) > len(desc1):
            merged['description'] = desc2
            merged['summary'] = desc2
        
        # Объединение CWE
        cwe1 = set(self._extract_cwe(primary))
        cwe2 = set(self._extract_cwe(secondary))
        merged['cwe_ids'] = list(cwe1.union(cwe2))
        merged['cwe'] = merged['cwe_ids']
        
        # Объединение affected products
        products1 = self._extract_products(primary)
        products2 = self._extract_products(secondary)
        merged_products = {}
        for p in products1 + products2:
            key = (p.get('vendor', ''), p.get('product', ''), p.get('version', ''))
            if key not in merged_products:
                merged_products[key] = p
        merged['affected_products'] = list(merged_products.values())
        
        # Объединение references
        refs1 = primary.get('references', [])
        refs2 = secondary.get('references', [])
        refs_dict = {}
        for ref in refs1 + refs2:
            url = ref.get('url') if isinstance(ref, dict) else ref
            if url and url not in refs_dict:
                refs_dict[url] = ref if isinstance(ref, dict) else {'url': url}
        merged['references'] = list(refs_dict.values())
        
        # Объединение tags
        tags1 = set(primary.get('tags', []))
        tags2 = set(secondary.get('tags', []))
        merged['tags'] = list(tags1.union(tags2))
        
        # Объединение метаданных
        meta1 = primary.get('metadata', {})
        meta2 = secondary.get('metadata', {})
        merged['metadata'] = {**meta2, **meta1}  # meta1 имеет приоритет
        
        # Выбираем более свежую дату last_modified
        date1 = self._parse_date(primary.get('last_modified') or primary.get('updated'))
        date2 = self._parse_date(secondary.get('last_modified') or secondary.get('updated'))
        if date2 and (not date1 or date2 > date1):
            merged['last_modified'] = date2
        
        # Объединение AI анализа (берем более высокий confidence)
        ai1 = primary.get('is_ai_related', False)
        ai2 = secondary.get('is_ai_related', False)
        conf1 = float(primary.get('ai_confidence', 0.0))
        conf2 = float(secondary.get('ai_confidence', 0.0))
        if ai2 or conf2 > conf1:
            merged['is_ai_related'] = ai2
            merged['ai_confidence'] = conf2
        
        return merged
    
    def _suggest_merge(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any]) -> Dict[str, Any]:
        """Предложения по объединению данных"""
        suggestions = {}
        
        # Какие поля можно взять из vuln2
        fields_to_merge = []
        
        # Описание
        desc1 = vuln1.get('description', '') or vuln1.get('summary', '')
        desc2 = vuln2.get('description', '') or vuln2.get('summary', '')
        if len(desc2) > len(desc1) * 1.2:  # desc2 значительно длиннее
            fields_to_merge.append('description')
        
        # References
        refs1 = len(vuln1.get('references', []))
        refs2 = len(vuln2.get('references', []))
        if refs2 > refs1:
            fields_to_merge.append('references')
        
        # CWE
        cwe1 = set(self._extract_cwe(vuln1))
        cwe2 = set(self._extract_cwe(vuln2))
        if cwe2 - cwe1:  # Есть новые CWE
            fields_to_merge.append('cwe_ids')
        
        suggestions['fields_to_merge'] = fields_to_merge
        suggestions['source_priority'] = vuln2.get('source', '')
        
        return suggestions
    
    def _normalize_description(self, text: str) -> str:
        """Нормализация описания для сравнения"""
        if not text:
            return ''
        
        # Удаление HTML тегов
        import re
        text = re.sub(r'<[^>]+>', '', text)
        
        # Приведение к нижнему регистру
        text = text.lower()
        
        # Удаление лишних пробелов
        text = ' '.join(text.split())
        
        # Удаление пунктуации (опционально, может снизить точность)
        # text = re.sub(r'[^\w\s]', '', text)
        
        return text
    
    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """
        Расчет семантического сходства текстов (упрощенная версия)
        Использует Jaccard similarity на основе слов
        """
        if not text1 or not text2:
            return 0.0
        
        words1 = set(text1.split())
        words2 = set(text2.split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        # Jaccard similarity
        jaccard = len(intersection) / len(union) if union else 0.0
        
        # Дополнительная проверка: длинные совпадающие фразы
        # Простая проверка на общие n-граммы (биграммы)
        def get_bigrams(text: str):
            words = text.split()
            return set([f"{words[i]} {words[i+1]}" for i in range(len(words) - 1)])
        
        bigrams1 = get_bigrams(text1)
        bigrams2 = get_bigrams(text2)
        if bigrams1 and bigrams2:
            bigram_similarity = len(bigrams1.intersection(bigrams2)) / len(bigrams1.union(bigrams2))
            # Комбинируем Jaccard и bigram similarity
            return (jaccard * 0.6 + bigram_similarity * 0.4)
        
        return jaccard
    
    def _extract_cwe(self, vuln: Dict[str, Any]) -> List[str]:
        """Извлечение CWE кодов"""
        cwe_list = vuln.get('cwe_ids', []) or vuln.get('cwe', [])
        if isinstance(cwe_list, str):
            return [cwe_list]
        elif isinstance(cwe_list, list):
            return [str(cwe).upper() for cwe in cwe_list]
        return []
    
    def _extract_products(self, vuln: Dict[str, Any]) -> List[Dict[str, str]]:
        """Извлечение affected products"""
        products = vuln.get('affected_products', [])
        if not products:
            # Попытка извлечь из CPE
            cpe_list = vuln.get('cpe_list', [])
            # Упрощенная версия - возвращаем пустой список
            return []
        return products if isinstance(products, list) else []
    
    def _extract_product_keys(self, vuln: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        """Извлечение ключей продуктов для сравнения"""
        products = self._extract_products(vuln)
        keys = []
        for p in products:
            if isinstance(p, dict):
                keys.append((
                    (p.get('vendor') or '').lower(),
                    (p.get('product') or '').lower(),
                    (p.get('version') or '').lower()
                ))
        return keys
    
    def _parse_date(self, date_input: Any) -> Optional[datetime]:
        """Парсинг даты"""
        if isinstance(date_input, datetime):
            return date_input
        if isinstance(date_input, str):
            try:
                from dateutil import parser
                return parser.parse(date_input)
            except:
                pass
        return None


# Глобальный экземпляр дедупликатора
deduplicator = Deduplicator()

