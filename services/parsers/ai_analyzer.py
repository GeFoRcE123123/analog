"""
AI/ML модуль для анализа уязвимостей
Определяет AI-связанные уязвимости, классифицирует по типам, оценивает риски
"""
import logging
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class AIClassification:
    """Результат AI анализа уязвимости"""
    is_ai_related: bool
    confidence: float  # 0.0 - 1.0
    ai_categories: List[str]  # ['machine_learning', 'neural_network', 'llm', etc.]
    reasoning: str  # Объяснение классификации


class AIAnalyzer:
    """
    AI/ML анализатор уязвимостей
    
    Функции:
    - Определение AI-связанных уязвимостей
    - Классификация по типам (CWE, OWASP Top 10)
    - Оценка рисков (zero-day потенциал, exploit availability)
    - Анализ популярности (упоминания в dark web, PoC, exploit-db)
    """
    
    # Ключевые слова для AI-связанных уязвимостей
    AI_KEYWORDS = {
        'core_ai': [
            'artificial intelligence', 'machine learning', 'deep learning',
            'neural network', 'ai model', 'ml model', 'ai system'
        ],
        'frameworks': [
            'tensorflow', 'pytorch', 'keras', 'scikit-learn', 'huggingface',
            'transformers', 'openai', 'anthropic', 'deepmind'
        ],
        'models': [
            'llm', 'large language model', 'gpt', 'bert', 'transformer',
            'generative ai', 'stable diffusion', 'midjourney', 'dall-e',
            'chatgpt', 'claude', 'bard', 'gemini', 'palm'
        ],
        'techniques': [
            'computer vision', 'nlp', 'natural language processing',
            'reinforcement learning', 'convolutional', 'recurrent', 'lstm',
            'gan', 'autoencoder', 'rnn', 'cnn', 'attention mechanism'
        ],
        'domains': [
            'autonomous vehicle', 'robotics', 'recommendation system',
            'fraud detection', 'anomaly detection', 'predictive analytics'
        ],
        'threats': [
            'adversarial attack', 'model poisoning', 'data poisoning',
            'membership inference', 'model inversion', 'backdoor attack',
            'prompt injection', 'jailbreak', 'ai hallucination'
        ]
    }
    
    # Веса для разных категорий
    CATEGORY_WEIGHTS = {
        'core_ai': 1.0,
        'frameworks': 0.9,
        'models': 0.95,
        'techniques': 0.8,
        'domains': 0.7,
        'threats': 1.0
    }
    
    # CWE коды, связанные с AI
    AI_RELATED_CWE = [
        'CWE-434',  # Unrestricted Upload of File with Dangerous Type
        'CWE-79',   # XSS (может быть в AI веб-интерфейсах)
        'CWE-352',  # CSRF
        'CWE-863',  # Incorrect Authorization
        'CWE-200',  # Information Exposure
        'CWE-287',  # Improper Authentication
    ]
    
    # OWASP Top 10 маппинг
    OWASP_TOP_10 = {
        'A01': 'Broken Access Control',
        'A02': 'Cryptographic Failures',
        'A03': 'Injection',
        'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',
        'A06': 'Vulnerable and Outdated Components',
        'A07': 'Identification and Authentication Failures',
        'A08': 'Software and Data Integrity Failures',
        'A09': 'Security Logging and Monitoring Failures',
        'A10': 'Server-Side Request Forgery (SSRF)'
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Кэш для ускорения анализа
        self._cache: Dict[str, AIClassification] = {}
    
    def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> AIClassification:
        """
        Анализ уязвимости на AI-связанность
        
        Args:
            vulnerability_data: Данные уязвимости (нормализованные или сырые)
            
        Returns:
            AIClassification объект
        """
        # Проверка кэша
        cve_id = vulnerability_data.get('cve_id') or vulnerability_data.get('id', '')
        if cve_id in self._cache:
            return self._cache[cve_id]
        
        # Извлечение текста для анализа
        text_fields = [
            vulnerability_data.get('title', ''),
            vulnerability_data.get('description', ''),
            vulnerability_data.get('summary', ''),
            ' '.join(vulnerability_data.get('tags', [])),
            ' '.join([ref.get('url', '') for ref in vulnerability_data.get('references', [])])
        ]
        
        combined_text = ' '.join([str(field) for field in text_fields]).lower()
        
        # Анализ на AI-связанность
        ai_categories = []
        total_score = 0.0
        matches = []
        
        for category, keywords in self.AI_KEYWORDS.items():
            category_score = 0.0
            category_matches = []
            
            for keyword in keywords:
                # Поиск ключевых слов (слово целиком, не подстрока)
                pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
                matches_found = re.findall(pattern, combined_text, re.IGNORECASE)
                
                if matches_found:
                    category_score += 1.0
                    category_matches.append(keyword)
            
            if category_score > 0:
                ai_categories.append(category)
                weighted_score = category_score * self.CATEGORY_WEIGHTS.get(category, 0.5)
                total_score += weighted_score
                matches.extend(category_matches)
        
        # Проверка CWE кодов
        cwe_list = vulnerability_data.get('cwe_ids', [])
        if not isinstance(cwe_list, list):
            cwe_list = vulnerability_data.get('cwe', [])
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]
        
        for cwe in cwe_list:
            cwe_str = str(cwe).upper()
            if any(ai_cwe in cwe_str for ai_cwe in self.AI_RELATED_CWE):
                total_score += 0.5
        
        # Проверка affected products
        affected = vulnerability_data.get('affected_products', [])
        for product in affected:
            product_name = (product.get('product', '') or product.get('name', '')).lower()
            vendor_name = (product.get('vendor', '') or product.get('package', {}).get('ecosystem', '')).lower()
            
            # Проверка на AI фреймворки в названиях продуктов
            for category, keywords in self.AI_KEYWORDS.items():
                for keyword in keywords:
                    if keyword in product_name or keyword in vendor_name:
                        if category not in ai_categories:
                            ai_categories.append(category)
                        total_score += 0.3
        
        # Нормализация confidence score (0.0 - 1.0)
        # Базовый порог: 1.0 = 100% confidence
        # Используем сигмоиду для сглаживания
        confidence = min(1.0, total_score / 5.0)  # Нормализация к 0-1
        
        # Порог для is_ai_related
        is_ai_related = confidence >= 0.3  # 30% порог
        
        # Формирование reasoning
        reasoning_parts = []
        if matches:
            reasoning_parts.append(f"Найдены ключевые слова: {', '.join(set(matches[:5]))}")
        if ai_categories:
            reasoning_parts.append(f"Категории: {', '.join(ai_categories)}")
        if cwe_list and any(ai_cwe in str(cwe).upper() for cwe in cwe_list for ai_cwe in self.AI_RELATED_CWE):
            reasoning_parts.append("Связанные CWE коды обнаружены")
        
        reasoning = '; '.join(reasoning_parts) if reasoning_parts else "Низкая уверенность"
        
        result = AIClassification(
            is_ai_related=is_ai_related,
            confidence=confidence,
            ai_categories=ai_categories,
            reasoning=reasoning
        )
        
        # Сохранение в кэш
        if cwe_id:
            self._cache[cwe_id] = result
        
        return result
    
    def classify_by_owasp(self, vulnerability_data: Dict[str, Any]) -> List[str]:
        """
        Классификация уязвимости по OWASP Top 10
        
        Args:
            vulnerability_data: Данные уязвимости
            
        Returns:
            Список OWASP категорий (например, ['A03', 'A07'])
        """
        categories = []
        
        cwe_list = vulnerability_data.get('cwe_ids', [])
        if not isinstance(cwe_list, list):
            cwe_list = vulnerability_data.get('cwe', [])
        
        description = (vulnerability_data.get('description', '') or vulnerability_data.get('summary', '')).lower()
        
        # Маппинг CWE -> OWASP (упрощенный)
        cwe_owasp_mapping = {
            'CWE-79': 'A03',  # XSS -> Injection
            'CWE-89': 'A03',  # SQL Injection -> Injection
            'CWE-434': 'A01', # File Upload -> Broken Access Control
            'CWE-352': 'A07', # CSRF -> Authentication Failures
            'CWE-287': 'A07', # Improper Authentication -> Authentication Failures
            'CWE-311': 'A02', # Missing Encryption -> Cryptographic Failures
            'CWE-327': 'A02', # Broken Crypto -> Cryptographic Failures
        }
        
        for cwe in cwe_list:
            cwe_str = str(cwe).upper()
            for cwe_code, owasp_code in cwe_owasp_mapping.items():
                if cwe_code in cwe_str:
                    if owasp_code not in categories:
                        categories.append(owasp_code)
        
        # Дополнительная классификация по описанию
        if 'injection' in description or 'sql' in description or 'command' in description:
            if 'A03' not in categories:
                categories.append('A03')
        
        if 'authentication' in description or 'authorization' in description or 'access control' in description:
            if 'A07' not in categories:
                categories.append('A07')
        
        if 'encryption' in description or 'crypto' in description or 'ssl' in description or 'tls' in description:
            if 'A02' not in categories:
                categories.append('A02')
        
        return categories
    
    def assess_zero_day_potential(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Оценка zero-day потенциала уязвимости
        
        Args:
            vulnerability_data: Данные уязвимости
            
        Returns:
            Dict с оценками: has_zero_day_potential, exploit_available, poc_available, risk_score
        """
        has_exploit = vulnerability_data.get('has_exploit', False)
        has_poc = vulnerability_data.get('has_poc', False)
        epss_score = vulnerability_data.get('epss_score')
        kev_status = vulnerability_data.get('kev_status', False)
        cvss_score = vulnerability_data.get('cvss_score', 0.0)
        
        # Оценка риска
        risk_score = 0.0
        
        # Высокий CVSS score
        if cvss_score >= 9.0:
            risk_score += 0.4
        elif cvss_score >= 7.0:
            risk_score += 0.3
        elif cvss_score >= 4.0:
            risk_score += 0.2
        
        # Наличие эксплойта
        if has_exploit:
            risk_score += 0.3
        
        # Наличие PoC
        if has_poc:
            risk_score += 0.2
        
        # CISA KEV (Known Exploited Vulnerabilities)
        if kev_status:
            risk_score += 0.3
        
        # EPSS score (если доступен)
        if epss_score:
            risk_score += float(epss_score) * 0.2
        
        # Zero-day потенциал
        has_zero_day_potential = (
            cvss_score >= 7.0 and (
                has_exploit or 
                has_poc or 
                kev_status or 
                (epss_score and epss_score > 0.7)
            )
        )
        
        return {
            'has_zero_day_potential': has_zero_day_potential,
            'exploit_available': has_exploit,
            'poc_available': has_poc,
            'risk_score': min(1.0, risk_score),
            'factors': {
                'high_cvss': cvss_score >= 7.0,
                'has_exploit': has_exploit,
                'has_poc': has_poc,
                'kev_listed': kev_status,
                'high_epss': epss_score and epss_score > 0.7
            }
        }
    
    def analyze_all(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Полный AI анализ уязвимости
        
        Args:
            vulnerability_data: Данные уязвимости
            
        Returns:
            Dict со всеми результатами анализа
        """
        ai_classification = self.analyze_vulnerability(vulnerability_data)
        owasp_categories = self.classify_by_owasp(vulnerability_data)
        zero_day_assessment = self.assess_zero_day_potential(vulnerability_data)
        
        return {
            'ai_classification': {
                'is_ai_related': ai_classification.is_ai_related,
                'confidence': ai_classification.confidence,
                'categories': ai_classification.ai_categories,
                'reasoning': ai_classification.reasoning
            },
            'owasp_classification': owasp_categories,
            'zero_day_assessment': zero_day_assessment,
            'overall_risk': zero_day_assessment['risk_score']
        }


# Глобальный экземпляр анализатора
ai_analyzer = AIAnalyzer()

