"""
Сервис автоматического тегирования AI-уязвимостей
Анализирует описание, название и другие поля для идентификации уязвимостей средств ИИ
"""

import re
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AIDetectionResult:
    """Результат детекции AI-уязвимости"""
    is_ai_related: bool
    confidence: float  # 0.0 - 1.0
    matched_keywords: List[str]
    matched_categories: List[str]
    suggested_tags: List[str]
    risk_multiplier: float  # Множитель риска для AI-уязвимостей


class AITaggerService:
    """Сервис для автоматического определения и тегирования AI-уязвимостей"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Категории AI ключевых слов с весами (чем выше вес, тем выше уверенность)
        self.ai_keywords = self._init_ai_keywords()
        
        # Категории уязвимостей AI
        self.ai_attack_patterns = self._init_attack_patterns()
        
        # Пороги для определения
        self.confidence_threshold = 0.3  # Минимальная уверенность для is_ai_related
        self.high_confidence_threshold = 0.7  # Высокая уверенность
    
    def _init_ai_keywords(self) -> Dict[str, Dict[str, float]]:
        """Инициализация ключевых слов по категориям"""
        return {
            # === КРИТИЧНЫЕ AI ТЕРМИНЫ (вес 1.0) ===
            'core_ai': {
                'artificial intelligence': 1.0,
                'machine learning': 1.0,
                'deep learning': 1.0,
                'neural network': 1.0,
                'llm': 1.0,
                'large language model': 1.0,
                'foundation model': 1.0,
                'generative ai': 1.0,
                'ai model': 1.0,
                'transformer': 0.9,
                'reinforcement learning': 0.9,
            },
            
            # === AI ПЛАТФОРМЫ И ФРЕЙМВОРКИ (вес 0.9) ===
            'platforms': {
                'tensorflow': 0.9,
                'pytorch': 0.9,
                'keras': 0.8,
                'scikit-learn': 0.8,
                'huggingface': 0.9,
                'hugging face': 0.9,
                'openai': 0.9,
                'anthropic': 0.8,
                'langchain': 0.9,
                'llamaindex': 0.8,
                'autogpt': 0.8,
            },
            
            # === AI ПРОДУКТЫ (вес 0.85) ===
            'products': {
                'gpt': 0.9,
                'chatgpt': 0.9,
                'gpt-3': 0.9,
                'gpt-4': 0.9,
                'claude': 0.8,
                'bard': 0.8,
                'gemini': 0.8,
                'dall-e': 0.8,
                'stable diffusion': 0.8,
                'midjourney': 0.7,
                'whisper': 0.7,
            },
            
            # === AI АТАКИ (вес 1.0 - очень специфично) ===
            'attacks': {
                'prompt injection': 1.0,
                'jailbreak': 1.0,
                'adversarial': 0.95,
                'adversarial attack': 0.95,
                'adversarial example': 0.95,
                'model extraction': 0.95,
                'model inversion': 0.95,
                'membership inference': 0.95,
                'data poisoning': 0.95,
                'backdoor attack': 0.95,
                'model poisoning': 0.95,
                'training data leak': 0.9,
                'model stealing': 0.9,
                'guardrail bypass': 0.9,
            },
            
            # === AI КОМПОНЕНТЫ (вес 0.6 - может быть false positive) ===
            'components': {
                'embedding': 0.6,
                'attention mechanism': 0.7,
                'convolutional': 0.6,
                'recurrent': 0.6,
                'lstm': 0.7,
                'gru': 0.7,
                'gan': 0.7,
                'autoencoder': 0.7,
                'gradient descent': 0.5,
                'backpropagation': 0.5,
            },
            
            # === AI ИНФРАСТРУКТУРА (вес 0.5 - общие термины) ===
            'infrastructure': {
                'model serving': 0.7,
                'model inference': 0.7,
                'model training': 0.6,
                'fine-tuning': 0.6,
                'vector database': 0.7,
                'chromadb': 0.7,
                'pinecone': 0.7,
                'weaviate': 0.7,
                'faiss': 0.7,
            },
            
            # === AI ОБЛАСТИ ПРИМЕНЕНИЯ (вес 0.5) ===
            'applications': {
                'computer vision': 0.6,
                'natural language processing': 0.6,
                'nlp': 0.6,
                'speech recognition': 0.6,
                'autonomous': 0.5,
                'self-driving': 0.6,
                'recommendation system': 0.5,
            }
        }
    
    def _init_attack_patterns(self) -> Dict[str, List[str]]:
        """Паттерны атак специфичных для AI"""
        return {
            'prompt_attacks': [
                'prompt injection', 'jailbreak', 'prompt leak',
                'system prompt', 'role playing', 'dan mode'
            ],
            'model_attacks': [
                'model extraction', 'model inversion', 'model stealing',
                'adversarial', 'membership inference', 'model poisoning'
            ],
            'data_attacks': [
                'data poisoning', 'training data leak', 'backdoor',
                'trojan model', 'poisoned model'
            ],
            'inference_attacks': [
                'inference manipulation', 'output parser exploit',
                'token smuggling', 'context overflow'
            ]
        }
    
    def analyze_vulnerability(self, 
                            title: str = "", 
                            description: str = "", 
                            cve_id: str = "",
                            affected_software: Optional[List[str]] = None,
                            references: Optional[List[str]] = None) -> AIDetectionResult:
        """
        Анализирует уязвимость на предмет отношения к AI
        
        Args:
            title: Название уязвимости
            description: Описание уязвимости
            cve_id: CVE идентификатор
            affected_software: Список затронутого ПО
            references: Список ссылок
            
        Returns:
            AIDetectionResult с результатами анализа
        """
        affected_software = affected_software or []
        references = references or []
        
        # Объединяем весь текст для анализа
        combined_text = f"{title} {description} {cve_id} {' '.join(affected_software)} {' '.join(references)}"
        combined_text = combined_text.lower()
        
        # Анализируем совпадения
        matched_keywords = []
        confidence_scores = []
        matched_categories = []
        
        for category, keywords in self.ai_keywords.items():
            for keyword, weight in keywords.items():
                # Используем границы слов для точного совпадения
                pattern = r'\b' + re.escape(keyword) + r'\b'
                if re.search(pattern, combined_text, re.IGNORECASE):
                    matched_keywords.append(keyword)
                    confidence_scores.append(weight)
                    if category not in matched_categories:
                        matched_categories.append(category)
                    
                    self.logger.debug(f"Found keyword: {keyword} (category: {category}, weight: {weight})")
        
        # Вычисляем общую уверенность
        if confidence_scores:
            # Используем максимальный вес + бонус за количество совпадений
            max_confidence = max(confidence_scores)
            quantity_bonus = min(len(confidence_scores) * 0.05, 0.3)  # До +0.3 за количество
            total_confidence = min(max_confidence + quantity_bonus, 1.0)
        else:
            total_confidence = 0.0
        
        # Определяем, является ли AI-уязвимостью
        is_ai_related = total_confidence >= self.confidence_threshold
        
        # Генерируем теги
        suggested_tags = self._generate_tags(
            matched_keywords, 
            matched_categories, 
            combined_text
        )
        
        # Определяем множитель риска
        risk_multiplier = self._calculate_risk_multiplier(
            matched_categories,
            total_confidence
        )
        
        result = AIDetectionResult(
            is_ai_related=is_ai_related,
            confidence=total_confidence,
            matched_keywords=matched_keywords[:10],  # Топ-10 совпадений
            matched_categories=matched_categories,
            suggested_tags=suggested_tags,
            risk_multiplier=risk_multiplier
        )
        
        if is_ai_related:
            self.logger.info(
                f"🤖 AI-уязвимость обнаружена: "
                f"Confidence={total_confidence:.2f}, "
                f"Keywords={len(matched_keywords)}, "
                f"Tags={suggested_tags}"
            )
        
        return result
    
    def _generate_tags(self, 
                       matched_keywords: List[str], 
                       categories: List[str],
                       text: str) -> List[str]:
        """Генерация тегов на основе обнаруженных паттернов"""
        tags = set()
        
        # Основной тег AI
        if matched_keywords:
            tags.add('ai')
        
        # Теги по категориям
        if 'core_ai' in categories or 'platforms' in categories:
            tags.add('machine_learning')
            tags.add('neural_network')
        
        if 'products' in categories:
            tags.add('ai_product')
        
        if 'attacks' in categories:
            tags.add('ai_attack')
        
        # Специфичные теги по паттернам атак
        for attack_type, patterns in self.ai_attack_patterns.items():
            if any(pattern in text for pattern in patterns):
                tags.add(attack_type)
        
        # Теги по типам платформ
        if any(kw in matched_keywords for kw in ['tensorflow', 'pytorch', 'keras']):
            tags.add('ml_framework')
        
        if any(kw in matched_keywords for kw in ['gpt', 'chatgpt', 'llm', 'large language model']):
            tags.add('llm')
        
        if any(kw in matched_keywords for kw in ['langchain', 'llamaindex', 'autogpt']):
            tags.add('ai_agent')
        
        # Теги по типам атак
        if 'prompt injection' in text or 'jailbreak' in text:
            tags.add('prompt_injection')
            tags.add('critical_ai_attack')
        
        if 'adversarial' in text:
            tags.add('adversarial_attack')
        
        if any(kw in text for kw in ['model extraction', 'model stealing', 'model inversion']):
            tags.add('model_theft')
        
        return sorted(list(tags))
    
    def _calculate_risk_multiplier(self, 
                                   categories: List[str],
                                   confidence: float) -> float:
        """
        Вычисляет множитель риска для AI-уязвимостей
        AI-уязвимости обычно более критичны
        """
        base_multiplier = 1.0
        
        # Повышаем приоритет для атак
        if 'attacks' in categories:
            base_multiplier = 2.0
        elif 'core_ai' in categories or 'platforms' in categories:
            base_multiplier = 1.5
        elif 'products' in categories:
            base_multiplier = 1.3
        
        # Увеличиваем на основе уверенности
        confidence_bonus = confidence * 0.5  # До +0.5x
        
        return base_multiplier + confidence_bonus
    
    def batch_analyze(self, vulnerabilities: List[Dict]) -> List[Tuple[Dict, AIDetectionResult]]:
        """
        Пакетный анализ списка уязвимостей
        
        Args:
            vulnerabilities: Список словарей с уязвимостями
            
        Returns:
            Список кортежей (уязвимость, результат анализа)
        """
        results = []
        
        for vuln in vulnerabilities:
            result = self.analyze_vulnerability(
                title=vuln.get('title', ''),
                description=vuln.get('description', ''),
                cve_id=vuln.get('cve_id', ''),
                affected_software=vuln.get('affected_software', []),
                references=vuln.get('references', [])
            )
            results.append((vuln, result))
        
        ai_count = sum(1 for _, r in results if r.is_ai_related)
        self.logger.info(f"Batch analysis: {ai_count}/{len(vulnerabilities)} AI-уязвимостей")
        
        return results
    
    def get_statistics(self, results: List[AIDetectionResult]) -> Dict:
        """Получение статистики по результатам анализа"""
        total = len(results)
        ai_related = sum(1 for r in results if r.is_ai_related)
        
        if not results:
            return {
                'total': 0,
                'ai_related': 0,
                'percentage': 0.0,
                'avg_confidence': 0.0,
                'categories': {},
                'tags': {}
            }
        
        avg_confidence = sum(r.confidence for r in results if r.is_ai_related) / max(ai_related, 1)
        
        # Подсчет категорий
        category_counts = {}
        tag_counts = {}
        
        for result in results:
            if result.is_ai_related:
                for cat in result.matched_categories:
                    category_counts[cat] = category_counts.get(cat, 0) + 1
                for tag in result.suggested_tags:
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        return {
            'total': total,
            'ai_related': ai_related,
            'percentage': (ai_related / total * 100) if total > 0 else 0,
            'avg_confidence': avg_confidence,
            'categories': category_counts,
            'tags': tag_counts
        }


# Глобальный экземпляр
ai_tagger = AITaggerService()
