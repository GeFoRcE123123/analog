#!/usr/bin/env python3
"""
Упрощенная демонстрация AI классификатора
Работает без зависимостей от структуры пакетов
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass

# Упрощенный AI классификатор
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
        'generative ai', 'stable diffusion', 'chatgpt', 'claude'
    ],
    'techniques': [
        'computer vision', 'nlp', 'natural language processing',
        'reinforcement learning', 'convolutional', 'recurrent', 'lstm'
    ],
    'threats': [
        'adversarial attack', 'model poisoning', 'prompt injection',
        'jailbreak', 'model extraction'
    ]
}

@dataclass
class Classification:
    is_ai_related: bool
    confidence: float
    categories: List[str]
    reasoning: str
    matched_keywords: List[str]

def classify_vulnerability(description: str, cve_id: str = "") -> Classification:
    """Классификация уязвимости на ИИ-связанность"""
    text = description.lower()
    
    categories = []
    matches = []
    total_score = 0.0
    
    weights = {
        'core_ai': 1.0,
        'frameworks': 0.9,
        'models': 0.95,
        'techniques': 0.8,
        'threats': 1.0
    }
    
    for category, keywords in AI_KEYWORDS.items():
        category_matches = []
        weight = weights.get(category, 0.5)
        
        for keyword in keywords:
            pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
            if re.search(pattern, text, re.IGNORECASE):
                category_matches.append(keyword)
                total_score += weight
                matches.append(keyword)
        
        if category_matches:
            categories.append(category)
    
    # Порог снижен для лучшего определения ИИ-связанных уязвимостей
    is_ai_related = total_score >= 0.9  # Снижен порог
    confidence = min(1.0, total_score / 5.0)  # Увеличена нормализация
    
    if matches:
        reasoning = f"Найдены ключевые слова ИИ/ML: {', '.join(matches[:5])}"
        if len(matches) > 5:
            reasoning += f" и еще {len(matches) - 5}"
    else:
        reasoning = "ИИ-связанные ключевые слова не обнаружены"
    
    return Classification(
        is_ai_related=is_ai_related,
        confidence=confidence,
        categories=categories,
        reasoning=reasoning,
        matched_keywords=matches
    )

print("=" * 60)
print("Демонстрация AI классификатора уязвимостей")
print("=" * 60)
print()

# Тест 1: TensorFlow
print("1. AI анализ уязвимости (TensorFlow)...")
tf_desc = "TensorFlow contains a vulnerability that allows remote code execution through malicious model files. This affects TensorFlow versions 2.0 through 2.15."
tf_result = classify_vulnerability(tf_desc, "CVE-2024-DEMO-001")
print(f"   CVE ID: CVE-2024-DEMO-001")
print(f"   ИИ-связана: {tf_result.is_ai_related}")
print(f"   Уверенность: {tf_result.confidence:.2f}")
print(f"   Категории: {', '.join(tf_result.categories)}")
print(f"   Ключевые слова: {', '.join(tf_result.matched_keywords[:5])}")
print(f"   Обоснование: {tf_result.reasoning}")
print()

# Тест 2: PyTorch
print("2. AI анализ уязвимости (PyTorch)...")
pt_desc = "PyTorch machine learning framework vulnerable to deserialization attack. An attacker can execute arbitrary code by providing a malicious pickle file."
pt_result = classify_vulnerability(pt_desc, "CVE-2024-DEMO-002")
print(f"   CVE ID: CVE-2024-DEMO-002")
print(f"   ИИ-связана: {pt_result.is_ai_related}")
print(f"   Уверенность: {pt_result.confidence:.2f}")
print(f"   Категории: {', '.join(pt_result.categories)}")
print(f"   Ключевые слова: {', '.join(pt_result.matched_keywords[:5])}")
print(f"   Обоснование: {pt_result.reasoning}")
print()

# Тест 3: Обычная уязвимость
print("3. AI анализ обычной уязвимости (не ИИ)...")
normal_desc = "Apache HTTP Server vulnerable to buffer overflow in mod_rewrite module. Remote attackers can cause denial of service."
normal_result = classify_vulnerability(normal_desc, "CVE-2024-DEMO-003")
print(f"   CVE ID: CVE-2024-DEMO-003")
print(f"   ИИ-связана: {normal_result.is_ai_related}")
print(f"   Уверенность: {normal_result.confidence:.2f}")
print(f"   Категории: {', '.join(normal_result.categories) if normal_result.categories else 'нет'}")
print(f"   Обоснование: {normal_result.reasoning}")
print()

# Статистика
print("4. Статистика анализа...")
results = [tf_result, pt_result, normal_result]
total = len(results)
ai_related = sum(1 for r in results if r.is_ai_related)
avg_confidence = sum(r.confidence for r in results) / total

print(f"   Всего проанализировано: {total}")
print(f"   ИИ-связанных: {ai_related} ({ai_related/total*100:.1f}%)")
print(f"   Средняя уверенность: {avg_confidence:.2f}")

category_counts = {}
for r in results:
    for cat in r.categories:
        category_counts[cat] = category_counts.get(cat, 0) + 1

if category_counts:
    print("\n   Распределение по категориям:")
    for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"     {cat}: {count}")

print()
print("=" * 60)
print("Демонстрация завершена")
print("=" * 60)
