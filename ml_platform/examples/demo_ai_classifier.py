#!/usr/bin/env python3
"""
Демонстрация работы AI классификатора уязвимостей
Работает без запуска API сервера
"""

import sys
from pathlib import Path

# Добавление пути к модулям
sys.path.insert(0, str(Path(__file__).parent.parent))

from security.ai_analysis.ai_classifier import AIClassifier
from security.cve_passport import CVEPassport

print("=" * 60)
print("Демонстрация AI классификатора уязвимостей")
print("=" * 60)
print()

# Создание классификатора
classifier = AIClassifier()

# Тест 1: TensorFlow уязвимость
print("1. AI анализ уязвимости (TensorFlow)...")
tf_passport = CVEPassport("CVE-2024-DEMO-001")
tf_passport.description = "TensorFlow contains a vulnerability that allows remote code execution through malicious model files. This affects TensorFlow versions 2.0 through 2.15."
tf_passport.cwe_ids = ["CWE-502"]
tf_passport.scoring.cvss_v3 = {"base_score": 9.8}

tf_classification = classifier.classify_passport(tf_passport)
print(f"   CVE ID: {tf_passport.cve_id}")
print(f"   ИИ-связана: {tf_classification.is_ai_related}")
print(f"   Уверенность: {tf_classification.confidence:.2f}")
print(f"   Категории: {', '.join(tf_classification.ai_categories)}")
print(f"   Ключевые слова: {', '.join(tf_classification.matched_keywords[:5])}")
print(f"   Обоснование: {tf_classification.reasoning}")
print()

# Тест 2: PyTorch уязвимость
print("2. AI анализ уязвимости (PyTorch)...")
pt_passport = CVEPassport("CVE-2024-DEMO-002")
pt_passport.description = "PyTorch machine learning framework vulnerable to deserialization attack. An attacker can execute arbitrary code by providing a malicious pickle file."
pt_passport.cwe_ids = ["CWE-502"]
pt_passport.scoring.cvss_v3 = {"base_score": 8.8}

pt_classification = classifier.classify_passport(pt_passport)
print(f"   CVE ID: {pt_passport.cve_id}")
print(f"   ИИ-связана: {pt_classification.is_ai_related}")
print(f"   Уверенность: {pt_classification.confidence:.2f}")
print(f"   Категории: {', '.join(pt_classification.ai_categories)}")
print(f"   Ключевые слова: {', '.join(pt_classification.matched_keywords[:5])}")
print(f"   Обоснование: {pt_classification.reasoning}")
print()

# Тест 3: Обычная уязвимость (не ИИ)
print("3. AI анализ обычной уязвимости (не ИИ)...")
normal_passport = CVEPassport("CVE-2024-DEMO-003")
normal_passport.description = "Apache HTTP Server vulnerable to buffer overflow in mod_rewrite module. Remote attackers can cause denial of service."
normal_passport.cwe_ids = ["CWE-120"]
normal_passport.scoring.cvss_v3 = {"base_score": 7.5}

normal_classification = classifier.classify_passport(normal_passport)
print(f"   CVE ID: {normal_passport.cve_id}")
print(f"   ИИ-связана: {normal_classification.is_ai_related}")
print(f"   Уверенность: {normal_classification.confidence:.2f}")
print(f"   Категории: {', '.join(normal_classification.ai_categories) if normal_classification.ai_categories else 'нет'}")
print(f"   Обоснование: {normal_classification.reasoning}")
print()

# Статистика
print("4. Статистика анализа...")
total = 3
ai_related = sum([
    tf_classification.is_ai_related,
    pt_classification.is_ai_related,
    normal_classification.is_ai_related
])
avg_confidence = sum([
    tf_classification.confidence,
    pt_classification.confidence,
    normal_classification.confidence
]) / total

print(f"   Всего проанализировано: {total}")
print(f"   ИИ-связанных: {ai_related} ({ai_related/total*100:.1f}%)")
print(f"   Средняя уверенность: {avg_confidence:.2f}")
print()

# Распределение по категориям
category_counts = {}
for classification in [tf_classification, pt_classification, normal_classification]:
    for cat in classification.ai_categories:
        category_counts[cat] = category_counts.get(cat, 0) + 1

if category_counts:
    print("   Распределение по категориям:")
    for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"     {cat}: {count}")

print()
print("=" * 60)
print("Демонстрация завершена")
print("=" * 60)
