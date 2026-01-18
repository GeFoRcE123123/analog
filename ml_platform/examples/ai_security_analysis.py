"""
Пример AI анализа уязвимостей безопасности
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml_platform.security.collectors.nvd_collector import NVDCollector
from ml_platform.security.cve_passport import CVEPassportManager
from ml_platform.security.ai_analysis.ai_classifier import HybridAIClassifier
from ml_platform.core.logger import PlatformLogger

logger = PlatformLogger.get_logger()


def main():
    """Основная функция AI анализа"""
    
    print("=" * 60)
    print("AI анализ уязвимостей безопасности")
    print("=" * 60)
    
    # 1. Сбор данных
    print("\n1. Сбор данных об уязвимостях...")
    nvd_collector = NVDCollector()
    
    # Поиск уязвимостей, связанных с TensorFlow (пример)
    print("   Поиск уязвимостей, связанных с TensorFlow...")
    cves = nvd_collector.get_cves_by_keyword("TensorFlow", limit=5)
    print(f"   Найдено CVE: {len(cves)}")
    
    # 2. Паспортизация
    print("\n2. Паспортизация уязвимостей...")
    passport_manager = CVEPassportManager()
    
    passports = []
    for cve_data in cves:
        try:
            normalized = nvd_collector.normalize_cve_data(cve_data)
            passport = passport_manager.create_passport(
                normalized["cve_id"],
                normalized
            )
            passports.append(passport)
            print(f"   Создан паспорт: {passport.cve_id}")
        except Exception as e:
            logger.warning(f"Ошибка создания паспорта: {e}")
    
    # 3. AI классификация
    print("\n3. AI классификация уязвимостей...")
    ai_classifier = HybridAIClassifier()
    
    ai_results = []
    for passport in passports:
        classification = ai_classifier.classify(passport)
        
        # Сохранение в паспорт
        from ml_platform.security.cve_passport import AIClassificationData
        passport.ai_classification = AIClassificationData(
            is_ai_related=classification.is_ai_related,
            confidence=classification.confidence,
            ai_categories=classification.ai_categories,
            reasoning=classification.reasoning,
            matched_keywords=classification.matched_keywords,
            owasp_categories=classification.owasp_categories,
            zero_day_assessment=classification.zero_day_assessment
        )
        
        ai_results.append({
            'cve_id': passport.cve_id,
            'classification': classification
        })
        
        print(f"\n   {passport.cve_id}:")
        print(f"     ИИ-связана: {classification.is_ai_related}")
        print(f"     Уверенность: {classification.confidence:.2f}")
        print(f"     Категории: {', '.join(classification.ai_categories)}")
        print(f"     Ключевые слова: {', '.join(classification.matched_keywords[:5])}")
        if classification.owasp_categories:
            print(f"     OWASP: {', '.join(classification.owasp_categories)}")
        if classification.zero_day_assessment:
            zd = classification.zero_day_assessment
            print(f"     Zero-day потенциал: {zd.get('has_zero_day_potential', False)}")
            print(f"     Risk score: {zd.get('risk_score', 0):.2f}")
    
    # 4. Статистика
    print("\n4. Статистика AI анализа:")
    ai_related_count = sum(1 for r in ai_results if r['classification'].is_ai_related)
    avg_confidence = sum(r['classification'].confidence for r in ai_results) / len(ai_results) if ai_results else 0
    
    print(f"   Всего проанализировано: {len(ai_results)}")
    print(f"   ИИ-связанных: {ai_related_count} ({ai_related_count/len(ai_results)*100:.1f}%)")
    print(f"   Средняя уверенность: {avg_confidence:.2f}")
    
    # Распределение по категориям
    category_counts = {}
    for r in ai_results:
        for cat in r['classification'].ai_categories:
            category_counts[cat] = category_counts.get(cat, 0) + 1
    
    if category_counts:
        print("\n   Распределение по категориям:")
        for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"     {cat}: {count}")
    
    print("\n" + "=" * 60)
    print("AI анализ завершен!")
    print("=" * 60)


if __name__ == "__main__":
    main()
