#!/usr/bin/env python3
"""
Демонстрация работы сервиса анализа безопасности с AI классификацией
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Добавление пути к платформе
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml_platform.security.collectors.nvd_collector import NVDCollector
from ml_platform.security.cve_passport import CVEPassportManager
from ml_platform.security.ai_analysis.ai_classifier import HybridAIClassifier, AIClassifier
from ml_platform.security.risk_engine import RiskEngine, Asset
from ml_platform.core.logger import PlatformLogger

# Настройка логирования
logger = PlatformLogger.get_logger()


def print_section(title: str):
    """Печать заголовка секции"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_subsection(title: str):
    """Печать подзаголовка"""
    print(f"\n{'─' * 70}")
    print(f"  {title}")
    print(f"{'─' * 70}")


def demo_cve_collection():
    """Демонстрация сбора данных об уязвимостях"""
    print_section("1. СБОР ДАННЫХ ОБ УЯЗВИМОСТЯХ")
    
    print("\n📡 Инициализация NVD Collector...")
    nvd_collector = NVDCollector()
    
    print("🔍 Поиск уязвимостей, связанных с TensorFlow и PyTorch...")
    
    # Поиск уязвимостей по ключевым словам
    tensorflow_cves = nvd_collector.get_cves_by_keyword("TensorFlow", limit=3)
    pytorch_cves = nvd_collector.get_cves_by_keyword("PyTorch", limit=2)
    
    print(f"\n✅ Найдено уязвимостей TensorFlow: {len(tensorflow_cves)}")
    print(f"✅ Найдено уязвимостей PyTorch: {len(pytorch_cves)}")
    
    # Для демонстрации используем синтетические данные, если реальных мало
    demo_cves = []
    
    if len(tensorflow_cves) > 0:
        demo_cves.extend(tensorflow_cves[:2])
    if len(pytorch_cves) > 0:
        demo_cves.extend(pytorch_cves[:1])
    
    # Добавляем синтетические данные для демонстрации
    if len(demo_cves) < 3:
        print("\n📝 Использование демонстрационных данных...")
        demo_cves.append({
            "id": "CVE-2024-DEMO-001",
            "descriptions": [{
                "lang": "en",
                "value": "TensorFlow contains a vulnerability that allows remote code execution "
                        "through malicious model files. This affects TensorFlow versions 2.0 through 2.15. "
                        "The vulnerability is in the model loading mechanism and can be exploited "
                        "by crafting a malicious SavedModel or Keras model file."
            }],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9
                }]
            },
            "weaknesses": [{
                "description": [{
                    "lang": "en",
                    "value": "CWE-502"
                }]
            }],
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:google:tensorflow:2.0:*:*:*:*:*:*:*"
                    }]
                }]
            }],
            "published": "2024-01-15T00:00:00.000Z",
            "lastModified": "2024-01-20T00:00:00.000Z"
        })
        
        demo_cves.append({
            "id": "CVE-2024-DEMO-002",
            "descriptions": [{
                "lang": "en",
                "value": "PyTorch machine learning framework vulnerable to deserialization attack. "
                        "An attacker can execute arbitrary code by providing a malicious pickle file. "
                        "This affects PyTorch versions 1.0 through 2.0."
            }],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 8.8,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
                    }
                }]
            },
            "weaknesses": [{
                "description": [{
                    "lang": "en",
                    "value": "CWE-502"
                }]
            }],
            "published": "2024-02-01T00:00:00.000Z",
            "lastModified": "2024-02-05T00:00:00.000Z"
        })
    
    return demo_cves, nvd_collector


def demo_passport_creation(cves, nvd_collector):
    """Демонстрация создания паспортов CVE"""
    print_section("2. ПАСПОРТИЗАЦИЯ УЯЗВИМОСТЕЙ")
    
    passport_manager = CVEPassportManager()
    passports = []
    
    for i, cve_data in enumerate(cves, 1):
        print_subsection(f"CVE {i}: {cve_data.get('id', 'UNKNOWN')}")
        
        try:
            # Нормализация данных
            if cve_data.get('id', '').startswith('CVE-2024-DEMO'):
                # Для демо данных создаем нормализованную структуру напрямую
                normalized = {
                    "cve_id": cve_data["id"],
                    "description": cve_data["descriptions"][0]["value"] if cve_data.get("descriptions") else "",
                    "published_date": cve_data.get("published", ""),
                    "last_modified": cve_data.get("lastModified", ""),
                    "source": "DEMO",
                    "cvss_v3": {
                        "base_score": cve_data["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"],
                        "vector_string": cve_data["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"],
                        "severity": cve_data["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                    } if cve_data.get("metrics", {}).get("cvssMetricV31") else None,
                    "cwe_ids": [cve_data["weaknesses"][0]["description"][0]["value"]] if cve_data.get("weaknesses") else [],
                    "affected_products": [{
                        "cpe": cve_data["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"]
                    }] if cve_data.get("configurations") else []
                }
            else:
                normalized = nvd_collector.normalize_cve_data(cve_data)
            
            # Создание паспорта
            passport = passport_manager.create_passport(normalized["cve_id"], normalized)
            passports.append(passport)
            
            # Вывод информации
            print(f"  📋 Описание: {passport.description[:100]}...")
            print(f"  🔢 CVSS Score: {passport.scoring.cvss_v3.get('base_score', 'N/A') if passport.scoring.cvss_v3 else 'N/A'}")
            print(f"  ⚠️  Severity: {passport.get_severity().value}")
            print(f"  🏷️  CWE: {', '.join(passport.cwe_ids) if passport.cwe_ids else 'N/A'}")
            print(f"  📦 Затронутых продуктов: {len(passport.affected_products)}")
            
        except Exception as e:
            print(f"  ❌ Ошибка создания паспорта: {e}")
            logger.error(f"Ошибка создания паспорта: {e}", exc_info=True)
    
    print(f"\n✅ Всего создано паспортов: {len(passports)}")
    return passports


def demo_ai_classification(passports):
    """Демонстрация AI классификации"""
    print_section("3. AI КЛАССИФИКАЦИЯ УЯЗВИМОСТЕЙ")
    
    print("\n🤖 Инициализация AI классификатора...")
    print("   (Используется гибридный подход: внешний API + локальный fallback)")
    
    ai_classifier = HybridAIClassifier(
        external_api_url=None,  # Для демо используем только локальный
        use_external=False,
        use_local=True
    )
    
    ai_results = []
    
    for i, passport in enumerate(passports, 1):
        print_subsection(f"Анализ {i}: {passport.cve_id}")
        
        try:
            # AI классификация
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
            
            ai_results.append(classification)
            
            # Вывод результатов
            print(f"  {'✅' if classification.is_ai_related else '❌'} ИИ-связана: {classification.is_ai_related}")
            print(f"  📊 Уверенность: {classification.confidence:.2%}")
            print(f"  🏷️  Категории: {', '.join(classification.ai_categories) if classification.ai_categories else 'Нет'}")
            
            if classification.matched_keywords:
                print(f"  🔑 Найденные ключевые слова: {', '.join(classification.matched_keywords[:5])}")
                if len(classification.matched_keywords) > 5:
                    print(f"     ... и еще {len(classification.matched_keywords) - 5}")
            
            if classification.owasp_categories:
                print(f"  🛡️  OWASP категории: {', '.join(classification.owasp_categories)}")
            
            if classification.zero_day_assessment:
                zd = classification.zero_day_assessment
                print(f"  ⚠️  Zero-day потенциал: {'Да' if zd.get('has_zero_day_potential') else 'Нет'}")
                print(f"  📈 Risk score: {zd.get('risk_score', 0):.2f}")
            
            print(f"  💭 Обоснование: {classification.reasoning}")
            
        except Exception as e:
            print(f"  ❌ Ошибка классификации: {e}")
            logger.error(f"Ошибка классификации: {e}", exc_info=True)
    
    # Статистика
    print_subsection("Статистика AI анализа")
    ai_related_count = sum(1 for r in ai_results if r.is_ai_related)
    avg_confidence = sum(r.confidence for r in ai_results) / len(ai_results) if ai_results else 0
    
    print(f"  📊 Всего проанализировано: {len(ai_results)}")
    print(f"  🤖 ИИ-связанных: {ai_related_count} ({ai_related_count/len(ai_results)*100:.1f}%)")
    print(f"  📈 Средняя уверенность: {avg_confidence:.2%}")
    
    return passports


def demo_risk_calculation(passports):
    """Демонстрация расчета рисков"""
    print_section("4. РАСЧЕТ РИСКОВ")
    
    print("\n⚖️  Инициализация движка расчета рисков...")
    risk_engine = RiskEngine()
    
    # Создание активов
    print("\n📦 Создание активов организации...")
    
    assets = [
        Asset(
            asset_id="ml-server-01",
            name="ML Training Server",
            asset_type="server",
            criticality=0.95,
            business_value=0.9,
            cpe_configurations=[
                "cpe:2.3:a:google:tensorflow:2.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:pytorch:pytorch:1.0:*:*:*:*:*:*:*"
            ],
            network_exposure=0.7,
            compensating_controls=["firewall", "ids_ips", "network_segmentation"]
        ),
        Asset(
            asset_id="web-app-01",
            name="Web Application with ML Features",
            asset_type="application",
            criticality=0.8,
            business_value=0.85,
            cpe_configurations=[
                "cpe:2.3:a:vendor:ml_webapp:1.0:*:*:*:*:*:*:*"
            ],
            network_exposure=0.9,
            compensating_controls=["waf", "firewall"]
        )
    ]
    
    for asset in assets:
        print(f"  ✅ {asset.name} (ID: {asset.asset_id})")
        print(f"     Критичность: {asset.criticality:.2f}, Бизнес-ценность: {asset.business_value:.2f}")
        print(f"     Контроли: {', '.join(asset.compensating_controls)}")
    
    # Расчет рисков
    print_subsection("Расчет рисков для активов")
    
    risk_calculations = []
    
    for passport in passports:
        if not passport.ai_classification or not passport.ai_classification.is_ai_related:
            continue  # Пропускаем не ИИ-связанные для демо
        
        # Сопоставление с активами
        affected_assets = risk_engine.match_cve_to_assets(passport, assets)
        
        if not affected_assets:
            # Для демо добавляем все активы, если нет точного совпадения
            affected_assets = assets
        
        for asset in affected_assets:
            try:
                risk = risk_engine.calculate_risk(
                    passport=passport,
                    asset=asset,
                    use_ml_correction=True
                )
                risk_calculations.append(risk)
                
                print(f"\n  📋 {passport.cve_id} → {asset.name}")
                print(f"     Базовый риск: {risk.base_risk_score:.3f}")
                print(f"     Скорректированный риск: {risk.adjusted_risk_score:.3f}")
                print(f"     Уровень риска: {risk.risk_level}")
                print(f"     Факторы:")
                for factor, value in risk.factors.items():
                    print(f"       - {factor}: {value:.3f}")
                
            except Exception as e:
                print(f"  ❌ Ошибка расчета риска: {e}")
    
    # Агрегированные риски
    print_subsection("Агрегированные риски по активам")
    
    for asset in assets:
        aggregate = risk_engine.calculate_aggregate_risk(asset, risk_calculations)
        
        print(f"\n  🏢 {asset.name}")
        print(f"     Всего рисков: {aggregate['total_risks']}")
        print(f"     Агрегированный риск: {aggregate['aggregate_risk']:.3f}")
        print(f"     Максимальный риск: {aggregate['max_risk']:.3f}")
        print(f"     Уровень: {aggregate['risk_level']}")
        print(f"     Критических: {aggregate['critical_count']}, Высоких: {aggregate['high_count']}")
    
    return risk_calculations, assets


def demo_summary(passports, risk_calculations):
    """Итоговая сводка"""
    print_section("5. ИТОГОВАЯ СВОДКА")
    
    print("\n📊 Статистика анализа:")
    print(f"  • Всего проанализировано CVE: {len(passports)}")
    
    ai_related = sum(1 for p in passports if p.ai_classification and p.ai_classification.is_ai_related)
    print(f"  • ИИ-связанных уязвимостей: {ai_related}")
    
    critical_cves = sum(1 for p in passports if p.get_severity().value == "Critical")
    print(f"  • Критических уязвимостей: {critical_cves}")
    
    print(f"  • Всего расчетов рисков: {len(risk_calculations)}")
    
    if risk_calculations:
        critical_risks = sum(1 for r in risk_calculations if r.risk_level == "Critical")
        high_risks = sum(1 for r in risk_calculations if r.risk_level == "High")
        print(f"  • Критических рисков: {critical_risks}")
        print(f"  • Высоких рисков: {high_risks}")
    
    print("\n🎯 Рекомендации:")
    print("  1. Приоритизировать патчи для ИИ-связанных уязвимостей")
    print("  2. Усилить мониторинг ML серверов")
    print("  3. Проверить компенсирующие контроли")
    print("  4. Регулярно обновлять ИИ фреймворки")
    
    print("\n✅ Демонстрация завершена успешно!")


def main():
    """Основная функция демонстрации"""
    print("\n" + "=" * 70)
    print("  🛡️  ДЕМОНСТРАЦИЯ СЕРВИСА АНАЛИЗА БЕЗОПАСНОСТИ")
    print("     с AI классификацией уязвимостей")
    print("=" * 70)
    print(f"\n⏰ Время запуска: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # 1. Сбор данных
        cves, nvd_collector = demo_cve_collection()
        
        if not cves:
            print("\n⚠️  Не удалось получить данные об уязвимостях.")
            print("   Используются демонстрационные данные.")
            return
        
        # 2. Паспортизация
        passports = demo_passport_creation(cves, nvd_collector)
        
        if not passports:
            print("\n❌ Не удалось создать паспорты CVE.")
            return
        
        # 3. AI классификация
        passports = demo_ai_classification(passports)
        
        # 4. Расчет рисков
        risk_calculations, assets = demo_risk_calculation(passports)
        
        # 5. Итоговая сводка
        demo_summary(passports, risk_calculations)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Демонстрация прервана пользователем.")
    except Exception as e:
        print(f"\n\n❌ Ошибка во время демонстрации: {e}")
        logger.error("Ошибка демонстрации", exc_info=True)
        raise


if __name__ == "__main__":
    main()
