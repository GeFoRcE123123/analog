"""
Пример полного анализа безопасности с использованием платформы
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ml_platform.security.collectors.nvd_collector import NVDCollector
from ml_platform.security.cve_passport import CVEPassportManager
from ml_platform.security.risk_engine import RiskEngine, Asset
from ml_platform.security.visualization.security_dashboard import SecurityVisualizer
from ml_platform.security.ml_models.vulnerability_classifier import VulnerabilityClassifierTrainer
from ml_platform.core.logger import PlatformLogger

logger = PlatformLogger.get_logger()


def main():
    """Основная функция анализа безопасности"""
    
    print("=" * 60)
    print("Анализ информационной безопасности")
    print("=" * 60)
    
    # 1. Сбор данных об уязвимостях
    print("\n1. Сбор данных об уязвимостях...")
    nvd_collector = NVDCollector()
    
    # Сбор недавних CVE (для демонстрации используем небольшой период)
    print("   Сбор недавних CVE из NVD...")
    recent_cves = nvd_collector.get_recent_cves(days=7)
    print(f"   Найдено CVE: {len(recent_cves)}")
    
    # 2. Паспортизация
    print("\n2. Паспортизация уязвимостей...")
    passport_manager = CVEPassportManager()
    
    passports = []
    for cve_data in recent_cves[:10]:  # Ограничиваем для демонстрации
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
    
    print(f"   Всего паспортов создано: {len(passports)}")
    
    # 3. Статистика по критичности
    print("\n3. Статистика по критичности:")
    severity_counts = {}
    for p in passports:
        severity = p.get_severity().value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in severity_counts.items():
        print(f"   {severity}: {count}")
    
    # 4. Создание активов
    print("\n4. Создание активов...")
    assets = [
        Asset(
            asset_id="web-server-01",
            name="Web Server Production",
            asset_type="server",
            criticality=0.9,
            business_value=0.95,
            cpe_configurations=[
                "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"
            ],
            network_exposure=0.8,
            compensating_controls=["firewall", "ids_ips", "waf"]
        ),
        Asset(
            asset_id="db-server-01",
            name="Database Server",
            asset_type="server",
            criticality=0.95,
            business_value=1.0,
            cpe_configurations=[
                "cpe:2.3:a:oracle:mysql:8.0:*:*:*:*:*:*:*"
            ],
            network_exposure=0.3,
            compensating_controls=["network_segmentation", "access_control"]
        ),
        Asset(
            asset_id="app-server-01",
            name="Application Server",
            asset_type="application",
            criticality=0.7,
            business_value=0.8,
            cpe_configurations=[
                "cpe:2.3:a:nodejs:nodejs:18.0:*:*:*:*:*:*:*"
            ],
            network_exposure=0.6,
            compensating_controls=["firewall"]
        )
    ]
    
    print(f"   Создано активов: {len(assets)}")
    
    # 5. Расчет рисков
    print("\n5. Расчет рисков...")
    risk_engine = RiskEngine()
    
    risk_calculations = []
    for passport in passports:
        # Сопоставление с активами
        affected_assets = risk_engine.match_cve_to_assets(passport, assets)
        
        for asset in affected_assets:
            try:
                risk = risk_engine.calculate_risk(
                    passport=passport,
                    asset=asset,
                    use_ml_correction=True
                )
                risk_calculations.append(risk)
                print(
                    f"   {passport.cve_id} -> {asset.name}: "
                    f"{risk.risk_level} (score: {risk.adjusted_risk_score:.2f})"
                )
            except Exception as e:
                logger.warning(f"Ошибка расчета риска: {e}")
    
    print(f"   Всего расчетов рисков: {len(risk_calculations)}")
    
    # 6. Агрегированные риски по активам
    print("\n6. Агрегированные риски по активам:")
    for asset in assets:
        aggregate = risk_engine.calculate_aggregate_risk(asset, risk_calculations)
        print(
            f"   {asset.name}: "
            f"{aggregate['risk_level']} "
            f"(score: {aggregate['aggregate_risk']:.2f}, "
            f"risks: {aggregate['total_risks']})"
        )
    
    # 7. Визуализация
    print("\n7. Создание визуализаций...")
    visualizer = SecurityVisualizer()
    
    try:
        report_files = visualizer.create_security_report(
            passports=passports,
            risk_calculations=risk_calculations,
            assets=assets
        )
        
        print("   Созданные графики:")
        for name, path in report_files.items():
            print(f"     {name}: {path}")
    except Exception as e:
        logger.error(f"Ошибка создания визуализаций: {e}")
    
    # 8. ML классификация (опционально)
    print("\n8. ML классификация уязвимостей...")
    if len(passports) >= 5:  # Минимум данных для обучения
        try:
            trainer = VulnerabilityClassifierTrainer()
            print("   Обучение модели...")
            trainer.train(passports, epochs=50)
            
            print("   Предсказания для нескольких CVE:")
            for passport in passports[:3]:
                predictions = trainer.predict(passport)
                print(
                    f"     {passport.cve_id}: "
                    f"Severity={predictions['severity']}, "
                    f"Attack Type={predictions['attack_type']}"
                )
        except Exception as e:
            logger.warning(f"Ошибка ML классификации: {e}")
    
    print("\n" + "=" * 60)
    print("Анализ безопасности завершен!")
    print("=" * 60)


if __name__ == "__main__":
    main()
