"""
Движок расчета рисков с использованием ML
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import numpy as np

from ml_platform.core.logger import PlatformLogger
from ml_platform.security.cve_passport import CVEPassport, SeverityLevel


@dataclass
class Asset:
    """Актив организации"""
    asset_id: str
    name: str
    asset_type: str  # server, application, network_device, etc.
    criticality: float  # 0.0 - 1.0
    business_value: float  # 0.0 - 1.0
    cpe_configurations: List[str]  # CPE строки для сопоставления
    network_exposure: float = 0.0  # 0.0 - 1.0
    compensating_controls: List[str] = None
    location: Optional[str] = None
    
    def __post_init__(self):
        if self.compensating_controls is None:
            self.compensating_controls = []


@dataclass
class RiskCalculation:
    """Результат расчета риска"""
    asset_id: str
    cve_id: str
    base_risk_score: float
    adjusted_risk_score: float
    risk_level: str  # Critical, High, Medium, Low
    factors: Dict[str, float]
    ml_correction_factor: float = 1.0
    calculated_at: datetime = None
    
    def __post_init__(self):
        if self.calculated_at is None:
            self.calculated_at = datetime.utcnow()


class RiskEngine:
    """Движок расчета рисков"""
    
    def __init__(self):
        """Инициализация движка рисков"""
        self.logger = PlatformLogger.get_logger()
        self.risk_calculations: List[RiskCalculation] = []
    
    def calculate_base_risk(
        self,
        passport: CVEPassport,
        asset: Asset
    ) -> float:
        """
        Расчет базового риска
        
        Args:
            passport: Паспорт CVE
            asset: Актив
            
        Returns:
            Базовый риск (0.0 - 1.0)
        """
        # Получение CVSS base score
        cvss_score = 0.0
        if passport.scoring.cvss_v3:
            cvss_score = passport.scoring.cvss_v3.get("base_score", 0.0) / 10.0
        elif passport.scoring.cvss_v2:
            cvss_score = passport.scoring.cvss_v2.get("base_score", 0.0) / 10.0
        
        # Учет критичности актива
        asset_criticality = asset.criticality
        
        # Учет бизнес-ценности
        business_value = asset.business_value
        
        # Базовый риск = CVSS × Критичность × Бизнес-ценность
        base_risk = cvss_score * asset_criticality * business_value
        
        return base_risk
    
    def calculate_exposure_factor(
        self,
        passport: CVEPassport,
        asset: Asset
    ) -> float:
        """
        Расчет фактора экспозиции
        
        Args:
            passport: Паспорт CVE
            asset: Актив
            
        Returns:
            Фактор экспозиции (0.0 - 1.0)
        """
        exposure = asset.network_exposure
        
        # Учет вектора атаки из CVSS
        if passport.scoring.cvss_v3:
            vector_string = passport.scoring.cvss_v3.get("vector_string", "")
            if "AV:N" in vector_string:  # Network
                exposure = max(exposure, 0.8)
            elif "AV:A" in vector_string:  # Adjacent
                exposure = max(exposure, 0.6)
            elif "AV:L" in vector_string:  # Local
                exposure = max(exposure, 0.4)
        
        return exposure
    
    def calculate_threat_likelihood(
        self,
        passport: CVEPassport
    ) -> float:
        """
        Расчет вероятности угрозы
        
        Args:
            passport: Паспорт CVE
            
        Returns:
            Вероятность угрозы (0.0 - 1.0)
        """
        likelihood = 0.5  # Базовая вероятность
        
        # Учет известной эксплуатации
        if passport.exploitability.known_exploited:
            likelihood = 0.9
        elif passport.exploitability.exploited_in_wild:
            if "Widely" in passport.exploitability.exploited_in_wild:
                likelihood = 0.95
            else:
                likelihood = 0.7
        
        # Учет наличия эксплойта
        if passport.exploitability.exploit_db_id:
            likelihood = min(likelihood + 0.1, 1.0)
        
        if passport.exploitability.metasploit_module:
            likelihood = min(likelihood + 0.15, 1.0)
        
        # Учет сложности атаки
        if passport.scoring.cvss_v3:
            vector_string = passport.scoring.cvss_v3.get("vector_string", "")
            if "AC:L" in vector_string:  # Low complexity
                likelihood = min(likelihood + 0.1, 1.0)
            elif "AC:H" in vector_string:  # High complexity
                likelihood = max(likelihood - 0.2, 0.1)
        
        # Учет ML предсказаний
        if passport.ml_predictions.propagation_likelihood:
            # Взвешенное среднее с ML предсказанием
            likelihood = 0.7 * likelihood + 0.3 * passport.ml_predictions.propagation_likelihood
        
        return likelihood
    
    def calculate_compensating_controls_factor(
        self,
        asset: Asset
    ) -> float:
        """
        Расчет фактора компенсирующих контролей
        
        Args:
            asset: Актив
            
        Returns:
            Фактор снижения риска (0.0 - 1.0)
        """
        # Базовое снижение риска
        reduction = 0.0
        
        # Типичные компенсирующие контроли и их эффективность
        control_effectiveness = {
            "firewall": 0.3,
            "ids_ips": 0.4,
            "waf": 0.5,
            "antivirus": 0.2,
            "edr": 0.6,
            "network_segmentation": 0.5,
            "access_control": 0.4,
            "patching": 0.8,
            "monitoring": 0.3
        }
        
        for control in asset.compensating_controls:
            control_lower = control.lower()
            for control_name, effectiveness in control_effectiveness.items():
                if control_name in control_lower:
                    reduction = max(reduction, effectiveness)
        
        # Комбинирование контролей (не аддитивно)
        if len(asset.compensating_controls) > 1:
            # Экспоненциальное снижение
            reduction = 1 - (1 - reduction) ** len(asset.compensating_controls)
        
        return 1.0 - reduction  # Фактор снижения риска
    
    def calculate_ml_correction_factor(
        self,
        passport: CVEPassport,
        asset: Asset,
        historical_incidents: Optional[List[Dict[str, Any]]] = None
    ) -> float:
        """
        Расчет ML корректирующего фактора
        
        Args:
            passport: Паспорт CVE
            asset: Актив
            historical_incidents: Исторические инциденты
            
        Returns:
            Корректирующий фактор (обычно 0.5 - 2.0)
        """
        correction = 1.0
        
        # Использование ML предсказаний
        if passport.ml_predictions.business_impact:
            # Корректировка на основе предсказанного бизнес-воздействия
            impact = passport.ml_predictions.business_impact
            correction *= (0.5 + impact)  # Масштабирование от 0.5 до 1.5
        
        # Учет исторических инцидентов
        if historical_incidents:
            similar_incidents = [
                inc for inc in historical_incidents
                if inc.get("cve_id") == passport.cve_id or
                   inc.get("asset_type") == asset.asset_type
            ]
            
            if similar_incidents:
                # Увеличение риска при наличии похожих инцидентов
                incident_count = len(similar_incidents)
                correction *= (1.0 + 0.1 * min(incident_count, 5))
        
        # Учет временных факторов
        if passport.published_date:
            days_since_publish = (datetime.utcnow() - passport.published_date).days
            
            # Новые уязвимости могут быть более рискованными
            if days_since_publish < 30:
                correction *= 1.2
            elif days_since_publish > 365:
                # Старые уязвимости могут быть менее актуальными
                correction *= 0.9
        
        return correction
    
    def calculate_risk(
        self,
        passport: CVEPassport,
        asset: Asset,
        use_ml_correction: bool = True,
        historical_incidents: Optional[List[Dict[str, Any]]] = None
    ) -> RiskCalculation:
        """
        Полный расчет риска
        
        Args:
            passport: Паспорт CVE
            asset: Актив
            use_ml_correction: Использовать ли ML коррекцию
            historical_incidents: Исторические инциденты
            
        Returns:
            Результат расчета риска
        """
        # Базовый риск
        base_risk = self.calculate_base_risk(passport, asset)
        
        # Факторы
        exposure_factor = self.calculate_exposure_factor(passport, asset)
        threat_likelihood = self.calculate_threat_likelihood(passport)
        controls_factor = self.calculate_compensating_controls_factor(asset)
        
        # Промежуточный риск
        intermediate_risk = base_risk * exposure_factor * threat_likelihood * controls_factor
        
        # ML коррекция
        ml_correction = 1.0
        if use_ml_correction:
            ml_correction = self.calculate_ml_correction_factor(
                passport, asset, historical_incidents
            )
        
        # Финальный риск
        adjusted_risk = intermediate_risk * ml_correction
        
        # Определение уровня риска
        if adjusted_risk >= 0.7:
            risk_level = "Critical"
        elif adjusted_risk >= 0.5:
            risk_level = "High"
        elif adjusted_risk >= 0.3:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        factors = {
            "base_risk": base_risk,
            "exposure_factor": exposure_factor,
            "threat_likelihood": threat_likelihood,
            "controls_factor": controls_factor,
            "ml_correction": ml_correction
        }
        
        calculation = RiskCalculation(
            asset_id=asset.asset_id,
            cve_id=passport.cve_id,
            base_risk_score=base_risk,
            adjusted_risk_score=adjusted_risk,
            risk_level=risk_level,
            factors=factors,
            ml_correction_factor=ml_correction
        )
        
        self.risk_calculations.append(calculation)
        
        return calculation
    
    def match_cve_to_assets(
        self,
        passport: CVEPassport,
        assets: List[Asset]
    ) -> List[Asset]:
        """
        Сопоставление CVE с активами через CPE matching
        
        Args:
            passport: Паспорт CVE
            assets: Список активов
            
        Returns:
            Список затронутых активов
        """
        affected_assets = []
        
        cve_cpes = {product.cpe for product in passport.affected_products}
        
        for asset in assets:
            # Проверка совпадения CPE
            for asset_cpe in asset.cpe_configurations:
                for cve_cpe in cve_cpes:
                    if self._cpe_matches(asset_cpe, cve_cpe):
                        affected_assets.append(asset)
                        break
        
        return affected_assets
    
    def _cpe_matches(self, asset_cpe: str, cve_cpe: str) -> bool:
        """
        Проверка совпадения CPE
        
        Args:
            asset_cpe: CPE актива
            cve_cpe: CPE из CVE
            
        Returns:
            True если совпадает
        """
        # Упрощенная проверка (в реальности нужен полноценный CPE парсер)
        # Проверка по vendor и product
        asset_parts = asset_cpe.split(":")
        cve_parts = cve_cpe.split(":")
        
        if len(asset_parts) >= 4 and len(cve_parts) >= 4:
            # vendor:product
            if asset_parts[3] == cve_parts[3] and asset_parts[4] == cve_parts[4]:
                return True
        
        return False
    
    def calculate_aggregate_risk(
        self,
        asset: Asset,
        risk_calculations: List[RiskCalculation]
    ) -> Dict[str, Any]:
        """
        Расчет агрегированного риска для актива
        
        Args:
            asset: Актив
            risk_calculations: Список расчетов рисков
            
        Returns:
            Агрегированный риск
        """
        asset_risks = [
            r for r in risk_calculations
            if r.asset_id == asset.asset_id
        ]
        
        if not asset_risks:
            return {
                "asset_id": asset.asset_id,
                "total_risks": 0,
                "aggregate_risk": 0.0,
                "max_risk": 0.0,
                "critical_count": 0,
                "high_count": 0
            }
        
        # Максимальный риск
        max_risk = max(r.adjusted_risk_score for r in asset_risks)
        
        # Средний риск
        avg_risk = np.mean([r.adjusted_risk_score for r in asset_risks])
        
        # Количество по уровням
        critical_count = sum(1 for r in asset_risks if r.risk_level == "Critical")
        high_count = sum(1 for r in asset_risks if r.risk_level == "High")
        
        # Агрегированный риск (взвешенное среднее)
        aggregate_risk = 0.7 * max_risk + 0.3 * avg_risk
        
        return {
            "asset_id": asset.asset_id,
            "total_risks": len(asset_risks),
            "aggregate_risk": aggregate_risk,
            "max_risk": max_risk,
            "avg_risk": avg_risk,
            "critical_count": critical_count,
            "high_count": high_count,
            "risk_level": "Critical" if aggregate_risk >= 0.7 else
                         "High" if aggregate_risk >= 0.5 else
                         "Medium" if aggregate_risk >= 0.3 else "Low"
        }
