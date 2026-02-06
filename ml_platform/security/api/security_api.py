"""
API endpoints для анализа безопасности
"""

from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

from ml_platform.core.logger import PlatformLogger
from ml_platform.security.collectors.nvd_collector import NVDCollector
from ml_platform.security.collectors.osv_collector import OSVCollector
from ml_platform.security.collectors.github_security_collector import GitHubSecurityCollector
from ml_platform.security.cve_passport import CVEPassport, CVEPassportManager
from ml_platform.security.risk_engine import RiskEngine, Asset
from ml_platform.security.ml_models.vulnerability_classifier import VulnerabilityClassifierTrainer

router = APIRouter(prefix="/security", tags=["security"])

logger = PlatformLogger.get_logger()
nvd_collector = NVDCollector()
osv_collector = OSVCollector()
github_collector = GitHubSecurityCollector()
passport_manager = CVEPassportManager()
risk_engine = RiskEngine()


class CVERequest(BaseModel):
    """Запрос на получение CVE"""
    cve_id: str


class AssetRequest(BaseModel):
    """Запрос на создание актива"""
    asset_id: str
    name: str
    asset_type: str
    criticality: float
    business_value: float
    cpe_configurations: List[str]
    network_exposure: float = 0.0
    compensating_controls: List[str] = []


class RiskCalculationRequest(BaseModel):
    """Запрос на расчет риска"""
    cve_id: str
    asset_id: str
    use_ml_correction: bool = True


@router.get("/cve/{cve_id}")
async def get_cve_passport(cve_id: str):
    """
    Получение паспорта CVE
    
    Args:
        cve_id: Идентификатор CVE
        
    Returns:
        Паспорт CVE
    """
    try:
        # Попытка получить из кэша
        passport = passport_manager.get_passport(cve_id)
        
        if not passport:
            # Сбор данных из источников
            nvd_data = nvd_collector.get_cve_by_id(cve_id)
            
            if not nvd_data:
                raise HTTPException(status_code=404, detail=f"CVE {cve_id} не найден")
            
            # Нормализация и создание паспорта
            normalized = nvd_collector.normalize_cve_data(nvd_data)
            passport = passport_manager.create_passport(cve_id, normalized)
        
        return passport.to_dict()
    
    except Exception as e:
        logger.error(f"Ошибка получения CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cve/collect")
async def collect_recent_cves(days: int = Query(7, ge=1, le=365)):
    """
    Сбор недавних CVE
    
    Args:
        days: Количество дней назад
        
    Returns:
        Список собранных CVE
    """
    try:
        cves = nvd_collector.get_recent_cves(days=days)
        
        passports = []
        for cve_data in cves:
            normalized = nvd_collector.normalize_cve_data(cve_data)
            passport = passport_manager.create_passport(normalized["cve_id"], normalized)
            passports.append(passport.to_dict())
        
        return {
            "collected": len(passports),
            "cves": passports
        }
    
    except Exception as e:
        logger.error(f"Ошибка сбора CVE: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/assets")
async def create_asset(asset: AssetRequest):
    """
    Создание актива
    
    Args:
        asset: Данные актива
        
    Returns:
        Созданный актив
    """
    try:
        asset_obj = Asset(
            asset_id=asset.asset_id,
            name=asset.name,
            asset_type=asset.asset_type,
            criticality=asset.criticality,
            business_value=asset.business_value,
            cpe_configurations=asset.cpe_configurations,
            network_exposure=asset.network_exposure,
            compensating_controls=asset.compensating_controls
        )
        
        return {
            "asset_id": asset_obj.asset_id,
            "name": asset_obj.name,
            "status": "created"
        }
    
    except Exception as e:
        logger.error(f"Ошибка создания актива: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/risk/calculate")
async def calculate_risk(request: RiskCalculationRequest, assets: List[AssetRequest] = Body(...)):
    """
    Расчет риска для CVE и актива
    
    Args:
        request: Параметры расчета
        assets: Список активов
        
    Returns:
        Результат расчета риска
    """
    try:
        # Получение паспорта CVE
        passport = passport_manager.get_passport(request.cve_id)
        if not passport:
            raise HTTPException(status_code=404, detail=f"CVE {request.cve_id} не найден")
        
        # Поиск актива
        asset_data = next((a for a in assets if a.asset_id == request.asset_id), None)
        if not asset_data:
            raise HTTPException(status_code=404, detail=f"Актив {request.asset_id} не найден")
        
        asset = Asset(
            asset_id=asset_data.asset_id,
            name=asset_data.name,
            asset_type=asset_data.asset_type,
            criticality=asset_data.criticality,
            business_value=asset_data.business_value,
            cpe_configurations=asset_data.cpe_configurations,
            network_exposure=asset_data.network_exposure,
            compensating_controls=asset_data.compensating_controls
        )
        
        # Расчет риска
        risk_calc = risk_engine.calculate_risk(
            passport=passport,
            asset=asset,
            use_ml_correction=request.use_ml_correction
        )
        
        return {
            "asset_id": risk_calc.asset_id,
            "cve_id": risk_calc.cve_id,
            "base_risk_score": risk_calc.base_risk_score,
            "adjusted_risk_score": risk_calc.adjusted_risk_score,
            "risk_level": risk_calc.risk_level,
            "factors": risk_calc.factors,
            "calculated_at": risk_calc.calculated_at.isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка расчета риска: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/risk/batch")
async def calculate_batch_risks(
    cve_ids: List[str] = Body(...),
    assets: List[AssetRequest] = Body(...),
    use_ml_correction: bool = True
):
    """
    Пакетный расчет рисков
    
    Args:
        cve_ids: Список CVE ID
        assets: Список активов
        use_ml_correction: Использовать ML коррекцию
        
    Returns:
        Список расчетов рисков
    """
    try:
        asset_objects = [
            Asset(
                asset_id=a.asset_id,
                name=a.name,
                asset_type=a.asset_type,
                criticality=a.criticality,
                business_value=a.business_value,
                cpe_configurations=a.cpe_configurations,
                network_exposure=a.network_exposure,
                compensating_controls=a.compensating_controls
            )
            for a in assets
        ]
        
        results = []
        
        for cve_id in cve_ids:
            passport = passport_manager.get_passport(cve_id)
            if not passport:
                continue
            
            # Сопоставление с активами
            affected_assets = risk_engine.match_cve_to_assets(passport, asset_objects)
            
            for asset in affected_assets:
                risk_calc = risk_engine.calculate_risk(
                    passport=passport,
                    asset=asset,
                    use_ml_correction=use_ml_correction
                )
                
                results.append({
                    "asset_id": risk_calc.asset_id,
                    "cve_id": risk_calc.cve_id,
                    "risk_score": risk_calc.adjusted_risk_score,
                    "risk_level": risk_calc.risk_level
                })
        
        return {
            "total_calculations": len(results),
            "results": results
        }
    
    except Exception as e:
        logger.error(f"Ошибка пакетного расчета рисков: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/risk/aggregate/{asset_id}")
async def get_aggregate_risk(asset_id: str, assets: List[AssetRequest] = Body(...)):
    """
    Получение агрегированного риска для актива
    
    Args:
        asset_id: ID актива
        assets: Список активов
        
    Returns:
        Агрегированный риск
    """
    try:
        asset_data = next((a for a in assets if a.asset_id == asset_id), None)
        if not asset_data:
            raise HTTPException(status_code=404, detail=f"Актив {asset_id} не найден")
        
        asset = Asset(
            asset_id=asset_data.asset_id,
            name=asset_data.name,
            asset_type=asset_data.asset_type,
            criticality=asset_data.criticality,
            business_value=asset_data.business_value,
            cpe_configurations=asset_data.cpe_configurations,
            network_exposure=asset_data.network_exposure,
            compensating_controls=asset_data.compensating_controls
        )
        
        aggregate = risk_engine.calculate_aggregate_risk(
            asset=asset,
            risk_calculations=risk_engine.risk_calculations
        )
        
        return aggregate
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка получения агрегированного риска: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_security_stats():
    """
    Получение статистики безопасности
    
    Returns:
        Статистика
    """
    try:
        passports = list(passport_manager.passports.values())
        
        total_cves = len(passports)
        critical_count = sum(1 for p in passports if p.is_critical())
        
        risk_calculations = risk_engine.risk_calculations
        total_risks = len(risk_calculations)
        critical_risks = sum(1 for r in risk_calculations if r.risk_level == "Critical")
        
        return {
            "total_cves": total_cves,
            "critical_cves": critical_count,
            "total_risk_calculations": total_risks,
            "critical_risks": critical_risks,
            "avg_risk_score": sum(r.adjusted_risk_score for r in risk_calculations) / total_risks if total_risks > 0 else 0.0
        }
    
    except Exception as e:
        logger.error(f"Ошибка получения статистики: {e}")
        raise HTTPException(status_code=500, detail=str(e))
