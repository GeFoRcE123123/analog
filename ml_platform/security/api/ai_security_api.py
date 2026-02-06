"""
API endpoints для AI анализа уязвимостей
"""

from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from ml_platform.core.logger import PlatformLogger
from ml_platform.security.cve_passport import CVEPassportManager
from ml_platform.security.ai_analysis.ai_classifier import (
    HybridAIClassifier,
    AIClassification
)

router = APIRouter(prefix="/security/ai", tags=["security-ai"])

logger = PlatformLogger.get_logger()
passport_manager = CVEPassportManager()
ai_classifier = HybridAIClassifier()


class AnalyzeRequest(BaseModel):
    """Запрос на AI анализ"""
    cve_id: Optional[str] = None
    title: Optional[str] = None
    description: str
    cwe_ids: List[str] = []
    cvss_score: Optional[float] = None


class AnalyzeResponse(BaseModel):
    """Ответ AI анализа"""
    success: bool
    is_ai_related: bool
    confidence: float
    categories: List[str]
    reasoning: str
    matched_keywords: List[str] = []
    owasp_categories: List[str] = []
    zero_day_assessment: Optional[Dict[str, Any]] = None
    model_version: str = "hybrid-v1.0"


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_vulnerability(request: AnalyzeRequest):
    """
    Анализ уязвимости на ИИ-связанность
    
    Args:
        request: Данные уязвимости для анализа
        
    Returns:
        Результат AI анализа
    """
    try:
        # Попытка получить паспорт CVE
        passport = None
        if request.cve_id:
            passport = passport_manager.get_passport(request.cve_id)
        
        # Если паспорт не найден, создаем временный
        if not passport:
            from ml_platform.security.cve_passport import CVEPassport
            
            passport = CVEPassport(request.cve_id or "UNKNOWN")
            passport.description = request.description
            passport.cwe_ids = request.cwe_ids
            
            if request.cvss_score:
                passport.scoring.cvss_v3 = {
                    'base_score': request.cvss_score
                }
        
        # AI классификация
        classification = ai_classifier.classify(passport)
        
        # Сохранение в паспорт
        if passport:
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
        
        return AnalyzeResponse(
            success=True,
            is_ai_related=classification.is_ai_related,
            confidence=classification.confidence,
            categories=classification.ai_categories,
            reasoning=classification.reasoning,
            matched_keywords=classification.matched_keywords,
            owasp_categories=classification.owasp_categories,
            zero_day_assessment=classification.zero_day_assessment,
            model_version="hybrid-v1.0"
        )
    
    except Exception as e:
        logger.error(f"Ошибка AI анализа: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/classify/{cve_id}")
async def classify_cve(cve_id: str):
    """
    Классификация существующего CVE
    
    Args:
        cve_id: Идентификатор CVE
        
    Returns:
        Результат классификации
    """
    try:
        passport = passport_manager.get_passport(cve_id)
        
        if not passport:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} не найден")
        
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
        
        return AnalyzeResponse(
            success=True,
            is_ai_related=classification.is_ai_related,
            confidence=classification.confidence,
            categories=classification.ai_categories,
            reasoning=classification.reasoning,
            matched_keywords=classification.matched_keywords,
            owasp_categories=classification.owasp_categories,
            zero_day_assessment=classification.zero_day_assessment,
            model_version="hybrid-v1.0"
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка классификации CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch-analyze")
async def batch_analyze(cve_ids: List[str] = Body(...)):
    """
    Пакетный анализ нескольких CVE
    
    Args:
        cve_ids: Список CVE ID
        
    Returns:
        Результаты анализа
    """
    results = []
    
    for cve_id in cve_ids:
        try:
            passport = passport_manager.get_passport(cve_id)
            
            if not passport:
                results.append({
                    'cve_id': cve_id,
                    'success': False,
                    'error': 'CVE not found'
                })
                continue
            
            # AI классификация
            classification = ai_classifier.classify(passport)
            
            results.append({
                'cve_id': cve_id,
                'success': True,
                'is_ai_related': classification.is_ai_related,
                'confidence': classification.confidence,
                'categories': classification.ai_categories
            })
        
        except Exception as e:
            results.append({
                'cve_id': cve_id,
                'success': False,
                'error': str(e)
            })
    
    return {
        'total': len(cve_ids),
        'processed': len([r for r in results if r.get('success')]),
        'results': results
    }


@router.get("/stats")
async def get_ai_stats():
    """
    Статистика по AI-связанным уязвимостям
    
    Returns:
        Статистика
    """
    try:
        passports = list(passport_manager.passports.values())
        
        total = len(passports)
        ai_related = sum(
            1 for p in passports
            if p.ai_classification and p.ai_classification.is_ai_related
        )
        
        # Распределение по категориям
        category_counts = {}
        for p in passports:
            if p.ai_classification and p.ai_classification.is_ai_related:
                for cat in p.ai_classification.ai_categories:
                    category_counts[cat] = category_counts.get(cat, 0) + 1
        
        return {
            'total_cves': total,
            'ai_related_count': ai_related,
            'ai_related_percentage': (ai_related / total * 100) if total > 0 else 0.0,
            'category_distribution': category_counts
        }
    
    except Exception as e:
        logger.error(f"Ошибка получения статистики: {e}")
        raise HTTPException(status_code=500, detail=str(e))
