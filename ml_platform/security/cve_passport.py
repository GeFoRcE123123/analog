"""
Система паспортизации CVE (CVE Passport)
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import json

from ml_platform.core.logger import PlatformLogger


class SeverityLevel(Enum):
    """Уровни критичности"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"


class AttackComplexity(Enum):
    """Сложность атаки"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class CVSSScoring:
    """CVSS скоринг"""
    cvss_v3: Optional[Dict[str, Any]] = None
    cvss_v4: Optional[Dict[str, Any]] = None
    cvss_v2: Optional[Dict[str, Any]] = None
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None


@dataclass
class AffectedProduct:
    """Затронутый продукт"""
    cpe: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    version_range: Optional[str] = None
    vulnerable: bool = True
    patch_available: bool = False
    patch_info: Optional[Dict[str, Any]] = None


@dataclass
class Exploitability:
    """Эксплуатируемость"""
    exploit_db_id: Optional[str] = None
    metasploit_module: Optional[str] = None
    known_exploited: bool = False
    exploited_in_wild: Optional[str] = None
    exploitation_rating: Optional[str] = None
    proof_of_concept: Optional[str] = None


@dataclass
class Remediation:
    """Ремедиация"""
    patches: List[Dict[str, Any]] = None
    workarounds: List[str] = None
    mitigation_score: Optional[float] = None
    remediation_steps: List[str] = None
    
    def __post_init__(self):
        if self.patches is None:
            self.patches = []
        if self.workarounds is None:
            self.workarounds = []
        if self.remediation_steps is None:
            self.remediation_steps = []


@dataclass
class MLPredictions:
    """ML предсказания"""
    risk_category: Optional[str] = None
    attack_complexity: Optional[str] = None
    propagation_likelihood: Optional[float] = None
    business_impact: Optional[float] = None
    confidence_score: Optional[float] = None
    time_to_exploit: Optional[int] = None  # дни до появления эксплойта


@dataclass
class AIClassificationData:
    """Данные AI классификации"""
    is_ai_related: bool = False
    confidence: float = 0.0
    ai_categories: List[str] = None
    reasoning: str = ""
    matched_keywords: List[str] = None
    owasp_categories: List[str] = None
    zero_day_assessment: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.ai_categories is None:
            self.ai_categories = []
        if self.matched_keywords is None:
            self.matched_keywords = []
        if self.owasp_categories is None:
            self.owasp_categories = []


@dataclass
class MetadataQuality:
    """Качество метаданных"""
    completeness_score: float = 0.0
    freshness_score: float = 0.0
    verified: bool = False
    data_sources: List[str] = None
    
    def __post_init__(self):
        if self.data_sources is None:
            self.data_sources = []


class CVEPassport:
    """Паспорт уязвимости CVE"""
    
    def __init__(self, cve_id: str):
        """
        Инициализация паспорта CVE
        
        Args:
            cve_id: Идентификатор CVE
        """
        self.cve_id = cve_id
        self.logger = PlatformLogger.get_logger()
        
        # Основная информация
        self.description: str = ""
        self.published_date: Optional[datetime] = None
        self.last_modified: Optional[datetime] = None
        self.data_sources: List[str] = []
        
        # Уязвимость
        self.cwe_id: Optional[str] = None
        self.cwe_ids: List[str] = []
        self.weakness_type: Optional[str] = None
        self.attack_vector: List[str] = []
        
        # Скоринг
        self.scoring = CVSSScoring()
        
        # Затронутые продукты
        self.affected_products: List[AffectedProduct] = []
        
        # Эксплуатируемость
        self.exploitability = Exploitability()
        
        # Ремедиация
        self.remediation = Remediation()
        
        # ML предсказания
        self.ml_predictions = MLPredictions()
        
        # AI классификация
        self.ai_classification: Optional[AIClassificationData] = None
        
        # Качество метаданных
        self.metadata_quality = MetadataQuality()
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь"""
        return {
            "metadata": {
                "cve_id": self.cve_id,
                "published_date": self.published_date.isoformat() if self.published_date else None,
                "last_modified": self.last_modified.isoformat() if self.last_modified else None,
                "data_sources": self.data_sources
            },
            "vulnerability": {
                "description": self.description,
                "cwe_id": self.cwe_id,
                "cwe_ids": self.cwe_ids,
                "weakness_type": self.weakness_type,
                "attack_vector": self.attack_vector
            },
            "scoring": {
                "cvss_v3": asdict(self.scoring.cvss_v3) if self.scoring.cvss_v3 else None,
                "cvss_v4": asdict(self.scoring.cvss_v4) if self.scoring.cvss_v4 else None,
                "cvss_v2": asdict(self.scoring.cvss_v2) if self.scoring.cvss_v2 else None,
                "temporal_score": self.scoring.temporal_score,
                "environmental_score": self.scoring.environmental_score
            },
            "affected_products": [asdict(product) for product in self.affected_products],
            "exploitability": asdict(self.exploitability),
            "remediation": asdict(self.remediation),
            "ml_predictions": asdict(self.ml_predictions),
            "ai_classification": asdict(self.ai_classification) if self.ai_classification else None,
            "metadata_quality": asdict(self.metadata_quality)
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Преобразование в JSON"""
        def datetime_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        return json.dumps(self.to_dict(), indent=indent, default=datetime_serializer)
    
    def calculate_metadata_quality(self):
        """Вычисление качества метаданных"""
        completeness_score = 0.0
        total_fields = 0
        filled_fields = 0
        
        # Проверка заполненности полей
        fields_to_check = [
            ("description", self.description),
            ("cwe_id", self.cwe_id),
            ("scoring.cvss_v3", self.scoring.cvss_v3),
            ("affected_products", len(self.affected_products) > 0),
            ("exploitability", self.exploitability.known_exploited is not None),
            ("remediation.patches", len(self.remediation.patches) > 0)
        ]
        
        for field_name, field_value in fields_to_check:
            total_fields += 1
            if field_value:
                filled_fields += 1
        
        if total_fields > 0:
            completeness_score = filled_fields / total_fields
        
        # Вычисление freshness score
        freshness_score = 1.0
        if self.last_modified:
            days_old = (datetime.utcnow() - self.last_modified).days
            # Экспоненциальное устаревание
            freshness_score = max(0.0, 1.0 - (days_old / 365.0))
        
        self.metadata_quality.completeness_score = completeness_score
        self.metadata_quality.freshness_score = freshness_score
        self.metadata_quality.data_sources = self.data_sources.copy()
    
    def get_severity(self) -> SeverityLevel:
        """Получение уровня критичности"""
        if self.scoring.cvss_v3:
            severity_str = self.scoring.cvss_v3.get("severity", "").upper()
            try:
                return SeverityLevel[severity_str]
            except KeyError:
                pass
        
        # Fallback на базовый score
        if self.scoring.cvss_v3:
            base_score = self.scoring.cvss_v3.get("base_score", 0)
            if base_score >= 9.0:
                return SeverityLevel.CRITICAL
            elif base_score >= 7.0:
                return SeverityLevel.HIGH
            elif base_score >= 4.0:
                return SeverityLevel.MEDIUM
            elif base_score > 0:
                return SeverityLevel.LOW
        
        return SeverityLevel.NONE
    
    def is_critical(self) -> bool:
        """Проверка критичности"""
        return self.get_severity() == SeverityLevel.CRITICAL
    
    def merge_with(self, other: 'CVEPassport'):
        """
        Объединение с другим паспортом (обогащение данными)
        
        Args:
            other: Другой паспорт CVE для объединения
        """
        if other.cve_id != self.cve_id:
            self.logger.warning(f"Попытка объединить разные CVE: {self.cve_id} и {other.cve_id}")
            return
        
        # Объединение источников данных
        self.data_sources.extend(other.data_sources)
        self.data_sources = list(set(self.data_sources))
        
        # Обогащение описания
        if not self.description and other.description:
            self.description = other.description
        
        # Объединение CWE
        self.cwe_ids.extend(other.cwe_ids)
        self.cwe_ids = list(set(self.cwe_ids))
        
        # Объединение затронутых продуктов
        existing_cpes = {p.cpe for p in self.affected_products}
        for product in other.affected_products:
            if product.cpe not in existing_cpes:
                self.affected_products.append(product)
        
        # Обогащение эксплуатируемости
        if not self.exploitability.known_exploited and other.exploitability.known_exploited:
            self.exploitability = other.exploitability
        
        # Объединение ремедиации
        self.remediation.patches.extend(other.remediation.patches)
        self.remediation.workarounds.extend(other.remediation.workarounds)
        
        # Пересчет качества метаданных
        self.calculate_metadata_quality()


class CVEPassportManager:
    """Менеджер паспортов CVE"""
    
    def __init__(self):
        """Инициализация менеджера"""
        self.logger = PlatformLogger.get_logger()
        self.passports: Dict[str, CVEPassport] = {}
    
    def create_passport(self, cve_id: str, normalized_data: Dict[str, Any]) -> CVEPassport:
        """
        Создание паспорта из нормализованных данных
        
        Args:
            cve_id: Идентификатор CVE
            normalized_data: Нормализованные данные из сборщика
            
        Returns:
            Созданный паспорт
        """
        passport = CVEPassport(cve_id)
        
        # Основная информация
        passport.description = normalized_data.get("description", "")
        if normalized_data.get("published_date"):
            try:
                passport.published_date = datetime.fromisoformat(
                    normalized_data["published_date"].replace("Z", "+00:00")
                )
            except:
                pass
        if normalized_data.get("last_modified"):
            try:
                passport.last_modified = datetime.fromisoformat(
                    normalized_data["last_modified"].replace("Z", "+00:00")
                )
            except:
                pass
        
        passport.data_sources = [normalized_data.get("source", "Unknown")]
        
        # CWE
        passport.cwe_ids = normalized_data.get("cwe_ids", [])
        if passport.cwe_ids:
            passport.cwe_id = passport.cwe_ids[0]
        
        # CVSS
        if normalized_data.get("cvss_v3"):
            passport.scoring.cvss_v3 = normalized_data["cvss_v3"]
        
        if normalized_data.get("cvss_v2"):
            passport.scoring.cvss_v2 = normalized_data["cvss_v2"]
        
        # Затронутые продукты
        for product_data in normalized_data.get("affected_products", []):
            product = AffectedProduct(
                cpe=product_data.get("cpe", ""),
                version_range=product_data.get("version_range")
            )
            passport.affected_products.append(product)
        
        # Пересчет качества
        passport.calculate_metadata_quality()
        
        # Сохранение
        self.passports[cve_id] = passport
        
        return passport
    
    def get_passport(self, cve_id: str) -> Optional[CVEPassport]:
        """Получение паспорта по CVE ID"""
        return self.passports.get(cve_id)
    
    def save_passport(self, passport: CVEPassport, storage_backend):
        """
        Сохранение паспорта в хранилище
        
        Args:
            passport: Паспорт для сохранения
            storage_backend: Бэкенд хранилища (ElasticSearch, PostgreSQL, etc.)
        """
        # Реализация зависит от выбранного хранилища
        pass
