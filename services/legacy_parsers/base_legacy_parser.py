"""
Базовый класс для legacy парсеров из папки pars/
Адаптирует старые парсеры под новую структуру проекта
"""
import logging
import re
from typing import List, Dict, Any, Optional
from datetime import datetime
from abc import ABC, abstractmethod

from models.entities import Vulnerability
from models.legacy_repositories import LegacyVulnerabilityRepository

logger = logging.getLogger(__name__)


class BaseLegacyParser(ABC):
    """
    Базовый класс для всех legacy парсеров
    """
    
    def __init__(self, name: str, vulnerability_repo: LegacyVulnerabilityRepository):
        self.name = name
        self.vulnerability_repo = vulnerability_repo
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
    
    @abstractmethod
    def parse(self, **kwargs) -> Dict[str, Any]:
        """
        Основной метод парсинга
        
        Returns:
            Dict с ключами: parsed, saved, errors
        """
        pass
    
    def _create_vulnerability(
        self,
        cve_id: str,
        title: str,
        description: str,
        cvss_score: float,
        source: str,
        link: str,
        etc_data: Optional[Dict] = None
    ) -> Vulnerability:
        """
        Создать объект Vulnerability из данных парсера
        
        Args:
            cve_id: CVE идентификатор
            title: Название уязвимости
            description: Описание
            cvss_score: CVSS score
            source: Источник данных
            link: Ссылка на уязвимость
            etc_data: Дополнительные данные (JSON)
            
        Returns:
            Vulnerability объект
        """
        # Определяем severity на основе CVSS
        if cvss_score >= 9.0:
            severity = 'critical'
        elif cvss_score >= 7.0:
            severity = 'high'
        elif cvss_score >= 4.0:
            severity = 'medium'
        else:
            severity = 'low'
        
        # Определяем risk_level
        risk_level = severity
        
        # Формируем etc данные
        etc_dict = etc_data or {}
        etc_dict.update({
            'category': source.lower(),
            'risk_level': risk_level,
            'status': 'new',
            'approved': False,
            'modifications': 0
        })
        
        vulnerability = Vulnerability(
            id=0,  # БД назначит ID
            cve_id=cve_id,
            title=title[:500] if len(title) > 500 else title,
            description=description[:2000] if len(description) > 2000 else description,
            severity=severity,
            status='new',
            cvss_score=float(cvss_score),
            risk_level=risk_level,
            category=source.lower(),
            source_identifier=source,
            created_date=datetime.now()
        )
        
        return vulnerability
    
    def _save_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> int:
        """
        Сохранить список уязвимостей в БД
        
        Args:
            vulnerabilities: Список объектов Vulnerability
            
        Returns:
            Количество успешно сохраненных уязвимостей
        """
        saved = 0
        for vuln in vulnerabilities:
            try:
                if self.vulnerability_repo.save_vulnerability(vuln):
                    saved += 1
                    self.logger.debug(f"✅ Сохранена уязвимость: {vuln.cve_id}")
                else:
                    self.logger.warning(f"⚠️ Не удалось сохранить: {vuln.cve_id}")
            except Exception as e:
                error_msg = f"Ошибка сохранения {vuln.cve_id}: {e}"
                self.logger.error(error_msg, exc_info=True)
                self.errors.append(error_msg)
        
        return saved
    
    def _normalize_cve_id(self, cve_id: str) -> Optional[str]:
        """
        Нормализовать CVE ID
        
        Args:
            cve_id: CVE идентификатор
            
        Returns:
            Нормализованный CVE ID или None
        """
        if not cve_id:
            return None
        
        # Извлекаем CVE ID из строки
        match = re.search(r'CVE-\d{4}-\d{4,}', str(cve_id).upper())
        if match:
            return match.group(0)
        
        return None
    
    def _extract_cvss_from_text(self, text: str) -> float:
        """
        Извлечь CVSS score из текста
        
        Args:
            text: Текст для поиска CVSS
            
        Returns:
            CVSS score (0.0 если не найден)
        """
        if not text:
            return 0.0
        
        # Поиск числа с плавающей точкой
        match = re.search(r'\d+\.\d+', str(text))
        if match:
            try:
                score = float(match.group(0))
                return min(10.0, max(0.0, score))  # Ограничиваем 0-10
            except:
                pass
        
        # Поиск целого числа
        match = re.search(r'\d+', str(text))
        if match:
            try:
                score = float(match.group(0))
                return min(10.0, max(0.0, score))
            except:
                pass
        
        return 0.0
    
    def _clean_text(self, text: str) -> str:
        """
        Очистить текст от лишних символов
        
        Args:
            text: Текст для очистки
            
        Returns:
            Очищенный текст
        """
        if not text:
            return ''
        
        # Удаляем лишние пробелы и переносы строк
        text = re.sub(r'\s+', ' ', str(text))
        text = text.strip()
        
        return text

