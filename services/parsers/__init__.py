"""
Модуль парсеров уязвимостей
Современная модульная архитектура с поддержкой множества источников
"""
from .base_parser import BaseParser, ParserStatus
from .normalizer import DataNormalizer, NormalizedVulnerability, normalizer
from .ai_analyzer import AIAnalyzer, AIClassification, ai_analyzer
from .deduplicator import Deduplicator, DeduplicationResult, deduplicator

__all__ = [
    'BaseParser',
    'ParserStatus',
    'DataNormalizer',
    'NormalizedVulnerability',
    'normalizer',
    'AIAnalyzer',
    'AIClassification',
    'ai_analyzer',
    'Deduplicator',
    'DeduplicationResult',
    'deduplicator',
]

