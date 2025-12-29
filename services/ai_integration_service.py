"""
Сервис интеграции с ИИ-системой парсинга и категоризации уязвимостей
Интегрирует внешнюю ИИ-систему на VM 10.0.88.25 с Backend и Frontend
"""
import logging
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime

# Опциональные импорты локальных ИИ модулей (могут отсутствовать на Backend)
try:
    from services.parsers.ai_analyzer import ai_analyzer, AIClassification
    LOCAL_AI_ANALYZER_AVAILABLE = True
except ImportError:
    LOCAL_AI_ANALYZER_AVAILABLE = False
    ai_analyzer = None
    AIClassification = None

try:
    from services.ai_tagger_service import ai_tagger, AIDetectionResult
    LOCAL_AI_TAGGER_AVAILABLE = True
except ImportError:
    LOCAL_AI_TAGGER_AVAILABLE = False
    ai_tagger = None
    AIDetectionResult = None

try:
    from models.database import DatabaseManager
    from config import Config
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False
    DatabaseManager = None
    Config = None

logger = logging.getLogger(__name__)


class AIIntegrationService:
    """
    Сервис для интеграции ИИ-системы с основным приложением
    
    Функции:
    - Анализ уязвимостей с помощью ИИ
    - Классификация (ИИ или нет)
    - Статистика по ключевым словам
    - Обучение модели
    - Мониторинг сайтов
    - Генерация паспортов уязвимостей
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Инициализация DatabaseManager (опционально)
        if DATABASE_AVAILABLE:
            try:
                self.db_manager = DatabaseManager()
            except Exception as e:
                self.logger.warning(f"Не удалось инициализировать DatabaseManager: {e}")
                self.db_manager = None
        else:
            self.db_manager = None
        
        # URL ИИ-системы на VM 10.0.88.25
        self.ai_api_url = "http://10.0.88.25:8000"
        self.ai_api_available = False
        
        # Проверка доступности внешней ИИ-системы
        self._check_ai_api_availability()
        
        # Используем локальные анализаторы как fallback (если доступны)
        self.local_ai_analyzer = ai_analyzer if LOCAL_AI_ANALYZER_AVAILABLE else None
        self.local_ai_tagger = ai_tagger if LOCAL_AI_TAGGER_AVAILABLE else None
    
    def _check_ai_api_availability(self):
        """Проверка доступности внешней ИИ-системы на VM 10.0.88.25"""
        try:
            response = requests.get(f"{self.ai_api_url}/health", timeout=3)
            if response.status_code == 200:
                self.ai_api_available = True
                self.logger.info("✅ Внешняя ИИ-система доступна на 10.0.88.25")
            else:
                self.logger.warning(f"⚠️ ИИ-система на 10.0.88.25 недоступна (HTTP {response.status_code})")
        except Exception as e:
            self.logger.info(f"Используем локальную ИИ-систему: {e}")
            self.ai_api_available = False
    
    def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Анализ уязвимости с помощью ИИ
        
        Args:
            vulnerability_data: Данные уязвимости (cve_id, title, description, etc.)
            
        Returns:
            Dict с результатами анализа
        """
        try:
            # Пробуем использовать внешнюю ИИ-систему на VM 10.0.88.25
            if self.ai_api_available:
                try:
                    # Формируем запрос для внешней ИИ-системы
                    api_data = {
                        'title': vulnerability_data.get('title', ''),
                        'description': vulnerability_data.get('description', ''),
                        'cve_id': vulnerability_data.get('cve_id', '')
                    }
                    response = requests.post(
                        f"{self.ai_api_url}/api/analyze",
                        json=api_data,
                        timeout=10
                    )
                    if response.status_code == 200:
                        api_result = response.json()
                        if api_result.get('success'):
                            # Преобразуем результат внешнего API в формат нашего сервиса
                            return {
                                'is_ai_related': api_result.get('is_ai_related', False),
                                'confidence': api_result.get('confidence', 0.0),
                                'cve_id': api_result.get('cve_id', ''),
                                'source': 'external_ai_api',
                                'ai_categories': [],
                                'matched_keywords': [],
                                'reasoning': f"Классификация выполнена внешней ИИ-системой на VM 10.0.88.25 (confidence: {api_result.get('confidence', 0.0):.2f})"
                            }
                except requests.exceptions.Timeout:
                    self.logger.warning("Таймаут при обращении к внешней ИИ-системе, используем локальную")
                except Exception as e:
                    self.logger.warning(f"Ошибка обращения к внешней ИИ-системе: {e}, используем локальную")
            
            # Используем локальную ИИ-систему (если доступна)
            if self.local_ai_analyzer and self.local_ai_tagger:
                try:
                    ai_result = self.local_ai_analyzer.analyze_all(vulnerability_data)
                    tagger_result = self.local_ai_tagger.analyze_vulnerability(
                        title=vulnerability_data.get('title', ''),
                        description=vulnerability_data.get('description', ''),
                        cve_id=vulnerability_data.get('cve_id', ''),
                        affected_software=vulnerability_data.get('affected_products', []),
                        references=vulnerability_data.get('references', [])
                    )
                    
                    # Объединяем результаты
                    return {
                        'is_ai_related': ai_result['ai_classification']['is_ai_related'] or tagger_result.is_ai_related,
                        'confidence': max(
                            ai_result['ai_classification']['confidence'],
                            tagger_result.confidence
                        ),
                        'ai_categories': ai_result['ai_classification']['categories'],
                        'matched_keywords': tagger_result.matched_keywords,
                        'suggested_tags': tagger_result.suggested_tags,
                        'reasoning': ai_result['ai_classification']['reasoning'],
                        'owasp_categories': ai_result['owasp_classification'],
                        'zero_day_assessment': ai_result['zero_day_assessment'],
                        'risk_multiplier': tagger_result.risk_multiplier,
                        'source': 'local'
                    }
                except Exception as e:
                    self.logger.warning(f"Ошибка локального анализа: {e}, возвращаем базовый результат")
            
            # Базовый результат, если локальные анализаторы недоступны
            return {
                'is_ai_related': False,
                'confidence': 0.0,
                'ai_categories': [],
                'matched_keywords': [],
                'suggested_tags': [],
                'reasoning': 'Локальные ИИ-анализаторы недоступны, внешняя ИИ-система также недоступна',
                'source': 'none'
            }
        except Exception as e:
            self.logger.error(f"Ошибка анализа уязвимости: {e}", exc_info=True)
            return {
                'is_ai_related': False,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def classify_vulnerability(self, vulnerability_id: int) -> Dict[str, Any]:
        """
        Классификация уязвимости (ИИ или нет)
        
        Args:
            vulnerability_id: ID уязвимости в БД
            
        Returns:
            Dict с результатами классификации
        """
        try:
            # Получаем данные уязвимости из БД
            if Config.USE_LEGACY_SCHEMA:
                from models.legacy_repositories import LegacyVulnerabilityRepository
                repo = LegacyVulnerabilityRepository(self.db_manager.connection)
            else:
                from models.postgres_repositories import PostgresVulnerabilityRepository
                repo = PostgresVulnerabilityRepository(self.db_manager.connection)
            
            vulnerability = repo.get_by_id(vulnerability_id)
            if not vulnerability:
                self.logger.warning(f"Уязвимость {vulnerability_id} не найдена в БД")
                return {'error': 'Уязвимость не найдена'}
            
            self.logger.info(f"Классификация уязвимости {vulnerability_id}: {getattr(vulnerability, 'cve_id', 'N/A')}")
            
            # Преобразуем в словарь для анализа
            vuln_data = {
                'cve_id': getattr(vulnerability, 'cve_id', ''),
                'title': getattr(vulnerability, 'title', ''),
                'description': getattr(vulnerability, 'description', ''),
                'affected_products': getattr(vulnerability, 'affected_packages', []),
                'references': getattr(vulnerability, 'references', []),
                'cwe_ids': getattr(vulnerability, 'cwe_ids', [])
            }
            
            # Анализ
            result = self.analyze_vulnerability(vuln_data)
            
            # Сохранение результата в БД
            self._save_analysis_result(vulnerability_id, result)
            
            return result
        except Exception as e:
            self.logger.error(f"Ошибка классификации уязвимости {vulnerability_id}: {e}", exc_info=True)
            return {'error': str(e)}
    
    def batch_analyze(self, vulnerability_ids: List[int]) -> Dict[str, Any]:
        """
        Пакетный анализ уязвимостей (работает с новыми уязвимостями)
        
        Args:
            vulnerability_ids: Список ID уязвимостей (можно пустой - тогда анализирует все новые)
            
        Returns:
            Dict со статистикой анализа
        """
        results = []
        ai_count = 0
        
        # Если список пустой, получаем новые уязвимости из БД
        if not vulnerability_ids:
            try:
                cursor = self.db_manager.connection.cursor()
                # Получаем последние 100 уязвимостей (новые)
                cursor.execute("""
                    SELECT id FROM turn 
                    ORDER BY id DESC 
                    LIMIT 100
                """)
                rows = cursor.fetchall()
                vulnerability_ids = [row[0] for row in rows]
                cursor.close()
                self.logger.info(f"Автоматически выбрано {len(vulnerability_ids)} новых уязвимостей для анализа")
            except Exception as e:
                self.logger.error(f"Ошибка получения новых уязвимостей: {e}")
                return {'error': f'Ошибка получения уязвимостей: {str(e)}'}
        
        self.logger.info(f"Начинаем пакетный анализ {len(vulnerability_ids)} уязвимостей")
        
        for idx, vuln_id in enumerate(vulnerability_ids, 1):
            try:
                self.logger.debug(f"Анализ {idx}/{len(vulnerability_ids)}: уязвимость {vuln_id}")
                result = self.classify_vulnerability(vuln_id)
                results.append(result)
                if result.get('is_ai_related'):
                    ai_count += 1
                    self.logger.info(f"✅ Уязвимость {vuln_id} классифицирована как ИИ-связанная (confidence: {result.get('confidence', 0.0):.2f})")
            except Exception as e:
                self.logger.error(f"Ошибка анализа уязвимости {vuln_id}: {e}", exc_info=True)
                results.append({'vulnerability_id': vuln_id, 'error': str(e)})
        
        return {
            'total': len(results),
            'ai_related': ai_count,
            'percentage': (ai_count / len(results) * 100) if results else 0,
            'results': results
        }
    
    def get_keywords_statistics(self) -> Dict[str, Any]:
        """
        Статистика по ключевым словам
        
        Returns:
            Dict со статистикой использования ключевых слов
        """
        try:
            cursor = self.db_manager.connection.cursor()
            
            # Получаем статистику из БД (если таблица ai_keywords существует)
            try:
                cursor.execute("""
                    SELECT keyword, category, usage_count, accuracy
                    FROM ai_keywords
                    ORDER BY usage_count DESC
                    LIMIT 100
                """)
                keywords_data = cursor.fetchall()
                
                keywords = []
                for row in keywords_data:
                    keywords.append({
                        'keyword': row[0],
                        'category': row[1],
                        'usage_count': row[2],
                        'accuracy': float(row[3]) if row[3] else 0.0
                    })
            except Exception:
                # Таблица не существует, используем данные из анализаторов (если доступны)
                keywords = []
                # Собираем ключевые слова из локальных анализаторов (если доступны)
                if LOCAL_AI_ANALYZER_AVAILABLE and ai_analyzer and hasattr(ai_analyzer, 'AI_KEYWORDS'):
                    try:
                        for category, kw_list in ai_analyzer.AI_KEYWORDS.items():
                            for keyword in kw_list:
                                keywords.append({
                                    'keyword': keyword,
                                    'category': category,
                                    'usage_count': 0,
                                    'accuracy': 0.0
                                })
                    except Exception as e:
                        self.logger.warning(f"Не удалось получить ключевые слова из ai_analyzer: {e}")
                        # Используем базовый набор ключевых слов
                        keywords = self._get_default_keywords()
                else:
                    # Используем базовый набор ключевых слов
                    keywords = self._get_default_keywords()
            
            # Подсчет по категориям
            category_stats = {}
            for kw in keywords:
                cat = kw['category']
                if cat not in category_stats:
                    category_stats[cat] = {'count': 0, 'total_usage': 0}
                category_stats[cat]['count'] += 1
                category_stats[cat]['total_usage'] += kw['usage_count']
            
            cursor.close()
            
            return {
                'total_keywords': len(keywords),
                'keywords': keywords[:50],  # Топ-50
                'category_stats': category_stats
            }
        except Exception as e:
            self.logger.error(f"Ошибка получения статистики ключевых слов: {e}", exc_info=True)
            return {'error': str(e)}
    
    def train_model(self, training_data: Optional[List[Dict[str, Any]]] = None, auto_collect: bool = True) -> Dict[str, Any]:
        """
        Обучение модели на новых данных
        
        Args:
            training_data: Список данных для обучения (опционально)
                [{'vulnerability_id': int, 'is_ai_related': bool, 'context': str}]
            auto_collect: Автоматически собрать данные из БД (подтвержденные ИИ-уязвимости)
            
        Returns:
            Dict с результатами обучения
        """
        try:
            cursor = self.db_manager.connection.cursor()
            
            # Автоматический сбор данных из БД
            if auto_collect:
                # Получаем все уязвимости с подтвержденным is_ai_related = TRUE
                cursor.execute("""
                    SELECT id, name, etc
                    FROM turn
                    WHERE is_ai_related = TRUE
                    AND id NOT IN (SELECT vulnerability_id FROM ai_training_data WHERE used_for_training = TRUE)
                """)
                
                confirmed_ai_vulns = cursor.fetchall()
                
                # Также получаем не-ИИ уязвимости для отрицательных примеров
                cursor.execute("""
                    SELECT id, name, etc
                    FROM turn
                    WHERE (is_ai_related = FALSE OR is_ai_related IS NULL)
                    AND id NOT IN (SELECT vulnerability_id FROM ai_training_data WHERE used_for_training = TRUE)
                    LIMIT %s
                """, (len(confirmed_ai_vulns),))
                
                non_ai_vulns = cursor.fetchall()
                
                # Формируем training_data
                if not training_data:
                    training_data = []
                
                for vuln_id, name, etc in confirmed_ai_vulns:
                    context = f"{name or ''} {etc or ''}".strip()
                    if context:
                        training_data.append({
                            'vulnerability_id': vuln_id,
                            'is_ai_related': True,
                            'context': context
                        })
                
                for vuln_id, name, etc in non_ai_vulns:
                    context = f"{name or ''} {etc or ''}".strip()
                    if context:
                        training_data.append({
                            'vulnerability_id': vuln_id,
                            'is_ai_related': False,
                            'context': context
                        })
            
            # Сохранение данных для обучения в БД
            trained_count = 0
            for data in training_data:
                try:
                    cursor.execute("""
                        INSERT INTO ai_training_data 
                        (vulnerability_id, is_ai_related, context_text, confirmed_at, confirmed_by)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (
                        data.get('vulnerability_id'),
                        data.get('is_ai_related'),
                        data.get('context', ''),
                        datetime.now(),
                        None  # Автоматическое обучение
                    ))
                    trained_count += 1
                except Exception as e:
                    self.logger.warning(f"Ошибка сохранения данных обучения: {e}")
            
            self.db_manager.connection.commit()
            
            # Извлечение новых ключевых слов из подтвержденных ИИ-уязвимостей
            new_keywords = self._extract_keywords_from_training_data()
            
            # Добавление новых ключевых слов в таблицу ai_keywords
            added_keywords = 0
            for keyword in new_keywords:
                try:
                    cursor.execute("""
                        INSERT INTO ai_keywords (keyword, category, source, usage_count)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (keyword) 
                        DO UPDATE SET usage_count = ai_keywords.usage_count + 1
                    """, (keyword, 'learned', 'extracted', 1))
                    added_keywords += 1
                except Exception as e:
                    self.logger.warning(f"Ошибка добавления ключевого слова {keyword}: {e}")
            
            # Обновление флага used_for_training
            cursor.execute("""
                UPDATE ai_training_data
                SET used_for_training = TRUE
                WHERE vulnerability_id IN %s
            """, (tuple([d.get('vulnerability_id') for d in training_data]),))
            
            self.db_manager.connection.commit()
            cursor.close()
            
            return {
                'success': True,
                'trained_samples': trained_count,
                'new_keywords': len(new_keywords),
                'added_keywords': added_keywords,
                'message': f'Обучено на {trained_count} образцах, извлечено {len(new_keywords)} новых ключевых слов, добавлено {added_keywords}'
            }
        except Exception as e:
            self.logger.error(f"Ошибка обучения модели: {e}", exc_info=True)
            if self.db_manager.connection:
                self.db_manager.connection.rollback()
            return {'error': str(e)}
    
    def _extract_keywords_from_training_data(self, min_frequency: int = 3) -> List[str]:
        """
        Извлечение ключевых слов из обучающих данных
        
        Args:
            min_frequency: Минимальная частота встречаемости для добавления
            
        Returns:
            Список новых ключевых слов
        """
        try:
            cursor = self.db_manager.connection.cursor()
            
            # Получаем подтвержденные ИИ-уязвимости
            cursor.execute("""
                SELECT DISTINCT context_text
                FROM ai_training_data
                WHERE is_ai_related = TRUE
                AND used_for_training = FALSE
            """)
            
            contexts = [row[0] for row in cursor.fetchall() if row[0]]
            
            if not contexts:
                cursor.close()
                return []
            
            # Извлечение n-грамм (1-3 слова)
            import re
            from collections import Counter
            
            all_ngrams = []
            
            for context in contexts:
                # Нормализация текста
                text = context.lower()
                # Извлекаем слова
                words = re.findall(r'\b[a-z]{3,}\b', text)  # Минимум 3 символа
                
                # 1-граммы (отдельные слова)
                for word in words:
                    if len(word) >= 4:  # Минимум 4 символа для 1-грамм
                        all_ngrams.append(word)
                
                # 2-граммы (биграммы)
                for i in range(len(words) - 1):
                    bigram = f"{words[i]} {words[i+1]}"
                    all_ngrams.append(bigram)
                
                # 3-граммы (триграммы) - только для важных фраз
                for i in range(len(words) - 2):
                    trigram = f"{words[i]} {words[i+1]} {words[i+2]}"
                    all_ngrams.append(trigram)
            
            # Подсчет частоты
            ngram_counts = Counter(all_ngrams)
            
            # Фильтрация по частоте и релевантности
            new_keywords = []
            existing_keywords = set()
            
            # Получаем существующие ключевые слова
            try:
                cursor.execute("SELECT keyword FROM ai_keywords")
                existing_keywords = {row[0].lower() for row in cursor.fetchall()}
            except:
                pass
            
            # Фильтруем и добавляем новые
            for ngram, count in ngram_counts.most_common(100):
                # Проверка частоты
                if count < min_frequency:
                    continue
                
                # Проверка на существование
                if ngram.lower() in existing_keywords:
                    continue
                
                # Проверка релевантности (исключаем общие слова)
                common_words = {'the', 'and', 'or', 'but', 'for', 'with', 'from', 'this', 'that', 'these', 'those'}
                words_in_ngram = ngram.split()
                if all(w in common_words for w in words_in_ngram):
                    continue
                
                new_keywords.append(ngram)
            
            cursor.close()
            return new_keywords
        except Exception as e:
            self.logger.error(f"Ошибка извлечения ключевых слов: {e}", exc_info=True)
            return []
    
    def _save_analysis_result(self, vulnerability_id: int, result: Dict[str, Any]):
        """Сохранение результата анализа в БД"""
        try:
            cursor = self.db_manager.connection.cursor()
            
            # Проверяем существование таблицы
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'ai_analysis_results'
                )
            """)
            table_exists = cursor.fetchone()[0]
            
            if not table_exists:
                # Создаем таблицу
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ai_analysis_results (
                        id SERIAL PRIMARY KEY,
                        vulnerability_id INTEGER REFERENCES turn(id),
                        is_ai_related BOOLEAN,
                        confidence FLOAT,
                        keywords_found TEXT[],
                        categories TEXT[],
                        reasoning TEXT,
                        analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        model_version VARCHAR(50)
                    )
                """)
                self.db_manager.connection.commit()
            
            # Сохранение результата
            cursor.execute("""
                INSERT INTO ai_analysis_results 
                (vulnerability_id, is_ai_related, confidence, keywords_found, categories, reasoning, model_version)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (vulnerability_id) 
                DO UPDATE SET 
                    is_ai_related = EXCLUDED.is_ai_related,
                    confidence = EXCLUDED.confidence,
                    keywords_found = EXCLUDED.keywords_found,
                    categories = EXCLUDED.categories,
                    reasoning = EXCLUDED.reasoning,
                    analyzed_at = CURRENT_TIMESTAMP
            """, (
                vulnerability_id,
                result.get('is_ai_related', False),
                result.get('confidence', 0.0),
                result.get('matched_keywords', []),
                result.get('ai_categories', []),
                result.get('reasoning', ''),
                'local_v1.0'
            ))
            
            # Обновление основной таблицы turn
            cursor.execute("""
                UPDATE turn
                SET is_ai_related = %s,
                    ai_confidence = %s
                WHERE id = %s
            """, (
                result.get('is_ai_related', False),
                result.get('confidence', 0.0),
                vulnerability_id
            ))
            
            self.db_manager.connection.commit()
            cursor.close()
        except Exception as e:
            self.logger.error(f"Ошибка сохранения результата анализа: {e}", exc_info=True)
            if self.db_manager.connection:
                self.db_manager.connection.rollback()
    
    def generate_passport(self, vulnerability_id: int) -> Dict[str, Any]:
        """
        Генерация паспорта уязвимости при помощи ИИ
        
        Args:
            vulnerability_id: ID уязвимости
            
        Returns:
            Dict с данными паспорта
        """
        try:
            # Получаем данные уязвимости
            if Config.USE_LEGACY_SCHEMA:
                from models.legacy_repositories import LegacyVulnerabilityRepository
                repo = LegacyVulnerabilityRepository(self.db_manager.connection)
            else:
                from models.postgres_repositories import PostgresVulnerabilityRepository
                repo = PostgresVulnerabilityRepository(self.db_manager.connection)
            
            vulnerability = repo.get_by_id(vulnerability_id)
            if not vulnerability:
                return {'error': 'Уязвимость не найдена'}
            
            # ИИ-анализ
            vuln_data = {
                'cve_id': getattr(vulnerability, 'cve_id', ''),
                'title': getattr(vulnerability, 'title', ''),
                'description': getattr(vulnerability, 'description', ''),
                'affected_products': getattr(vulnerability, 'affected_packages', []),
                'references': getattr(vulnerability, 'references', []),
                'cwe_ids': getattr(vulnerability, 'cwe_ids', []),
                'cvss_score': getattr(vulnerability, 'cvss_score', 0.0)
            }
            
            ai_result = self.analyze_vulnerability(vuln_data)
            
            # Формирование паспорта
            passport = {
                'vulnerability_id': vulnerability_id,
                'general_info': {
                    'cve_id': getattr(vulnerability, 'cve_id', ''),
                    'title': getattr(vulnerability, 'title', ''),
                    'description': getattr(vulnerability, 'description', ''),
                    'published_date': str(getattr(vulnerability, 'published_date', '')),
                    'last_modified': str(getattr(vulnerability, 'last_modified', ''))
                },
                'classification': {
                    'is_ai_related': ai_result.get('is_ai_related', False),
                    'confidence': ai_result.get('confidence', 0.0),
                    'ai_categories': ai_result.get('ai_categories', []),
                    'cwe_ids': getattr(vulnerability, 'cwe_ids', []),
                    'owasp_categories': ai_result.get('owasp_categories', [])
                },
                'risk_assessment': {
                    'cvss_score': getattr(vulnerability, 'cvss_score', 0.0),
                    'severity': getattr(vulnerability, 'severity', 'unknown'),
                    'zero_day_potential': ai_result.get('zero_day_assessment', {}).get('has_zero_day_potential', False),
                    'exploit_available': ai_result.get('zero_day_assessment', {}).get('exploit_available', False),
                    'poc_available': ai_result.get('zero_day_assessment', {}).get('poc_available', False),
                    'risk_score': ai_result.get('zero_day_assessment', {}).get('risk_score', 0.0)
                },
                'affected_components': {
                    'products': getattr(vulnerability, 'affected_packages', []),
                    'platforms': []  # Можно извлечь из affected_packages
                },
                'recommendations': {
                    'immediate_actions': [],
                    'patches': [],
                    'workarounds': []
                },
                'additional_info': {
                    'references': getattr(vulnerability, 'references', []),
                    'keywords': ai_result.get('matched_keywords', []),
                    'tags': ai_result.get('suggested_tags', []),
                    'reasoning': ai_result.get('reasoning', '')
                },
                'generated_at': datetime.now().isoformat(),
                'model_version': 'local_v1.0'
            }
            
            # Сохранение паспорта в БД
            self._save_passport(vulnerability_id, passport)
            
            return passport
        except Exception as e:
            self.logger.error(f"Ошибка генерации паспорта для {vulnerability_id}: {e}", exc_info=True)
            return {'error': str(e)}
    
    def _save_passport(self, vulnerability_id: int, passport: Dict[str, Any]):
        """Сохранение паспорта в БД"""
        try:
            cursor = self.db_manager.connection.cursor()
            
            # Проверяем существование таблицы
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'ai_vulnerability_passports'
                )
            """)
            table_exists = cursor.fetchone()[0]
            
            if not table_exists:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ai_vulnerability_passports (
                        id SERIAL PRIMARY KEY,
                        vulnerability_id INTEGER REFERENCES turn(id),
                        passport_data JSONB NOT NULL,
                        generated_by_ai BOOLEAN DEFAULT TRUE,
                        model_version VARCHAR(50),
                        confidence FLOAT,
                        generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                self.db_manager.connection.commit()
            
            # Сохранение
            import json
            cursor.execute("""
                INSERT INTO ai_vulnerability_passports 
                (vulnerability_id, passport_data, generated_by_ai, model_version, confidence)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (vulnerability_id) 
                DO UPDATE SET 
                    passport_data = EXCLUDED.passport_data,
                    updated_at = CURRENT_TIMESTAMP,
                    confidence = EXCLUDED.confidence
            """, (
                vulnerability_id,
                json.dumps(passport),
                True,
                passport.get('model_version', 'local_v1.0'),
                passport.get('classification', {}).get('confidence', 0.0)
            ))
            
            self.db_manager.connection.commit()
            cursor.close()
        except Exception as e:
            self.logger.error(f"Ошибка сохранения паспорта: {e}", exc_info=True)
            if self.db_manager.connection:
                self.db_manager.connection.rollback()
    
    def _get_default_keywords(self) -> List[Dict[str, Any]]:
        """Базовый набор ключевых слов ИИ (если локальные анализаторы недоступны)"""
        default_keywords = [
            'ai', 'artificial intelligence', 'machine learning', 'deep learning',
            'neural network', 'llm', 'large language model', 'transformer',
            'tensorflow', 'pytorch', 'keras', 'scikit-learn', 'ml model',
            'generative ai', 'gpt', 'chatgpt', 'openai', 'huggingface'
        ]
        return [
            {
                'keyword': kw,
                'category': 'general',
                'usage_count': 0,
                'accuracy': 0.0
            }
            for kw in default_keywords
        ]


# Глобальный экземпляр
ai_integration_service = AIIntegrationService()

