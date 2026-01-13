"""
Адаптер репозиториев для работы с существующей схемой БД
Таблицы: turn, cvelist, cwelist, map_table, operators, actids и др.
"""
import logging
import json
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
from models.entities import Vulnerability, Operator
logger = logging.getLogger(__name__)


class LegacyVulnerabilityRepository:
    """Репозиторий для работы с таблицей turn и связанными таблицами"""

    def __init__(self, db_connection):
        self.db = db_connection

    def save_vulnerability(self, vulnerability: Vulnerability) -> bool:
        """
        Сохранение уязвимости в таблицу turn и связанные таблицы
        """
        cursor = None
        try:
            cursor = self.db.cursor()
            # Проверяем, существует ли уже запись с таким CVE
            cve_id = getattr(vulnerability, 'cve_id', None) or getattr(vulnerability, 'title', None) or 'UNKNOWN-CVE'
            
            # Валидация cve_id - должен быть не пустым и валидным
            if not cve_id or cve_id == 'UNKNOWN-CVE' or len(cve_id.strip()) == 0:
                logger.error(f"❌ [LEGACY_REPO] Невалидный cve_id: '{cve_id}' для уязвимости '{vulnerability.title[:50]}'")
                return False
            
            # Очистка cve_id от лишних пробелов
            cve_id = cve_id.strip()
            
            logger.info(f"💾 [LEGACY_REPO] Начинаем сохранение {cve_id}")
            logger.debug(f"   cve_id={cve_id}, title={vulnerability.title[:50]}, source_identifier={getattr(vulnerability, 'source_identifier', 'N/A')}")
            
            # 1. Сохраняем в таблицу turn
            turn_id = self._save_to_turn(cursor, vulnerability)
            if not turn_id:
                logger.error(f"❌ [LEGACY_REPO] _save_to_turn вернул None для {cve_id}")
                self.db.rollback()
                if cursor:
                    cursor.close()
                return False
            
            logger.debug(f"   ✅ turn_id={turn_id}")

            # 2. Если есть CVE, сохраняем в cvelist
            if cve_id and cve_id != 'UNKNOWN':
                try:
                    self._save_to_cvelist(cursor, cve_id, vulnerability)
                    logger.debug(f"   ✅ [CVELIST] Сохранено для {cve_id}")
                except Exception as e:
                    logger.error(f"❌ [CVELIST] Ошибка сохранения в cvelist для {cve_id}: {e}", exc_info=True)
                    # Не прерываем транзакцию, но логируем ошибку

            # 3. Если есть CWE (weaknesses), сохраняем в cwelist и map_table
            if hasattr(vulnerability, 'weaknesses') and vulnerability.weaknesses:
                try:
                    self._save_cwe_data(cursor, cve_id, vulnerability)
                    logger.debug(f"   ✅ [CWE] Сохранено для {cve_id}")
                except Exception as e:
                    logger.error(f"❌ [CWE] Ошибка сохранения CWE для {cve_id}: {e}", exc_info=True)
                    # Не прерываем транзакцию, но логируем ошибку

            # 4. Сохраняем маппинг в map_table
            try:
                self._save_to_map_table(cursor, cve_id, vulnerability)
                logger.debug(f"   ✅ [MAP_TABLE] Сохранено для {cve_id}")
            except Exception as e:
                logger.error(f"❌ [MAP_TABLE] Ошибка сохранения в map_table для {cve_id}: {e}", exc_info=True)
                # Не прерываем транзакцию, но логируем ошибку

            # Коммитим транзакцию
            try:
                self.db.commit()
                logger.info(f"✅ [LEGACY_REPO] Уязвимость {cve_id} сохранена в legacy схему (turn_id={turn_id})")
                return True
            except Exception as commit_error:
                logger.error(f"❌ [LEGACY_REPO] Ошибка коммита транзакции для {cve_id}: {commit_error}", exc_info=True)
                self.db.rollback()
                return False

        except Exception as e:
            if cursor:
                self.db.rollback()
            logger.error(f"❌ [LEGACY_REPO] Ошибка сохранения уязвимости {cve_id}: {e}", exc_info=True)
            import traceback
            logger.error(f"   Traceback: {traceback.format_exc()}")
            return False
        finally:
            if cursor:
                cursor.close()

    def _save_to_turn(self, cursor, vulnerability: Vulnerability) -> Optional[int]:
        """Сохранение в таблицу turn"""
        try:
            # cve_id уже валидирован в save_vulnerability, но проверяем на всякий случай
            cve_id = getattr(vulnerability, 'cve_id', None) or getattr(vulnerability, 'title', None) or 'UNKNOWN-CVE'
            
            if not cve_id or cve_id == 'UNKNOWN-CVE' or len(cve_id.strip()) == 0:
                logger.error(f"❌ [TURN] Невалидный cve_id в _save_to_turn: '{cve_id}'")
                return None
            
            cve_id = cve_id.strip()
            
            # Определяем source (NVD, RedHat, OSV, Debian, Ubuntu и т.д.)
            source = getattr(vulnerability, 'source_identifier', None)
            if not source:
                # Если source_identifier не установлен, пытаемся определить из category
                source = getattr(vulnerability, 'category', 'NVD')
            
            # Нормализация source
            source_lower = source.lower() if source else ''
            if 'redhat' in source_lower or source == 'redhat':
                source = 'RedHat'
            elif 'osv' in source_lower:
                source = 'OSV'
            elif 'debian' in source_lower or source == 'Debian':
                source = 'Debian'
            elif 'ubuntu' in source_lower or source == 'Ubuntu':
                source = 'Ubuntu'
            elif not source or source == 'NVD':
                source = 'NVD'
            else:
                # Сохраняем как есть, если это валидное значение
                source = str(source)

            # Формируем link
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith('CVE-') else getattr(vulnerability, 'url', '')

            # Определяем name (title или описание)
            name = vulnerability.title[:500] if len(vulnerability.title) <= 500 else vulnerability.title[:497] + '...'

            # CVSS score
            cvss = float(vulnerability.cvss_score) if vulnerability.cvss_score else 0.0

            # Price (можно использовать ai_confidence или severity)
            price_one = 0.0
            if hasattr(vulnerability, 'ai_confidence'):
                price_one = float(vulnerability.ai_confidence) * 100
            elif vulnerability.severity == 'critical':
                price_one = 100.0
            elif vulnerability.severity == 'high':
                price_one = 75.0
            elif vulnerability.severity == 'medium':
                price_one = 50.0
            else:
                price_one = 25.0

            # Priority (на основе CVSS)
            priority = cvss

            # Даты
            joining_date = vulnerability.created_date or datetime.now()
            start_date = getattr(vulnerability, 'published', None) or joining_date
            end_date = vulnerability.completed_date or getattr(vulnerability, 'last_modified', None)

            # ETC (дополнительная информация в JSON)
            etc_data = {
                'category': vulnerability.category,
                'risk_level': vulnerability.risk_level,
                'status': vulnerability.status,
                'approved': vulnerability.approved,
                'modifications': vulnerability.modifications
            }
            # ЗАКОММЕНТИРОВАНО: Логика ИИ уязвимостей
            # if hasattr(vulnerability, 'is_ai_related'):
            #     etc_data['is_ai_related'] = vulnerability.is_ai_related
            #     etc_data['ai_confidence'] = getattr(vulnerability, 'ai_confidence', 0.0)
            etc = json.dumps(etc_data, ensure_ascii=False)

            # Status (boolean)
            status = vulnerability.status not in ['completed', 'approved']

            # Подготовка данных для NVD полей (до проверки существования)
            cvss_v2_vector = getattr(vulnerability, 'cvss_v2_vector', None)
            cvss_v3_vector = getattr(vulnerability, 'cvss_v3_vector', None)
            cvss_v4_vector = getattr(vulnerability, 'cvss_v4_vector', None)
            cvss_version = getattr(vulnerability, 'cvss_version', None) or '3.1'
            epss_score = getattr(vulnerability, 'epss_score', None)
            epss_percentile = getattr(vulnerability, 'epss_percentile', None)
            
            # CWE IDs из weaknesses
            cwe_ids = []
            weaknesses = getattr(vulnerability, 'weaknesses', [])
            if weaknesses:
                for weakness in weaknesses:
                    if isinstance(weakness, dict):
                        cwe_id = weakness.get('cwe_id') or weakness.get('cweId', '')
                    else:
                        cwe_id = getattr(weakness, 'cwe_id', '')
                    if cwe_id and cwe_id not in cwe_ids:
                        cwe_ids.append(cwe_id)
            
            # JSONB поля
            affected_products = getattr(vulnerability, 'affected_products', None)
            if affected_products:
                affected_products_json = json.dumps(affected_products, ensure_ascii=False) if not isinstance(affected_products, str) else affected_products
            else:
                affected_products_json = None
                
            nvd_references = getattr(vulnerability, 'references', None)
            if nvd_references:
                nvd_references_json = json.dumps(nvd_references, ensure_ascii=False) if not isinstance(nvd_references, str) else nvd_references
            else:
                nvd_references_json = None
                
            vendor_comments_json = None
            if hasattr(vulnerability, 'vendor_comments') and vulnerability.vendor_comments:
                vendor_comments_json = json.dumps(vulnerability.vendor_comments, ensure_ascii=False) if not isinstance(vulnerability.vendor_comments, str) else vulnerability.vendor_comments
                
            cpe_configurations = getattr(vulnerability, 'configurations', None)
            if cpe_configurations:
                cpe_configurations_json = json.dumps(cpe_configurations, ensure_ascii=False) if not isinstance(cpe_configurations, str) else cpe_configurations
            else:
                cpe_configurations_json = None
                
            nvd_weaknesses_json = None
            if weaknesses:
                # Преобразуем weaknesses в JSON-совместимый формат
                weaknesses_list = []
                for weakness in weaknesses:
                    if isinstance(weakness, dict):
                        weaknesses_list.append(weakness)
                    else:
                        weaknesses_list.append({
                            'source': getattr(weakness, 'source', ''),
                            'type': getattr(weakness, 'type', ''),
                            'description': getattr(weakness, 'description', ''),
                            'cwe_id': getattr(weakness, 'cwe_id', '')
                        })
                nvd_weaknesses_json = json.dumps(weaknesses_list, ensure_ascii=False)
                
            source_identifier = getattr(vulnerability, 'source_identifier', None) or source
            nvd_status = getattr(vulnerability, 'vuln_status', None) or 'PUBLISHED'
            nvd_published = getattr(vulnerability, 'published', None) or start_date
            nvd_last_modified = getattr(vulnerability, 'last_modified', None) or end_date
            
            # Описания на разных языках
            nvd_descriptions = getattr(vulnerability, 'descriptions', None)
            if nvd_descriptions:
                nvd_descriptions_json = json.dumps(nvd_descriptions, ensure_ascii=False) if not isinstance(nvd_descriptions, str) else nvd_descriptions
            else:
                nvd_descriptions_json = None
                
            # CVSS метрики
            metrics = getattr(vulnerability, 'metrics', None)
            cvss_v2_metrics = None
            cvss_v3_metrics = None
            cvss_v4_metrics = None
            nvd_metrics_json = None
            if metrics:
                if isinstance(metrics, dict):
                    cvss_v2_metrics = json.dumps(metrics.get('cvss_v2'), ensure_ascii=False) if metrics.get('cvss_v2') else None
                    cvss_v3_metrics = json.dumps(metrics.get('cvss_v3'), ensure_ascii=False) if metrics.get('cvss_v3') else None
                    cvss_v4_metrics = json.dumps(metrics.get('cvss_v4'), ensure_ascii=False) if metrics.get('cvss_v4') else None
                    nvd_metrics_json = json.dumps(metrics, ensure_ascii=False)
                else:
                    # Если это NVDMetrics объект
                    cvss_v2_metrics = json.dumps(metrics.cvss_v2, ensure_ascii=False) if metrics.cvss_v2 else None
                    cvss_v3_metrics = json.dumps(metrics.cvss_v3, ensure_ascii=False) if metrics.cvss_v3 else None
                    cvss_v4_metrics = json.dumps(metrics.cvss_v4, ensure_ascii=False) if metrics.cvss_v4 else None
                    nvd_metrics_json = json.dumps({
                        'cvss_v2': metrics.cvss_v2,
                        'cvss_v3': metrics.cvss_v3,
                        'cvss_v4': metrics.cvss_v4
                    }, ensure_ascii=False)
            
            has_kev = getattr(vulnerability, 'has_kev', False) or False
            has_cert_alerts = getattr(vulnerability, 'has_cert_alerts', False) or False
            
            # CVE JSON 5.x данные (если есть)
            cve_json5_data = getattr(vulnerability, 'raw_cve_json5', None)
            if cve_json5_data:
                cve_json5_data_json = json.dumps(cve_json5_data, ensure_ascii=False) if not isinstance(cve_json5_data, str) else cve_json5_data
            else:
                cve_json5_data_json = None
            
            # Проверяем, существует ли уже запись с этим CVE ID
            cursor.execute("SELECT id FROM turn WHERE cve = %s", (cve_id,))
            existing_row = cursor.fetchone()
            existing = existing_row is not None
            
            if existing:
                logger.debug(f"   [TURN] Обновляем существующую запись для {cve_id}")
                # Обновляем существующую запись с новыми NVD полями
                cursor.execute("""
                    UPDATE turn SET
                        source = %s, link = %s, name = %s, cvss = %s,
                        price_one = %s, priority = %s, joining_date = %s,
                        start_date = %s, end_date = %s, etc = %s, status = %s,
                        cvss_v2_vector = %s, cvss_v3_vector = %s, cvss_v4_vector = %s,
                        cvss_version = %s, epss_score = %s, epss_percentile = %s,
                        cwe_ids = %s, affected_products = %s, nvd_references = %s,
                        vendor_comments = %s, cpe_configurations = %s, nvd_weaknesses = %s,
                        source_identifier = %s, nvd_status = %s, nvd_published = %s,
                        nvd_last_modified = %s, nvd_descriptions = %s, nvd_metrics = %s,
                        cvss_v2_metrics = %s, cvss_v3_metrics = %s, cvss_v4_metrics = %s,
                        has_kev = %s, has_cert_alerts = %s, cve_json5_data = %s
                    WHERE cve = %s
                    RETURNING id
                """, (
                    source, link, name, cvss, price_one, priority,
                    joining_date, start_date, end_date, etc, status,
                    cvss_v2_vector, cvss_v3_vector, cvss_v4_vector, cvss_version,
                    epss_score, epss_percentile, cwe_ids if cwe_ids else None,
                    affected_products_json, nvd_references_json, vendor_comments_json,
                    cpe_configurations_json, nvd_weaknesses_json, source_identifier,
                    nvd_status, nvd_published, nvd_last_modified, nvd_descriptions_json,
                    nvd_metrics_json, cvss_v2_metrics, cvss_v3_metrics, cvss_v4_metrics,
                    has_kev, has_cert_alerts, cve_json5_data_json, cve_id
                ))
            else:
                # Вставляем новую запись
                logger.debug(f"   [TURN] Вставляем новую запись для {cve_id}, source={source}")
                try:
                    cursor.execute("""
                        INSERT INTO turn (
                            source, link, cve, joining_date, name, cvss,
                            price_one, priority, start_date, end_date, etc, status,
                            cvss_v2_vector, cvss_v3_vector, cvss_v4_vector, cvss_version,
                            epss_score, epss_percentile, cwe_ids, affected_products, nvd_references,
                            vendor_comments, cpe_configurations, nvd_weaknesses,
                            source_identifier, nvd_status, nvd_published, nvd_last_modified,
                            nvd_descriptions, nvd_metrics, cvss_v2_metrics, cvss_v3_metrics, cvss_v4_metrics,
                            has_kev, has_cert_alerts, cve_json5_data
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                  %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (
                        source, link, cve_id, joining_date, name, cvss,
                        price_one, priority, start_date, end_date, etc, status,
                        cvss_v2_vector, cvss_v3_vector, cvss_v4_vector, cvss_version,
                        epss_score, epss_percentile, cwe_ids if cwe_ids else None,
                        affected_products_json, nvd_references_json, vendor_comments_json,
                        cpe_configurations_json, nvd_weaknesses_json, source_identifier,
                        nvd_status, nvd_published, nvd_last_modified, nvd_descriptions_json,
                        nvd_metrics_json, cvss_v2_metrics, cvss_v3_metrics, cvss_v4_metrics,
                        has_kev, has_cert_alerts, cve_json5_data_json
                    ))
                except Exception as insert_error:
                    # Если ошибка UNIQUE constraint, пытаемся обновить
                    if 'unique' in str(insert_error).lower() or 'duplicate' in str(insert_error).lower():
                        logger.warning(f"   ⚠️ [TURN] Дубликат CVE {cve_id}, обновляем существующую запись")
                        cursor.execute("""
                            UPDATE turn SET
                                source = %s, link = %s, name = %s, cvss = %s,
                                price_one = %s, priority = %s, joining_date = %s,
                                start_date = %s, end_date = %s, etc = %s, status = %s,
                                cvss_v2_vector = %s, cvss_v3_vector = %s, cvss_v4_vector = %s,
                                cvss_version = %s, epss_score = %s, epss_percentile = %s,
                                cwe_ids = %s, affected_products = %s, nvd_references = %s,
                                vendor_comments = %s, cpe_configurations = %s, nvd_weaknesses = %s,
                                source_identifier = %s, nvd_status = %s, nvd_published = %s,
                                nvd_last_modified = %s, nvd_descriptions = %s, nvd_metrics = %s,
                                cvss_v2_metrics = %s, cvss_v3_metrics = %s, cvss_v4_metrics = %s,
                                has_kev = %s, has_cert_alerts = %s, cve_json5_data = %s
                            WHERE cve = %s
                            RETURNING id
                        """, (
                            source, link, name, cvss, price_one, priority,
                            joining_date, start_date, end_date, etc, status,
                            cvss_v2_vector, cvss_v3_vector, cvss_v4_vector, cvss_version,
                            epss_score, epss_percentile, cwe_ids if cwe_ids else None,
                            affected_products_json, nvd_references_json, vendor_comments_json,
                            cpe_configurations_json, nvd_weaknesses_json, source_identifier,
                            nvd_status, nvd_published, nvd_last_modified, nvd_descriptions_json,
                            nvd_metrics_json, cvss_v2_metrics, cvss_v3_metrics, cvss_v4_metrics,
                            has_kev, has_cert_alerts, cve_json5_data_json, cve_id
                        ))
                    else:
                        raise  # Пробрасываем другие ошибки

            result = cursor.fetchone()
            turn_id = result[0] if result else None
            
            if turn_id:
                logger.info(f"   ✅ [TURN] Сохранено в turn: cve={cve_id}, turn_id={turn_id}, source={source}")
            else:
                logger.error(f"   ❌ [TURN] INSERT/UPDATE не вернул ID для {cve_id}")
                logger.error(f"   Параметры: source={source}, cve_id={cve_id}, name={name[:50]}")
            
            return turn_id

        except Exception as e:
            logger.error(f"❌ [TURN] Ошибка сохранения в turn для {cve_id}: {e}", exc_info=True)
            import traceback
            logger.error(f"   Traceback: {traceback.format_exc()}")
            return None

    def _save_to_cvelist(self, cursor, cve_id: str, vulnerability: Vulnerability):
        """Сохранение описаний CVE в таблицу cvelist"""
        try:
            # Получаем описания
            descriptions = getattr(vulnerability, 'descriptions', [])
            if not descriptions:
                # Используем основное описание
                ff_eng = vulnerability.description[:1000] if vulnerability.description else ''
                ff_rus = ''  # Русское описание, если есть
            else:
                # Ищем английское описание
                ff_eng = ''
                ff_rus = ''
                for desc in descriptions:
                    if isinstance(desc, dict):
                        lang = desc.get('lang', 'en')
                        value = desc.get('value', '')
                        if lang == 'en' and not ff_eng:
                            ff_eng = value[:1000]
                        elif lang == 'ru' and not ff_rus:
                            ff_rus = value[:1000]
                    elif isinstance(desc, str):
                        if not ff_eng:
                            ff_eng = desc[:1000]

                # Если английского нет, берем первое
                if not ff_eng and descriptions:
                    first_desc = descriptions[0]
                    if isinstance(first_desc, dict):
                        ff_eng = first_desc.get('value', '')[:1000]
                    else:
                        ff_eng = str(first_desc)[:1000]

            # Проверяем существование
            cursor.execute("SELECT cve FROM cvelist WHERE cve = %s", (cve_id,))
            if cursor.fetchone():
                # Обновляем
                cursor.execute("""
                    UPDATE cvelist SET ff_eng = %s, ff_rus = %s WHERE cve = %s
                """, (ff_eng, ff_rus, cve_id))
            else:
                # Вставляем
                cursor.execute("""
                    INSERT INTO cvelist (cve, ff_eng, ff_rus) VALUES (%s, %s, %s)
                """, (cve_id, ff_eng, ff_rus))

        except Exception as e:
            logger.error(f"Ошибка сохранения в cvelist: {e}")

    def _save_cwe_data(self, cursor, cve_id: str, vulnerability: Vulnerability):
        """Сохранение CWE данных в cwelist"""
        try:
            weaknesses = getattr(vulnerability, 'weaknesses', [])
            if not weaknesses:
                return

            for weakness in weaknesses:
                if isinstance(weakness, dict):
                    cwe_id = weakness.get('cwe_id') or weakness.get('cweId', '')
                    description = weakness.get('description', '')
                    if isinstance(description, dict):
                        description = description.get('value', '')
                else:
                    # Если это объект NVDWeakness
                    cwe_id = getattr(weakness, 'cwe_id', '')
                    description = getattr(weakness, 'description', '')

                if not cwe_id:
                    continue

                # Сохраняем в cwelist
                cursor.execute("SELECT cwe FROM cwelist WHERE cwe = %s", (cwe_id,))
                if not cursor.fetchone():
                    cursor.execute("""
                        INSERT INTO cwelist (cwe, interpretation, wayexploitation)
                        VALUES (%s, %s, %s)
                    """, (cwe_id, description[:500], ''))

        except Exception as e:
            logger.error(f"Ошибка сохранения CWE: {e}")

    def _save_to_map_table(self, cursor, cve_id: str, vulnerability: Vulnerability):
        """Сохранение маппинга в map_table"""
        try:
            # CVSS
            cvss_str = str(vulnerability.cvss_score) if vulnerability.cvss_score else '0.0'

            # CWE (берем первый из weaknesses)
            cwe = ''
            weaknesses = getattr(vulnerability, 'weaknesses', [])
            if weaknesses:
                first_weak = weaknesses[0]
                if isinstance(first_weak, dict):
                    cwe = first_weak.get('cwe_id') or first_weak.get('cweId', '')
                else:
                    cwe = getattr(first_weak, 'cwe_id', '')

            # Exploit (на основе has_kev или других индикаторов)
            exploit = getattr(vulnerability, 'has_kev', False) or False

            # Patch (если есть vendor_comments или другие индикаторы)
            patch = bool(getattr(vulnerability, 'vendor_comments', []))

            # Attack_compl (категория или attack complexity)
            attack_compl = vulnerability.category or 'unknown'

            # Проверяем существование
            cursor.execute("SELECT cve FROM map_table WHERE cve = %s", (cve_id,))
            if cursor.fetchone():
                # Обновляем
                cursor.execute("""
                    UPDATE map_table SET
                        cvss = %s, cwe = %s, exploit = %s, patch = %s, attack_compl = %s
                    WHERE cve = %s
                """, (cvss_str, cwe, exploit, patch, attack_compl, cve_id))
            else:
                # Вставляем
                cursor.execute("""
                    INSERT INTO map_table (cve, cvss, cwe, exploit, patch, attack_compl)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (cve_id, cvss_str, cwe, exploit, patch, attack_compl))

        except Exception as e:
            logger.error(f"Ошибка сохранения в map_table: {e}")

    def assign_operator(self, vuln_id: int, operator_id: int) -> bool:
        """Назначение оператора на уязвимость (сохранение в actids)"""
        try:
            # Получаем CVE по ID уязвимости
            with self.db.cursor() as cursor:
                cursor.execute("SELECT cve FROM turn WHERE id = %s", (vuln_id,))
                row = cursor.fetchone()
                if not row or not row[0]:
                    logger.error(f"❌ [assign_operator] Уязвимость с ID {vuln_id} не найдена или не имеет CVE")
                    return False
                cve_id = row[0]
            
            # Получаем имя оператора по ID из таблицы users
            operator_name = None
            with self.db.cursor() as cursor:
                cursor.execute("SELECT username, email FROM users WHERE id = %s", (operator_id,))
                user_row = cursor.fetchone()
                if user_row:
                    operator_name = user_row[0] or user_row[1]
                    logger.debug(f"🔍 [assign_operator] Найден оператор ID {operator_id}: {operator_name}")
                else:
                    logger.error(f"❌ [assign_operator] Оператор с ID {operator_id} не найден в users")
                    return False
            
            if not operator_name:
                logger.error(f"❌ [assign_operator] Не удалось получить имя оператора для ID {operator_id}")
                return False
            
            # Сохраняем назначение в actids
            with self.db.cursor() as cursor:
                uid = uuid.uuid4()
                cursor.execute("""
                    INSERT INTO actids (cve, uid, active, oper)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (cve, oper) DO UPDATE SET active = %s, uid = %s
                """, (cve_id, uid, True, operator_name, True, uid))
                self.db.commit()
                logger.info(f"✅ [assign_operator] Уязвимость {vuln_id} (CVE: {cve_id}) назначена оператору {operator_name} (ID: {operator_id})")
                return True
        except Exception as e:
            logger.error(f"❌ [assign_operator] Ошибка назначения оператора: {e}", exc_info=True)
            self.db.rollback()
            return False

    def unassign_operator(self, vuln_id: int) -> bool:
        """Снять назначение оператора с уязвимости (удаление из actids)"""
        try:
            # Получаем CVE по ID уязвимости
            with self.db.cursor() as cursor:
                cursor.execute("SELECT cve FROM turn WHERE id = %s", (vuln_id,))
                row = cursor.fetchone()
                if not row or not row[0]:
                    logger.error(f"❌ [unassign_operator] Уязвимость с ID {vuln_id} не найдена или не имеет CVE")
                    return False
                cve_id = row[0]
            
            # Удаляем назначение из actids (устанавливаем active = FALSE)
            with self.db.cursor() as cursor:
                cursor.execute("""
                    UPDATE actids 
                    SET active = FALSE 
                    WHERE cve = %s
                """, (cve_id,))
                self.db.commit()
                logger.info(f"✅ [unassign_operator] Назначение снято с уязвимости {vuln_id} (CVE: {cve_id})")
                return True
        except Exception as e:
            logger.error(f"❌ [unassign_operator] Ошибка снятия назначения: {e}", exc_info=True)
            self.db.rollback()
            return False

    def get_vulnerabilities_by_operator(self, operator_id: int) -> List[Vulnerability]:
        """Получить все уязвимости, назначенные оператору"""
        try:
            from models.entities import Vulnerability
            import json
            
            # Сначала получаем имя оператора по ID из таблицы users
            operator_name = None
            try:
                with self.db.cursor() as cursor:
                    # Пробуем получить из users (если есть поле username или email)
                    cursor.execute("SELECT username, email FROM users WHERE id = %s", (operator_id,))
                    user_row = cursor.fetchone()
                    if user_row:
                        operator_name = user_row[0] or user_row[1]
                        logger.debug(f"🔍 [get_vulnerabilities_by_operator] Найден пользователь ID {operator_id}: {operator_name}")
                    
                    # Если не нашли в users, пробуем получить из operators по ID
                    # Но в legacy схеме operators хранит только operator (имя) и level
                    # Нужно проверить, есть ли связь через другую таблицу
                    if not operator_name:
                        # Пробуем найти оператора по ID через другие таблицы
                        # В legacy схеме может не быть прямой связи operator_id -> operator_name
                        # Возвращаем пустой список, если не можем найти оператора
                        logger.warning(f"⚠️ [get_vulnerabilities_by_operator] Не удалось найти оператора по ID {operator_id}")
                        return []
            except Exception as e:
                logger.error(f"❌ [get_vulnerabilities_by_operator] Ошибка получения имени оператора: {e}")
                return []
            
            if not operator_name:
                logger.warning(f"⚠️ [get_vulnerabilities_by_operator] Оператор с ID {operator_id} не найден")
                return []
            
            # Получаем все CVE, назначенные этому оператору из actids
            vulnerabilities = []
            with self.db.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT cve FROM actids 
                    WHERE oper = %s AND active = TRUE
                """, (operator_name,))
                cve_rows = cursor.fetchall()
                cve_list = [row[0] for row in cve_rows]
                
                if not cve_list:
                    logger.debug(f"🔍 [get_vulnerabilities_by_operator] Нет назначенных уязвимостей для оператора {operator_name}")
                    return []
                
                logger.debug(f"🔍 [get_vulnerabilities_by_operator] Найдено {len(cve_list)} CVE для оператора {operator_name}")
                
                # Получаем уязвимости по CVE из таблицы turn
                placeholders = ','.join(['%s'] * len(cve_list))
                cursor.execute(f"""
                    SELECT id, source, link, cve, joining_date, name, cvss, 
                           price_one, priority, start_date, end_date, etc, status, nvd_descriptions
                    FROM turn
                    WHERE cve IN ({placeholders})
                    ORDER BY joining_date DESC
                """, tuple(cve_list))
                rows = cursor.fetchall()
                
                for row in rows:
                    try:
                        etc_data = json.loads(row[11]) if row[11] else {}
                    except:
                        etc_data = {}
                    
                    # Загружаем описание из nvd_descriptions (приоритет) или cvelist (fallback)
                    description = ''
                    nvd_descriptions = row[13] if len(row) > 13 else None
                    
                    # Пробуем извлечь описание из nvd_descriptions
                    if nvd_descriptions:
                        try:
                            if isinstance(nvd_descriptions, str):
                                desc_data = json.loads(nvd_descriptions)
                            else:
                                desc_data = nvd_descriptions
                            
                            if isinstance(desc_data, list) and len(desc_data) > 0:
                                for desc_item in desc_data:
                                    if isinstance(desc_item, dict):
                                        lang = desc_item.get('lang', 'en')
                                        value = desc_item.get('value', '')
                                        if lang == 'en' and value:
                                            description = value
                                            break
                                if not description:
                                    first_desc = desc_data[0]
                                    if isinstance(first_desc, dict):
                                        description = first_desc.get('value', '')
                                    else:
                                        description = str(first_desc)
                            elif isinstance(desc_data, dict):
                                description = desc_data.get('value', '') or str(desc_data)
                        except:
                            pass
                    
                    # Если описание не найдено в nvd_descriptions, пробуем cvelist
                    if not description:
                        try:
                            cursor.execute("SELECT ff_eng, ff_rus FROM cvelist WHERE cve = %s", (row[3],))
                            cve_row = cursor.fetchone()
                            if cve_row:
                                description = cve_row[0] or cve_row[1] or ''
                        except:
                            pass
                    
                    # Определяем title: если name = CVE ID, используем только CVE ID
                    cve_id = row[3] or ''
                    name = row[5] or ''
                    if name == cve_id:
                        title = cve_id
                    elif name and name.strip():
                        title = cve_id if cve_id else name
                    else:
                        title = cve_id or 'Unknown'
                    
                    vuln = Vulnerability(
                        id=row[0],
                        title=title,  # Используем исправленный title
                        description=description,  # Описание из nvd_descriptions или cvelist
                        severity=self._cvss_to_severity(row[6] or 0.0),
                        status='new' if row[12] else 'completed',
                        assigned_operator=operator_id,  # Сохраняем operator_id
                        created_date=row[4],
                        completed_date=row[10],
                        approved=etc_data.get('approved', False),
                        modifications=etc_data.get('modifications', 0),
                        cvss_score=float(row[6] or 0.0),
                        risk_level=etc_data.get('risk_level', 'medium'),
                        category=etc_data.get('category', row[1] or 'unknown'),
                        cve_id=cve_id
                    )
                    vuln.source_identifier = row[1] or 'NVD'
                    vulnerabilities.append(vuln)
            
            logger.info(f"✅ [get_vulnerabilities_by_operator] Возвращаем {len(vulnerabilities)} уязвимостей для оператора {operator_name} (ID: {operator_id})")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"❌ [get_vulnerabilities_by_operator] Ошибка получения уязвимостей для оператора {operator_id}: {e}", exc_info=True)
            return []

    def get_by_id(self, vuln_id: int) -> Optional[Vulnerability]:
        """Получение уязвимости по ID из таблицы turn"""
        try:
            from models.entities import Vulnerability
            import json
            
            with self.db.cursor() as cursor:
                cursor.execute("""
                    SELECT id, source, link, cve, joining_date, name, cvss, 
                           price_one, priority, start_date, end_date, etc, status, nvd_descriptions
                    FROM turn WHERE id = %s
                """, (vuln_id,))
                row = cursor.fetchone()
                
                if not row:
                    logger.debug(f"⚠️ [get_by_id] Уязвимость с ID {vuln_id} не найдена в turn")
                    return None
                
                # Парсим etc данные
                try:
                    etc_data = json.loads(row[11]) if row[11] else {}
                except:
                    etc_data = {}
                
                # Загружаем описание из nvd_descriptions (приоритет) или cvelist (fallback)
                description = ''
                nvd_descriptions = row[13] if len(row) > 13 else None
                
                # Пробуем извлечь описание из nvd_descriptions
                if nvd_descriptions:
                    try:
                        if isinstance(nvd_descriptions, str):
                            desc_data = json.loads(nvd_descriptions)
                        else:
                            desc_data = nvd_descriptions
                        
                        if isinstance(desc_data, list) and len(desc_data) > 0:
                            for desc_item in desc_data:
                                if isinstance(desc_item, dict):
                                    lang = desc_item.get('lang', 'en')
                                    value = desc_item.get('value', '')
                                    if lang == 'en' and value:
                                        description = value
                                        break
                            if not description:
                                first_desc = desc_data[0]
                                if isinstance(first_desc, dict):
                                    description = first_desc.get('value', '')
                                else:
                                    description = str(first_desc)
                        elif isinstance(desc_data, dict):
                            description = desc_data.get('value', '') or str(desc_data)
                        logger.debug(f"✅ [get_by_id] Загружено описание из nvd_descriptions для {row[3]}: {len(description)} символов")
                    except Exception as e:
                        logger.debug(f"⚠️ [get_by_id] Ошибка парсинга nvd_descriptions для {row[3]}: {e}")
                
                # Если описание не найдено в nvd_descriptions, пробуем cvelist
                if not description:
                    try:
                        cursor.execute("SELECT ff_eng, ff_rus FROM cvelist WHERE cve = %s", (row[3],))
                        cve_row = cursor.fetchone()
                        if cve_row:
                            description = cve_row[0] or cve_row[1] or ''
                            logger.debug(f"✅ [get_by_id] Загружено описание из cvelist для {row[3]}: {len(description)} символов")
                        else:
                            logger.debug(f"⚠️ [get_by_id] Описание для {row[3]} не найдено в cvelist")
                    except Exception as e:
                        logger.debug(f"⚠️ [get_by_id] Ошибка загрузки описания из cvelist для {row[3]}: {e}")
                
                # Определяем title: если name = CVE ID, используем только CVE ID
                cve_id = row[3] or ''
                name = row[5] or ''
                if name == cve_id:
                    title = cve_id
                elif name and name.strip():
                    title = cve_id if cve_id else name
                else:
                    title = cve_id or 'Unknown'
                
                # Загружаем назначенного оператора из actids
                assigned_operator_id = None
                try:
                    cursor.execute("""
                        SELECT oper FROM actids 
                        WHERE cve = %s AND active = TRUE 
                        LIMIT 1
                    """, (row[3],))
                    actids_row = cursor.fetchone()
                    if actids_row:
                        operator_name = actids_row[0]
                        # Получаем operator_id по имени оператора из users
                        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s LIMIT 1", (operator_name, operator_name))
                        user_row = cursor.fetchone()
                        if user_row:
                            assigned_operator_id = user_row[0]
                            logger.debug(f"🔍 [get_by_id] Найден назначенный оператор для CVE {row[3]}: {operator_name} (ID: {assigned_operator_id})")
                except Exception as e:
                    logger.debug(f"⚠️ [get_by_id] Ошибка загрузки оператора для {row[3]}: {e}")
                
                vulnerability = Vulnerability(
                    id=row[0],
                    title=title,  # Используем исправленный title
                    description=description,  # Описание из nvd_descriptions или cvelist
                    severity=self._cvss_to_severity(row[6] or 0.0),
                    status='new' if row[12] else 'completed',
                    assigned_operator=assigned_operator_id,
                    created_date=row[4],
                    completed_date=row[10],
                    approved=etc_data.get('approved', False),
                    modifications=etc_data.get('modifications', 0),
                    cvss_score=float(row[6] or 0.0),
                    risk_level=etc_data.get('risk_level', 'medium'),
                    category=etc_data.get('category', row[1] or 'unknown'),
                    cve_id=cve_id
                )
                vulnerability.source_identifier = row[1] or 'NVD'
                
                logger.info(f"✅ [get_by_id] Уязвимость ID {vuln_id} загружена: CVE={cve_id}, title={title}, описание={len(description)} символов")
                return vulnerability
                
        except Exception as e:
            logger.error(f"❌ [get_by_id] Ошибка получения уязвимости по ID {vuln_id}: {e}", exc_info=True)
            return None

    def get_by_cve_id(self, cve_id: str) -> Optional[Vulnerability]:
        """Получение уязвимости по CVE ID (совместимость с modern репозиторием)"""
        turn_data = self.get_by_cve(cve_id)
        if not turn_data:
            return None
        
        # Конвертируем данные из turn в Vulnerability
        from models.entities import Vulnerability
        import json
        
        etc_data = json.loads(turn_data.get('etc', '{}')) if turn_data.get('etc') else {}
        
        vulnerability = Vulnerability(
            id=turn_data.get('id', 0),
            title=turn_data.get('name', cve_id),
            description='',  # Будет загружено из cvelist
            severity='medium',  # Будет определено из CVSS
            status='new' if turn_data.get('status') else 'completed',
            assigned_operator=None,
            created_date=turn_data.get('joining_date'),
            completed_date=turn_data.get('end_date'),
            approved=etc_data.get('approved', False),
            modifications=etc_data.get('modifications', 0),
            cvss_score=float(turn_data.get('cvss', 0.0)),
            risk_level=etc_data.get('risk_level', 'medium'),
            category=etc_data.get('category', 'security'),
            cve_id=cve_id
        )
        
        # Загружаем описание из cvelist
        try:
            with self.db.cursor() as cursor:
                cursor.execute("SELECT ff_eng, ff_rus FROM cvelist WHERE cve = %s", (cve_id,))
                cve_row = cursor.fetchone()
                if cve_row:
                    vulnerability.description = cve_row[0] or cve_row[1] or ''
        except:
            pass
        
        return vulnerability

    def get_by_cve(self, cve_id: str) -> Optional[Dict]:
        """Получение уязвимости по CVE из таблицы turn"""
        try:
            with self.db.cursor() as cursor:
                cursor.execute("""
                    SELECT source, link, cve, joining_date, name, cvss, price_one,
                           priority, start_date, end_date, etc, status, id
                    FROM turn WHERE cve = %s
                """, (cve_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        'source': row[0],
                        'link': row[1],
                        'cve': row[2],
                        'joining_date': row[3],
                        'name': row[4],
                        'cvss': row[5],
                        'price_one': row[6],
                        'priority': row[7],
                        'start_date': row[8],
                        'end_date': row[9],
                        'etc': row[10],
                        'status': row[11],
                        'id': row[12]
                    }
                return None
        except Exception as e:
            logger.error(f"Ошибка получения уязвимости: {e}")
            return None

    def bulk_save_nvd_vulnerabilities(self, vulnerabilities: List[Dict]) -> int:
        """
        Массовое сохранение уязвимостей из NVD в legacy схему
        Принимает список словарей с данными NVD уязвимостей
        """
        from models.legacy_adapter import dict_to_vulnerability
        from models.entities import NVDVulnerability
        
        saved_count = 0
        for vuln_dict in vulnerabilities:
            try:
                # Конвертируем словарь в NVDVulnerability, затем в Vulnerability
                # Упрощенная конвертация для legacy схемы
                vulnerability = self._dict_to_vulnerability_for_legacy(vuln_dict)
                if self.save_vulnerability(vulnerability):
                    saved_count += 1
            except Exception as e:
                logger.error(f"Ошибка сохранения уязвимости {vuln_dict.get('cve_id', 'unknown')}: {e}")
        
        return saved_count

    def _dict_to_vulnerability_for_legacy(self, vuln_dict: Dict) -> Vulnerability:
        """Конвертация словаря NVD уязвимости в Vulnerability для legacy схемы"""
        from models.entities import Vulnerability
        from datetime import datetime
        
        cve_id = vuln_dict.get('cve_id', '')
        descriptions = vuln_dict.get('descriptions', [])
        
        # Получаем описание
        description = ""
        if descriptions:
            for desc in descriptions:
                if isinstance(desc, dict) and desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                first_desc = descriptions[0]
                description = first_desc.get('value', '') if isinstance(first_desc, dict) else str(first_desc)
        
        # Определяем severity и CVSS
        metrics = vuln_dict.get('metrics', {})
        cvss_score = 0.0
        severity = 'medium'
        
        if metrics.get('cvss_v4'):
            cvss_data = metrics['cvss_v4']
            cvss_score = float(cvss_data.get('baseScore', 0.0))
            severity_str = cvss_data.get('baseSeverity', 'medium').lower()
        elif metrics.get('cvss_v3'):
            cvss_data = metrics['cvss_v3']
            cvss_score = float(cvss_data.get('baseScore', 0.0))
            severity_str = cvss_data.get('baseSeverity', 'medium').lower()
        elif metrics.get('cvss_v2'):
            cvss_data = metrics['cvss_v2']
            cvss_score = float(cvss_data.get('baseScore', 0.0))
            severity_str = 'medium'
        else:
            severity_str = 'medium'
        
        severity_map = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low'}
        severity = severity_map.get(severity_str, 'medium')
        
        # Парсим даты
        published_str = vuln_dict.get('published', '')
        try:
            published = datetime.fromisoformat(published_str.replace('Z', '+00:00')) if published_str else datetime.now()
        except:
            published = datetime.now()
        
        vulnerability = Vulnerability(
            id=0,
            title=cve_id or 'Unknown CVE',
            description=description[:1000],
            severity=severity,
            status='new',
            assigned_operator=None,
            created_date=datetime.now(),
            completed_date=None,
            approved=False,
            modifications=0,
            cvss_score=cvss_score,
            risk_level=severity,
            category='security',
            cve_id=cve_id
        )
        
        # Добавляем NVD поля
        vulnerability.source_identifier = vuln_dict.get('source_identifier', 'NVD')
        vulnerability.published = published
        vulnerability.last_modified = published
        vulnerability.vuln_status = vuln_dict.get('vuln_status', '')
        vulnerability.descriptions = descriptions
        vulnerability.metrics = metrics
        vulnerability.weaknesses = vuln_dict.get('weaknesses', [])
        vulnerability.configurations = vuln_dict.get('configurations', [])
        vulnerability.references = vuln_dict.get('references', [])
        vulnerability.vendor_comments = vuln_dict.get('vendor_comments', [])
        vulnerability.is_ai_related = vuln_dict.get('is_ai_related', False)
        vulnerability.ai_confidence = float(vuln_dict.get('ai_confidence', 0.0))
        vulnerability.has_kev = vuln_dict.get('has_kev', False)
        vulnerability.has_cert_alerts = vuln_dict.get('has_cert_alerts', False)
        
        return vulnerability

    def get_all(self) -> List[Vulnerability]:
        """Получить все уязвимости из таблицы turn (для совместимости с VulnerabilityService)"""
        return self.get_all_vulnerabilities()
    
    def get_all_vulnerabilities(self, limit: Optional[int] = None) -> List[Vulnerability]:
        """Получить все уязвимости из таблицы turn (для совместимости)"""
        try:
            from models.entities import Vulnerability
            import json
            
            vulnerabilities = []
            with self.db.cursor() as cursor:
                # Если limit не указан, получаем все записи (или очень большое число)
                if limit is None:
                    limit_clause = ""  # Без ограничения
                else:
                    limit_clause = f"LIMIT {limit}"
                
                cursor.execute(f"""
                    SELECT id, source, link, cve, joining_date, name, cvss, 
                           price_one, priority, start_date, end_date, etc, status, nvd_descriptions
                    FROM turn
                    ORDER BY joining_date DESC
                    {limit_clause}
                """)
                rows = cursor.fetchall()
                
                for row in rows:
                    try:
                        etc_data = json.loads(row[11]) if row[11] else {}
                    except:
                        etc_data = {}
                    
                    # Загружаем описание из nvd_descriptions (приоритет) или cvelist (fallback)
                    description = ''
                    nvd_descriptions = row[13] if len(row) > 13 else None
                    
                    # Пробуем извлечь описание из nvd_descriptions
                    if nvd_descriptions:
                        try:
                            if isinstance(nvd_descriptions, str):
                                desc_data = json.loads(nvd_descriptions)
                            else:
                                desc_data = nvd_descriptions
                            
                            if isinstance(desc_data, list) and len(desc_data) > 0:
                                for desc_item in desc_data:
                                    if isinstance(desc_item, dict):
                                        lang = desc_item.get('lang', 'en')
                                        value = desc_item.get('value', '')
                                        if lang == 'en' and value:
                                            description = value
                                            break
                                if not description:
                                    first_desc = desc_data[0]
                                    if isinstance(first_desc, dict):
                                        description = first_desc.get('value', '')
                                    else:
                                        description = str(first_desc)
                            elif isinstance(desc_data, dict):
                                description = desc_data.get('value', '') or str(desc_data)
                        except:
                            pass
                    
                    # Если описание не найдено в nvd_descriptions, пробуем cvelist
                    if not description:
                        try:
                            cursor.execute("SELECT ff_eng, ff_rus FROM cvelist WHERE cve = %s", (row[3],))
                            cve_row = cursor.fetchone()
                            if cve_row:
                                description = cve_row[0] or cve_row[1] or ''
                        except:
                            pass
                    
                    # Определяем title: если name = CVE ID, используем только CVE ID
                    cve_id = row[3] or ''
                    name = row[5] or ''
                    if name == cve_id:
                        title = cve_id
                    elif name and name.strip():
                        title = cve_id if cve_id else name
                    else:
                        title = cve_id or 'Unknown'
                    
                    # Загружаем назначенного оператора из actids
                    assigned_operator_id = None
                    try:
                        cursor.execute("""
                            SELECT oper FROM actids 
                            WHERE cve = %s AND active = TRUE 
                            LIMIT 1
                        """, (row[3],))
                        actids_row = cursor.fetchone()
                        if actids_row:
                            operator_name = actids_row[0]
                            # Получаем operator_id по имени оператора из users
                            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s LIMIT 1", (operator_name, operator_name))
                            user_row = cursor.fetchone()
                            if user_row:
                                assigned_operator_id = user_row[0]
                    except Exception as e:
                        logger.debug(f"⚠️ [get_all_vulnerabilities] Ошибка загрузки оператора для {row[3]}: {e}")
                    
                    vuln = Vulnerability(
                        id=row[0],
                        title=title,  # Используем исправленный title
                        description=description,  # Описание из nvd_descriptions или cvelist
                        severity=self._cvss_to_severity(row[6] or 0.0),
                        status='new' if row[12] else 'completed',
                        assigned_operator=assigned_operator_id,
                        created_date=row[4],
                        completed_date=row[10],
                        approved=etc_data.get('approved', False),
                        modifications=etc_data.get('modifications', 0),
                        cvss_score=float(row[6] or 0.0),
                        risk_level=etc_data.get('risk_level', 'medium'),
                        category=etc_data.get('category', row[1] or 'unknown'),
                        cve_id=cve_id
                    )
                    vuln.source_identifier = row[1] or 'NVD'
                    vulnerabilities.append(vuln)
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Ошибка получения всех уязвимостей: {e}", exc_info=True)
            return []

    def get_paginated(self, page: int = 1, per_page: int = 50,
                     status: Optional[str] = None, severity: Optional[str] = None,
                     search: Optional[str] = None) -> Tuple[List[Vulnerability], int]:
        """Получить уязвимости с пагинацией и фильтрацией"""
        try:
            from models.entities import Vulnerability
            import json
            
            logger.debug(f"🔍 [get_paginated] Запрос: page={page}, per_page={per_page}, status={status}, severity={severity}, search={search}")
            
            # Построение WHERE условий
            where_conditions = []
            params = []
            
            if status:
                # status в turn - это boolean, нужно конвертировать
                if status == 'new':
                    where_conditions.append("status = TRUE")
                elif status == 'completed':
                    where_conditions.append("status = FALSE")
            
            if severity:
                # Определяем диапазон CVSS для severity
                cvss_ranges = {
                    'critical': (9.0, 10.0),
                    'high': (7.0, 9.0),
                    'medium': (4.0, 7.0),
                    'low': (0.0, 4.0)
                }
                if severity in cvss_ranges:
                    min_cvss, max_cvss = cvss_ranges[severity]
                    where_conditions.append(f"cvss >= %s AND cvss < %s")
                    params.extend([min_cvss, max_cvss])
            
            if search:
                where_conditions.append("(cve ILIKE %s OR name ILIKE %s)")
                search_pattern = f"%{search}%"
                params.extend([search_pattern, search_pattern])
            
            where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
            logger.debug(f"🔍 [get_paginated] WHERE clause: {where_clause}, params={params}")
            
            # Подсчет общего количества
            count_query = f"SELECT COUNT(*) FROM turn WHERE {where_clause}"
            logger.debug(f"🔍 [get_paginated] Count query: {count_query}")
            
            # Проверяем соединение
            if self.db is None or self.db.closed:
                logger.error("❌ [get_paginated] Соединение с БД закрыто или None")
                return [], 0
            
            with self.db.cursor() as cursor:
                cursor.execute(count_query, tuple(params))
                total_count = cursor.fetchone()[0]
                logger.info(f"📊 [get_paginated] Всего уязвимостей в БД: {total_count}")
            
            # Получение данных с пагинацией
            offset = (page - 1) * per_page
            query = f"""
                SELECT id, source, link, cve, joining_date, name, cvss, 
                       price_one, priority, start_date, end_date, etc, status, nvd_descriptions
                FROM turn
                WHERE {where_clause}
                ORDER BY id DESC, joining_date DESC
                LIMIT %s OFFSET %s
            """
            query_params = list(params) + [per_page, offset]
            logger.debug(f"🔍 [get_paginated] Data query: {query[:100]}..., params={query_params}")
            
            vulnerabilities = []
            with self.db.cursor() as cursor:
                cursor.execute(query, tuple(query_params))
                rows = cursor.fetchall()
                logger.info(f"📊 [get_paginated] Получено строк из БД: {len(rows)}")
                
                for row in rows:
                    try:
                        etc_data = json.loads(row[11]) if row[11] else {}
                    except:
                        etc_data = {}
                    
                    # Загружаем описание из nvd_descriptions (приоритет) или cvelist (fallback)
                    description = ''
                    nvd_descriptions = row[13] if len(row) > 13 else None
                    
                    # Пробуем извлечь описание из nvd_descriptions
                    if nvd_descriptions:
                        try:
                            if isinstance(nvd_descriptions, str):
                                desc_data = json.loads(nvd_descriptions)
                            else:
                                desc_data = nvd_descriptions
                            
                            if isinstance(desc_data, list) and len(desc_data) > 0:
                                # Ищем английское описание
                                for desc_item in desc_data:
                                    if isinstance(desc_item, dict):
                                        lang = desc_item.get('lang', 'en')
                                        value = desc_item.get('value', '')
                                        if lang == 'en' and value:
                                            description = value
                                            break
                                # Если английского нет, берем первое
                                if not description:
                                    first_desc = desc_data[0]
                                    if isinstance(first_desc, dict):
                                        description = first_desc.get('value', '')
                                    else:
                                        description = str(first_desc)
                            elif isinstance(desc_data, dict):
                                description = desc_data.get('value', '') or str(desc_data)
                        except Exception as e:
                            logger.debug(f"⚠️ [get_paginated] Ошибка парсинга nvd_descriptions для {row[3]}: {e}")
                    
                    # Если описание не найдено в nvd_descriptions, пробуем cvelist
                    if not description:
                        try:
                            cursor.execute("SELECT ff_eng, ff_rus FROM cvelist WHERE cve = %s", (row[3],))
                            cve_row = cursor.fetchone()
                            if cve_row:
                                description = cve_row[0] or cve_row[1] or ''
                        except Exception as e:
                            logger.debug(f"⚠️ [get_paginated] Ошибка загрузки описания из cvelist для {row[3]}: {e}")
                    
                    # Определяем title: если name = CVE ID, используем только CVE ID, иначе name
                    cve_id = row[3] or ''
                    name = row[5] or ''
                    if name == cve_id:
                        # name совпадает с CVE ID - используем только CVE ID
                        title = cve_id
                    elif name and name.strip():
                        # name содержит что-то другое (например, описание) - используем только CVE ID если есть
                        title = cve_id if cve_id else name
                    else:
                        # name пустое - используем CVE ID
                        title = cve_id or 'Unknown'
                    
                    # Загружаем назначенного оператора из actids
                    assigned_operator_id = None
                    try:
                        cursor.execute("""
                            SELECT oper FROM actids 
                            WHERE cve = %s AND active = TRUE 
                            LIMIT 1
                        """, (row[3],))
                        actids_row = cursor.fetchone()
                        if actids_row:
                            operator_name = actids_row[0]
                            # Получаем operator_id по имени оператора из users
                            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s LIMIT 1", (operator_name, operator_name))
                            user_row = cursor.fetchone()
                            if user_row:
                                assigned_operator_id = user_row[0]
                                logger.debug(f"🔍 [get_paginated] Найден назначенный оператор для CVE {row[3]}: {operator_name} (ID: {assigned_operator_id})")
                    except Exception as e:
                        logger.debug(f"⚠️ [get_paginated] Ошибка загрузки оператора для {row[3]}: {e}")
                    
                    vuln = Vulnerability(
                        id=row[0],
                        title=title,  # Используем исправленный title
                        description=description,  # Описание из nvd_descriptions или cvelist
                        severity=self._cvss_to_severity(row[6] or 0.0),
                        status='new' if row[12] else 'completed',
                        assigned_operator=assigned_operator_id,
                        created_date=row[4],
                        completed_date=row[10],
                        approved=etc_data.get('approved', False),
                        modifications=etc_data.get('modifications', 0),
                        cvss_score=float(row[6] or 0.0),
                        risk_level=etc_data.get('risk_level', 'medium'),
                        category=etc_data.get('category', row[1] or 'unknown'),
                        cve_id=cve_id
                    )
                    vuln.source_identifier = row[1] or 'NVD'
                    vulnerabilities.append(vuln)
            
            logger.info(f"✅ [get_paginated] Возвращаем {len(vulnerabilities)} уязвимостей из {total_count}")
            return vulnerabilities, total_count
        except Exception as e:
            logger.error(f"❌ [get_paginated] Ошибка получения уязвимостей с пагинацией: {e}", exc_info=True)
            return [], 0

    def _cvss_to_severity(self, cvss: float) -> str:
        """Конвертация CVSS score в severity"""
        if cvss >= 9.0:
            return 'critical'
        elif cvss >= 7.0:
            return 'high'
        elif cvss >= 4.0:
            return 'medium'
        else:
            return 'low'


class LegacyOperatorRepository:
    """Репозиторий для работы с таблицей operators"""

    def __init__(self, db_connection):
        self.db = db_connection

    def save_operator(self, operator: Operator) -> bool:
        """Сохранение оператора в таблицу operators"""
        try:
            with self.db.cursor() as cursor:
                # Проверяем существование
                cursor.execute("SELECT operator FROM operators WHERE operator = %s", (operator.name,))
                if cursor.fetchone():
                    # Обновляем
                    cursor.execute("""
                        UPDATE operators SET level = %s WHERE operator = %s
                    """, (operator.current_metric, operator.name))
                else:
                    # Вставляем
                    cursor.execute("""
                        INSERT INTO operators (operator, level) VALUES (%s, %s)
                    """, (operator.name, operator.current_metric))

                self.db.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка сохранения оператора: {e}")
            self.db.rollback()
            return False

    def get_all(self) -> List[Dict]:
        """Получение всех операторов"""
        try:
            with self.db.cursor() as cursor:
                cursor.execute("SELECT operator, level FROM operators")
                return [{'name': row[0], 'level': row[1]} for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Ошибка получения операторов: {e}")
            return []

