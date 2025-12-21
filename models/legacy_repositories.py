"""
Адаптер репозиториев для работы с существующей схемой БД
Таблицы: turn, cvelist, cwelist, map_table, operators, actids и др.
"""
import logging
import json
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any
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
            cve_id = getattr(vulnerability, 'cve_id', None) or vulnerability.title
            
            # 1. Сохраняем в таблицу turn
            turn_id = self._save_to_turn(cursor, vulnerability)
            if not turn_id:
                logger.warning(f"⚠️ Не удалось сохранить в turn для {cve_id}")
                self.db.rollback()
                if cursor:
                    cursor.close()
                return False

            # 2. Если есть CVE, сохраняем в cvelist
            if cve_id and cve_id != 'UNKNOWN':
                try:
                    self._save_to_cvelist(cursor, cve_id, vulnerability)
                except Exception as e:
                    logger.warning(f"⚠️ Ошибка сохранения в cvelist для {cve_id}: {e}")

            # 3. Если есть CWE (weaknesses), сохраняем в cwelist и map_table
            if hasattr(vulnerability, 'weaknesses') and vulnerability.weaknesses:
                try:
                    self._save_cwe_data(cursor, cve_id, vulnerability)
                except Exception as e:
                    logger.warning(f"⚠️ Ошибка сохранения CWE для {cve_id}: {e}")

            # 4. Сохраняем маппинг в map_table
            try:
                self._save_to_map_table(cursor, cve_id, vulnerability)
            except Exception as e:
                logger.warning(f"⚠️ Ошибка сохранения в map_table для {cve_id}: {e}")

            # Коммитим транзакцию
            self.db.commit()
            logger.info(f"✅ Уязвимость {cve_id} сохранена в legacy схему (turn_id={turn_id})")
            return True

        except Exception as e:
            if cursor:
                self.db.rollback()
            logger.error(f"❌ Ошибка сохранения уязвимости: {e}", exc_info=True)
            return False
        finally:
            if cursor:
                cursor.close()

    def _save_to_turn(self, cursor, vulnerability: Vulnerability) -> Optional[int]:
        """Сохранение в таблицу turn"""
        try:
            cve_id = getattr(vulnerability, 'cve_id', None) or vulnerability.title
            
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
            if hasattr(vulnerability, 'is_ai_related'):
                etc_data['is_ai_related'] = vulnerability.is_ai_related
            etc = json.dumps(etc_data, ensure_ascii=False)

            # Status (boolean)
            status = vulnerability.status not in ['completed', 'approved']

            # Проверяем, существует ли уже запись
            cursor.execute("SELECT id FROM turn WHERE cve = %s", (cve_id,))
            existing = cursor.fetchone()

            if existing:
                # Обновляем существующую запись
                cursor.execute("""
                    UPDATE turn SET
                        source = %s, link = %s, name = %s, cvss = %s,
                        price_one = %s, priority = %s, joining_date = %s,
                        start_date = %s, end_date = %s, etc = %s, status = %s
                    WHERE cve = %s
                    RETURNING id
                """, (
                    source, link, name, cvss, price_one, priority,
                    joining_date, start_date, end_date, etc, status, cve_id
                ))
            else:
                # Вставляем новую запись
                cursor.execute("""
                    INSERT INTO turn (
                        source, link, cve, joining_date, name, cvss,
                        price_one, priority, start_date, end_date, etc, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    source, link, cve_id, joining_date, name, cvss,
                    price_one, priority, start_date, end_date, etc, status
                ))

            result = cursor.fetchone()
            return result[0] if result else None

        except Exception as e:
            logger.error(f"❌ Ошибка сохранения в turn для {cve_id}: {e}", exc_info=True)
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
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

    def assign_operator(self, cve_id: str, operator_name: str) -> bool:
        """Назначение оператора на уязвимость (сохранение в actids)"""
        try:
            with self.db.cursor() as cursor:
                uid = uuid.uuid4()
                cursor.execute("""
                    INSERT INTO actids (cve, uid, active, oper)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (cve, oper) DO UPDATE SET active = %s, uid = %s
                """, (cve_id, uid, True, operator_name, True, uid))
                self.db.commit()
                return True
        except Exception as e:
            logger.error(f"Ошибка назначения оператора: {e}")
            self.db.rollback()
            return False

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

