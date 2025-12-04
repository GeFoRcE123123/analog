import logging
import json
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
from models.repositories import VulnerabilityRepository, OperatorRepository
from models.entities import Vulnerability, Operator, NVDVulnerability
logger = logging.getLogger(__name__)


class PostgresVulnerabilityRepository(VulnerabilityRepository):
    """Реализация репозитория уязвимостей для PostgreSQL с поддержкой NVD"""

    def __init__(self, db_connection):
        self.db = db_connection

    def save_nvd_vulnerability(self, nvd_vuln: Dict) -> bool:
        """Сохранение уязвимости из NVD в базу данных"""
        try:
            # Проверяем, существует ли уже уязвимость
            existing = self.get_by_cve_id(nvd_vuln['cve_id'])
            if existing:
                return self._update_nvd_vulnerability(nvd_vuln)
            else:
                return self._insert_nvd_vulnerability(nvd_vuln)

        except Exception as e:
            print(f"Ошибка сохранения NVD уязвимости {nvd_vuln['cve_id']}: {e}")
            return False

    def bulk_save_nvd_vulnerabilities(self, vulnerabilities: List[Dict]) -> int:
        """Массовое сохранение уязвимостей из NVD"""
        saved_count = 0
        for vuln in vulnerabilities:
            if self.save_nvd_vulnerability(vuln):
                saved_count += 1

                # Если уязвимость связана с AI, сохраняем в отдельную таблицу
                if vuln.get('is_ai_related'):
                    self._save_to_ai_vulnerabilities(vuln)

        return saved_count

    def get_by_cve_id(self, cve_id: str) -> Optional[Vulnerability]:
        """Получение уязвимости по CVE ID"""
        try:
            with self.db.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM vulnerabilities WHERE cve_id = %s
                """, (cve_id,))

                result = cursor.fetchone()
                if result:
                    return self._map_to_vulnerability_entity(result)

                return None

        except Exception as e:
            print(f"Ошибка получения уязвимости {cve_id}: {e}")
            return None

    def _insert_nvd_vulnerability(self, nvd_vuln: Dict) -> bool:
        """Вставка новой NVD уязвимости"""
        try:
            with self.db.cursor() as cursor:
                # Конвертируем даты
                published = datetime.fromisoformat(nvd_vuln['published'].replace('Z', '+00:00'))
                last_modified = datetime.fromisoformat(nvd_vuln['last_modified'].replace('Z', '+00:00'))

                # Вставляем в основную таблицу
                cursor.execute("""
                    INSERT INTO vulnerabilities (
                        cve_id, source_identifier, published, last_modified, 
                        vuln_status, descriptions, metrics, weaknesses,
                        configurations, "references", vendor_comments,
                        is_ai_related, ai_confidence, has_kev, has_cert_alerts,
                        created_date, title, description, severity, cvss_score
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    nvd_vuln['cve_id'],
                    nvd_vuln['source_identifier'],
                    published,
                    last_modified,
                    nvd_vuln['vuln_status'],
                    json.dumps(nvd_vuln['descriptions']),
                    json.dumps(nvd_vuln['metrics']),
                    json.dumps(nvd_vuln['weaknesses']),
                    json.dumps(nvd_vuln['configurations']),
                    json.dumps(nvd_vuln['references']),
                    json.dumps(nvd_vuln['vendor_comments']),
                    nvd_vuln['is_ai_related'],
                    nvd_vuln['ai_confidence'],
                    nvd_vuln.get('has_kev', False),
                    nvd_vuln.get('has_cert_alerts', False),
                    datetime.now(),  # created_date
                    nvd_vuln['cve_id'],  # title
                    self._get_primary_description(nvd_vuln['descriptions']),  # description
                    self._calculate_severity(nvd_vuln['metrics']),  # severity
                    self._get_cvss_score(nvd_vuln['metrics'])  # cvss_score
                ))

                self.db.commit()
                print(f"✅ Уязвимость {nvd_vuln['cve_id']} сохранена в БД")
                return True

        except Exception as e:
            self.db.rollback()
            print(f"❌ Ошибка вставки уязвимости {nvd_vuln['cve_id']}: {e}")
            return False

    def _update_nvd_vulnerability(self, nvd_vuln: Dict) -> bool:
        """Обновление существующей NVD уязвимости"""
        try:
            with self.db.cursor() as cursor:
                last_modified = datetime.fromisoformat(nvd_vuln['last_modified'].replace('Z', '+00:00'))

                cursor.execute("""
                    UPDATE vulnerabilities SET
                        source_identifier = %s,
                        last_modified = %s,
                        vuln_status = %s,
                        descriptions = %s,
                        metrics = %s,
                        weaknesses = %s,
                        configurations = %s,
                        "references" = %s,
                        vendor_comments = %s,
                        is_ai_related = %s,
                        ai_confidence = %s,
                        has_kev = %s,
                        has_cert_alerts = %s,
                        description = %s,
                        severity = %s,
                        cvss_score = %s
                    WHERE cve_id = %s
                """, (
                    nvd_vuln['source_identifier'],
                    last_modified,
                    nvd_vuln['vuln_status'],
                    json.dumps(nvd_vuln['descriptions']),
                    json.dumps(nvd_vuln['metrics']),
                    json.dumps(nvd_vuln['weaknesses']),
                    json.dumps(nvd_vuln['configurations']),
                    json.dumps(nvd_vuln['references']),
                    json.dumps(nvd_vuln['vendor_comments']),
                    nvd_vuln['is_ai_related'],
                    nvd_vuln['ai_confidence'],
                    nvd_vuln.get('has_kev', False),
                    nvd_vuln.get('has_cert_alerts', False),
                    self._get_primary_description(nvd_vuln['descriptions']),
                    self._calculate_severity(nvd_vuln['metrics']),
                    self._get_cvss_score(nvd_vuln['metrics']),
                    nvd_vuln['cve_id']
                ))

                self.db.commit()
                print(f"✅ Уязвимость {nvd_vuln['cve_id']} обновлена в БД")
                return True

        except Exception as e:
            self.db.rollback()
            print(f"❌ Ошибка обновления уязвимости {nvd_vuln['cve_id']}: {e}")
            return False

    def _save_to_ai_vulnerabilities(self, nvd_vuln: Dict):
        """Сохранение в таблицу AI уязвимостей"""
        try:
            with self.db.cursor() as cursor:
                # Проверяем, существует ли уже в AI таблице
                cursor.execute(
                    "SELECT id FROM ai_vulnerabilities WHERE cve_id = %s",
                    (nvd_vuln['cve_id'],)
                )
                exists = cursor.fetchone()

                if not exists:
                    cursor.execute("""
                        INSERT INTO ai_vulnerabilities (
                            cve_id, ai_confidence, ai_keywords_found,
                            created_at
                        ) VALUES (%s, %s, %s, NOW())
                    """, (
                        nvd_vuln['cve_id'],
                        nvd_vuln['ai_confidence'],
                        json.dumps(self._extract_ai_keywords(nvd_vuln))
                    ))

                    self.db.commit()
                    print(f"🤖 AI уязвимость {nvd_vuln['cve_id']} сохранена в отдельную таблицу")

        except Exception as e:
            self.db.rollback()
            print(f"❌ Ошибка сохранения в AI таблицу {nvd_vuln['cve_id']}: {e}")

    def _get_primary_description(self, descriptions: List[Dict]) -> str:
        """Получение основного описания на английском"""
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')[:500]  # Ограничиваем длину
        return descriptions[0].get('value', '')[:500] if descriptions else ''

    def _calculate_severity(self, metrics: Dict) -> str:
        """Расчет severity на основе CVSS метрик"""
        try:
            # Приоритет: v4 -> v3 -> v2
            if metrics.get('cvss_v4'):
                severity = metrics['cvss_v4'].get('baseSeverity', 'medium')
            elif metrics.get('cvss_v3'):
                severity = metrics['cvss_v3'].get('baseSeverity', 'medium')
            elif metrics.get('cvss_v2'):
                severity = metrics['cvss_v2'].get('baseSeverity', 'medium')
            else:
                severity = 'medium'

            # Конвертируем в наш формат
            severity_map = {
                'critical': 'critical', 'high': 'high', 'medium': 'medium',
                'low': 'low', 'none': 'low'
            }
            return severity_map.get(severity.lower(), 'medium')

        except Exception:
            return 'medium'

    def _get_cvss_score(self, metrics: Dict) -> float:
        """Получение CVSS score"""
        try:
            # Приоритет: v4 -> v3 -> v2
            if metrics.get('cvss_v4'):
                return float(metrics['cvss_v4'].get('baseScore', 0.0))
            elif metrics.get('cvss_v3'):
                return float(metrics['cvss_v3'].get('baseScore', 0.0))
            elif metrics.get('cvss_v2'):
                return float(metrics['cvss_v2'].get('baseScore', 0.0))
            else:
                return 0.0
        except Exception:
            return 0.0

    def _extract_ai_keywords(self, nvd_vuln: Dict) -> List[str]:
        """Извлечение AI ключевых слов из уязвимости"""
        found_keywords = []
        ai_keywords = [
            'ai', 'artificial intelligence', 'machine learning', 'neural network',
            'deep learning', 'tensorflow', 'pytorch', 'keras', 'scikit-learn'
        ]

        # Проверяем описания
        descriptions = nvd_vuln.get('descriptions', [])
        combined_text = ' '.join([desc.get('value', '').lower() for desc in descriptions])

        for keyword in ai_keywords:
            if keyword in combined_text:
                found_keywords.append(keyword)

        return found_keywords

    def get_ai_vulnerabilities(self) -> List[Vulnerability]:
        """Получение всех AI уязвимостей"""
        try:
            with self.db.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM vulnerabilities 
                    WHERE is_ai_related = TRUE 
                    ORDER BY published DESC
                """)

                results = cursor.fetchall()
                return [self._map_to_vulnerability_entity(row) for row in results]

        except Exception as e:
            print(f"Ошибка получения AI уязвимостей: {e}")
            return []

    def _map_to_vulnerability_entity(self, db_row) -> Vulnerability:
        """Маппинг строки БД в сущность Vulnerability с учетом новых NVD полей"""
        try:
            # db_row - это кортеж с данными из БД в порядке SELECT запроса
            # 0: id, 1: title, 2: description, 3: severity, 4: status,
            # 5: assigned_operator, 6: created_date, 7: completed_date,
            # 8: approved, 9: modifications, 10: cvss_score, 11: risk_level, 12: category
            # + новые NVD поля (13-27)

            # Базовые поля (оригинальные)
            vulnerability = Vulnerability(
                id=db_row[0],
                title=db_row[1],
                description=db_row[2],
                severity=db_row[3],
                status=db_row[4],
                assigned_operator=db_row[5],
                created_date=db_row[6],
                completed_date=db_row[7],
                approved=db_row[8],
                modifications=db_row[9],
                cvss_score=float(db_row[10]) if db_row[10] else 0.0,
                risk_level=db_row[11],
                category=db_row[12]
            )

            # Добавляем NVD данные как атрибуты
            # Проверяем, есть ли NVD поля в результате (длина db_row > 13)
            if len(db_row) > 13:
                vulnerability.cve_id = db_row[13] if db_row[13] else None
                vulnerability.source_identifier = db_row[14] if db_row[14] else None
                vulnerability.published = db_row[15] if db_row[15] else None
                vulnerability.last_modified = db_row[16] if db_row[16] else None
                vulnerability.vuln_status = db_row[17] if db_row[17] else None

                # JSON поля - парсим из строки
                if db_row[18]:  # descriptions
                    try:
                        vulnerability.descriptions = json.loads(db_row[18])
                    except:
                        vulnerability.descriptions = []

                if db_row[19]:  # metrics
                    try:
                        vulnerability.metrics = json.loads(db_row[19])
                    except:
                        vulnerability.metrics = {}

                if db_row[20]:  # weaknesses
                    try:
                        vulnerability.weaknesses = json.loads(db_row[20])
                    except:
                        vulnerability.weaknesses = []

                if db_row[21]:  # configurations
                    try:
                        vulnerability.configurations = json.loads(db_row[21])
                    except:
                        vulnerability.configurations = []

                if db_row[22]:  # references
                    try:
                        vulnerability.references = json.loads(db_row[22])
                    except:
                        vulnerability.references = []

                if db_row[23]:  # vendor_comments
                    try:
                        vulnerability.vendor_comments = json.loads(db_row[23])
                    except:
                        vulnerability.vendor_comments = []

                # Флаги
                vulnerability.is_ai_related = bool(db_row[24]) if db_row[24] is not None else False
                vulnerability.ai_confidence = float(db_row[25]) if db_row[25] else 0.0
                vulnerability.has_kev = bool(db_row[26]) if db_row[26] is not None else False
                vulnerability.has_cert_alerts = bool(db_row[27]) if db_row[27] is not None else False

            return vulnerability

        except Exception as e:
            logger.error(f"Ошибка маппинга уязвимости из БД: {e}")
            # Возвращаем базовую уязвимость в случае ошибки
            return Vulnerability(
                id=db_row[0] if len(db_row) > 0 else 0,
                title=db_row[1] if len(db_row) > 1 else "Unknown",
                description=db_row[2] if len(db_row) > 2 else "",
                severity=db_row[3] if len(db_row) > 3 else "medium"
            )

class PostgresVulnerabilityRepository:
    """PostgreSQL репозиторий для уязвимостей"""

    def __init__(self, connection):
        self.connection = connection

    def get_by_id(self, vuln_id: int) -> Optional[Vulnerability]:
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category
        FROM vulnerabilities 
        WHERE id = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (vuln_id,))
                row = cursor.fetchone()
                return Vulnerability.from_db_row(row) if row else None
        except Exception as e:
            logger.error(f"Error getting vulnerability by ID {vuln_id}: {e}")
            return None

    def get_all(self) -> List[Vulnerability]:
        """Получить все уязвимости (ограничено для предотвращения перегрузки)"""
        query = """
            SELECT id, title, description, severity, status, assigned_operator, 
                   created_date, completed_date, approved, modifications, 
                   cvss_score, risk_level, category
            FROM vulnerabilities 
            ORDER BY created_date DESC
            LIMIT 1000
            """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                return [Vulnerability.from_db_row(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting all vulnerabilities: {e}")
            return []

    def get_all_unlimited(self) -> List[Vulnerability]:
        """Получить все уязвимости без ограничений (для аналитики)"""
        query = """
            SELECT id, title, description, severity, status, assigned_operator, 
                   created_date, completed_date, approved, modifications, 
                   cvss_score, risk_level, category
            FROM vulnerabilities 
            ORDER BY created_date DESC
            """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                return [Vulnerability.from_db_row(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting all vulnerabilities (unlimited): {e}")
            return []

    def get_all_unlimited(self) -> List[Vulnerability]:
        """Получить все уязвимости без ограничений (для аналитики)"""
        query = """
            SELECT id, title, description, severity, status, assigned_operator, 
                   created_date, completed_date, approved, modifications, 
                   cvss_score, risk_level, category
            FROM vulnerabilities 
            ORDER BY created_date DESC
            """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                return [Vulnerability.from_db_row(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting all vulnerabilities (unlimited): {e}")
            return []

    def get_paginated(self, page: int = 1, per_page: int = 50, 
                     status: Optional[str] = None, severity: Optional[str] = None, 
                     search: Optional[str] = None) -> Tuple[List[Vulnerability], int]:
        """Получить уязвимости с пагинацией и фильтрацией"""
        try:
            offset = (page - 1) * per_page
            
            # Базовый запрос
            base_query = """
                SELECT id, title, description, severity, status, assigned_operator, 
                       created_date, completed_date, approved, modifications, 
                       cvss_score, risk_level, category
                FROM vulnerabilities 
            """
            
            # Условия фильтрации
            conditions = []
            params = []
            
            if status and status != 'all':
                conditions.append("status = %s")
                params.append(status)
                
            if severity and severity != 'all':
                conditions.append("severity = %s")
                params.append(severity)
                
            if search:
                conditions.append("(title ILIKE %s OR description ILIKE %s)")
                params.extend([f'%{search}%', f'%{search}%'])
            
            # Добавляем WHERE если есть условия
            if conditions:
                base_query += " WHERE " + " AND ".join(conditions)
            
            # Добавляем ORDER BY и LIMIT/OFFSET
            base_query += " ORDER BY created_date DESC LIMIT %s OFFSET %s"
            params.extend([per_page, offset])
            
            # Запрос для данных
            with self.connection.cursor() as cursor:
                cursor.execute(base_query, params)
                rows = cursor.fetchall()
                vulnerabilities = [Vulnerability.from_db_row(row) for row in rows]
                
                # Запрос для подсчета общего количества
                count_query = "SELECT COUNT(*) FROM vulnerabilities"
                count_params = []
                
                if conditions:
                    count_query += " WHERE " + " AND ".join(conditions)
                    count_params = params[:-2]  # Исключаем LIMIT и OFFSET
                    
                cursor.execute(count_query, count_params)
                total_count = cursor.fetchone()[0]
                
                return vulnerabilities, total_count
                
        except Exception as e:
            logger.error(f"Error getting paginated vulnerabilities: {e}")
            return [], 0

    def get_by_title(self, title: str) -> Optional[Vulnerability]:
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category
        FROM vulnerabilities 
        WHERE title = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (title,))
                row = cursor.fetchone()
                return Vulnerability.from_db_row(row) if row else None
        except Exception as e:
            logger.error(f"Error getting vulnerability by title '{title}': {e}")
            return None

    def get_by_status(self, status: str) -> List[Vulnerability]:
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category
        FROM vulnerabilities 
        WHERE status = %s
        ORDER BY created_date DESC
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (status,))
                rows = cursor.fetchall()
                return [Vulnerability.from_db_row(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting vulnerabilities by status '{status}': {e}")
            return []

    def get_by_severity(self, severity: str) -> List[Vulnerability]:
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category
        FROM vulnerabilities 
        WHERE severity = %s
        ORDER BY cvss_score DESC
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (severity,))
                rows = cursor.fetchall()
                return [Vulnerability.from_db_row(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting vulnerabilities by severity '{severity}': {e}")
            return []

    def get_by_cve_id(self, cve_id: str) -> Optional[Vulnerability]:
        """Получить уязвимость по CVE ID"""
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category,
               cve_id, source_identifier, published, last_modified, vuln_status,
               descriptions, metrics, weaknesses, configurations, "references", 
               vendor_comments, is_ai_related, ai_confidence, has_kev, has_cert_alerts
        FROM vulnerabilities 
        WHERE cve_id = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (cve_id,))
                row = cursor.fetchone()
                if row:
                    return self._map_to_vulnerability_entity(row)
                return None
        except Exception as e:
            logger.error(f"Error getting vulnerability by CVE ID {cve_id}: {e}")
            return None

    def add(self, vulnerability: Vulnerability) -> bool:
        query = """
        INSERT INTO vulnerabilities 
        (title, description, severity, status, assigned_operator, created_date, 
         completed_date, approved, modifications, cvss_score, risk_level, category,
         cve_id, source_identifier, published, last_modified, vuln_status,
         descriptions, metrics, weaknesses, configurations, "references", 
         vendor_comments, is_ai_related, ai_confidence, has_kev, has_cert_alerts)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (
                    vulnerability.title,
                    vulnerability.description,
                    vulnerability.severity,
                    vulnerability.status,
                    vulnerability.assigned_operator,
                    vulnerability.created_date or datetime.now(),
                    vulnerability.completed_date,
                    vulnerability.approved,
                    vulnerability.modifications,
                    vulnerability.cvss_score,
                    vulnerability.risk_level,
                    vulnerability.category,
                    # NVD поля
                    vulnerability.cve_id,
                    vulnerability.source_identifier,
                    vulnerability.published,
                    vulnerability.last_modified,
                    vulnerability.vuln_status,
                    json.dumps(vulnerability.descriptions) if vulnerability.descriptions else None,
                    json.dumps(vulnerability.metrics) if vulnerability.metrics else None,
                    json.dumps(vulnerability.weaknesses) if vulnerability.weaknesses else None,
                    json.dumps(vulnerability.configurations) if vulnerability.configurations else None,
                    json.dumps(vulnerability.references) if vulnerability.references else None,
                    json.dumps(vulnerability.vendor_comments) if vulnerability.vendor_comments else None,
                    vulnerability.is_ai_related,
                    vulnerability.ai_confidence,
                    vulnerability.has_kev,
                    vulnerability.has_cert_alerts
                ))
                new_id = cursor.fetchone()[0]
                vulnerability.id = new_id
                self.connection.commit()
                logger.info(f"Vulnerability added: {vulnerability.title} (ID: {new_id})")
                return True
        except Exception as e:
            logger.error(f"Error adding vulnerability '{vulnerability.title}': {e}")
            self.connection.rollback()
            return False

    def update(self, vulnerability: Vulnerability) -> bool:
        query = """
        UPDATE vulnerabilities 
        SET title = %s, description = %s, severity = %s, status = %s, 
            assigned_operator = %s, created_date = %s, completed_date = %s, 
            approved = %s, modifications = %s, cvss_score = %s, 
            risk_level = %s, category = %s
        WHERE id = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (
                    vulnerability.title,
                    vulnerability.description,
                    vulnerability.severity,
                    vulnerability.status,
                    vulnerability.assigned_operator,
                    vulnerability.created_date,
                    vulnerability.completed_date,
                    vulnerability.approved,
                    vulnerability.modifications,
                    vulnerability.cvss_score,
                    vulnerability.risk_level,
                    vulnerability.category,
                    vulnerability.id
                ))
                self.connection.commit()
                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Vulnerability updated: {vulnerability.title} (ID: {vulnerability.id})")
                return success
        except Exception as e:
            logger.error(f"Error updating vulnerability {vulnerability.id}: {e}")
            self.connection.rollback()
            return False

    def delete(self, vuln_id: int) -> bool:
        query = "DELETE FROM vulnerabilities WHERE id = %s"
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (vuln_id,))
                self.connection.commit()
                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Vulnerability deleted: ID {vuln_id}")
                return success
        except Exception as e:
            logger.error(f"Error deleting vulnerability {vuln_id}: {e}")
            self.connection.rollback()
            return False

    def assign_operator(self, vuln_id: int, operator_id: int) -> bool:
        query = """
        UPDATE vulnerabilities 
        SET assigned_operator = %s, status = 'in_progress'
        WHERE id = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (operator_id, vuln_id))
                self.connection.commit()
                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Operator {operator_id} assigned to vulnerability {vuln_id}")
                return success
        except Exception as e:
            logger.error(f"Error assigning operator {operator_id} to vulnerability {vuln_id}: {e}")
            self.connection.rollback()
            return False

    def unassign_operator(self, vuln_id: int) -> bool:
        query = """
        UPDATE vulnerabilities 
        SET assigned_operator = NULL, status = 'new'
        WHERE id = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (vuln_id,))
                self.connection.commit()
                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Operator unassigned from vulnerability {vuln_id}")
                return success
        except Exception as e:
            logger.error(f"Error unassigning operator from vulnerability {vuln_id}: {e}")
            self.connection.rollback()
            return False


class PostgresOperatorRepository:
    """PostgreSQL репозиторий для операторов"""

    def __init__(self, connection):
        self.connection = connection
        self.vulnerability_repo = PostgresVulnerabilityRepository(connection)

    def get_by_id(self, operator_id: int) -> Optional[Operator]:
        query = """
        SELECT id, name, email, experience_level, current_metric, last_activity
        FROM operators 
        WHERE id = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (operator_id,))
                row = cursor.fetchone()
                if row:
                    operator = Operator.from_db_row(row)
                    # Загружаем назначенные уязвимости
                    operator.assigned_vulnerabilities = self.get_assigned_vulnerabilities(operator_id)
                    return operator
                return None
        except Exception as e:
            logger.error(f"Error getting operator by ID {operator_id}: {e}")
            return None

    def get_all(self) -> List[Operator]:
        query = """
        SELECT id, name, email, experience_level, current_metric, last_activity
        FROM operators 
        ORDER BY name
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                operators = []
                for row in rows:
                    operator = Operator.from_db_row(row)
                    # Загружаем назначенные уязвимости
                    operator.assigned_vulnerabilities = self.get_assigned_vulnerabilities(operator.id)
                    operators.append(operator)
                return operators
        except Exception as e:
            logger.error(f"Error getting all operators: {e}")
            return []

    def get_by_email(self, email: str) -> Optional[Operator]:
        query = """
        SELECT id, name, email, experience_level, current_metric, last_activity
        FROM operators 
        WHERE email = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (email,))
                row = cursor.fetchone()
                if row:
                    operator = Operator.from_db_row(row)
                    operator.assigned_vulnerabilities = self.get_assigned_vulnerabilities(operator.id)
                    return operator
                return None
        except Exception as e:
            logger.error(f"Error getting operator by email '{email}': {e}")
            return None

    def add(self, operator: Operator) -> bool:
        query = """
        INSERT INTO operators 
        (name, email, experience_level, current_metric, last_activity)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (
                    operator.name,
                    operator.email,
                    operator.experience_level,
                    operator.current_metric,
                    operator.last_activity or datetime.now()
                ))
                new_id = cursor.fetchone()[0]
                operator.id = new_id
                self.connection.commit()
                logger.info(f"Operator added: {operator.name} (ID: {new_id})")
                return True
        except Exception as e:
            logger.error(f"Error adding operator '{operator.name}': {e}")
            self.connection.rollback()
            return False

    def update(self, operator: Operator) -> bool:
        query = """
        UPDATE operators 
        SET name = %s, email = %s, experience_level = %s, 
            current_metric = %s, last_activity = %s
        WHERE id = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (
                    operator.name,
                    operator.email,
                    operator.experience_level,
                    operator.current_metric,
                    operator.last_activity or datetime.now(),
                    operator.id
                ))
                self.connection.commit()
                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Operator updated: {operator.name} (ID: {operator.id})")
                return success
        except Exception as e:
            logger.error(f"Error updating operator {operator.id}: {e}")
            self.connection.rollback()
            return False

    def delete(self, operator_id: int) -> bool:
        # Сначала снимаем назначения уязвимостей
        update_query = """
        UPDATE vulnerabilities 
        SET assigned_operator = NULL 
        WHERE assigned_operator = %s
        """
        delete_query = "DELETE FROM operators WHERE id = %s"

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(update_query, (operator_id,))
                cursor.execute(delete_query, (operator_id,))
                self.connection.commit()
                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Operator deleted: ID {operator_id}")
                return success
        except Exception as e:
            logger.error(f"Error deleting operator {operator_id}: {e}")
            self.connection.rollback()
            return False

    def update_metric(self, operator_id: int, new_metric: float) -> bool:
        query = """
        UPDATE operators 
        SET current_metric = %s, last_activity = %s
        WHERE id = %s
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (new_metric, datetime.now(), operator_id))
                self.connection.commit()
                success = cursor.rowcount > 0
                if success:
                    logger.info(f"Operator metric updated: ID {operator_id} -> {new_metric}")
                return success
        except Exception as e:
            logger.error(f"Error updating operator metric {operator_id}: {e}")
            self.connection.rollback()
            return False

    def get_assigned_vulnerabilities(self, operator_id: int) -> List[Vulnerability]:
        """Получить уязвимости, назначенные оператору"""
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category
        FROM vulnerabilities 
        WHERE assigned_operator = %s
        ORDER BY created_date DESC
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (operator_id,))
                rows = cursor.fetchall()
                return [Vulnerability.from_db_row(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting assigned vulnerabilities for operator {operator_id}: {e}")
            return []