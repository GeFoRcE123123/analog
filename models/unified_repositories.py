import json
import logging
import re
from typing import List, Optional, Tuple

from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class UnifiedVulnerabilityRepository:
    """Read/write-lite репозиторий для объединенной таблицы vulnerabilities_unified."""

    def __init__(self, db_connection, table_name: str = "vulnerabilities_unified"):
        self.db = db_connection
        self.table = table_name

    def _parse_tags_from_etc(self, etc_text: Optional[str]) -> List[str]:
        if not etc_text:
            return []
        try:
            data = json.loads(etc_text)
            raw = data.get("tags", []) if isinstance(data, dict) else []
            if isinstance(raw, list):
                return [str(t).strip() for t in raw if str(t).strip()]
            if isinstance(raw, str):
                return [t.strip() for t in raw.split(",") if t.strip()]
        except Exception:
            return []
        return []

    def _pick_cve(self, primary: Optional[str], legacy: Optional[str], modern: Optional[str]) -> Optional[str]:
        def is_cve(val: Optional[str]) -> bool:
            if not val:
                return False
            return bool(re.match(r"^CVE-\d{4}-\d+", str(val)))

        for val in (primary, modern, legacy):
            if is_cve(val):
                return val
        return None

    def _extract_description(self, value: Optional[object]) -> str:
        if not value:
            return ""
        data = value
        if isinstance(value, str):
            try:
                data = json.loads(value)
            except Exception:
                return value
        if isinstance(data, list) and data:
            for item in data:
                if isinstance(item, dict) and item.get("lang") == "en" and item.get("value"):
                    return str(item.get("value"))
            first = data[0]
            if isinstance(first, dict):
                return str(first.get("value") or "")
            return str(first)
        if isinstance(data, dict):
            return str(data.get("value") or "")
        return str(data)

    def _extract_descriptions_payload(self, value: Optional[object]) -> List[dict]:
        if not value:
            return []
        data = value
        if isinstance(value, str):
            try:
                data = json.loads(value)
            except Exception:
                return []
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            return [data]
        return []

    def _map_row_to_vulnerability(self, row) -> Vulnerability:
        primary_cve = row[13] if len(row) > 13 else None
        legacy_cve = row[33] if len(row) > 33 else None
        modern_cve = row[34] if len(row) > 34 else None
        display_cve = self._pick_cve(primary_cve, legacy_cve, modern_cve)
        legacy_nvd_desc = row[35] if len(row) > 35 else None
        modern_desc = row[36] if len(row) > 36 else None
        cvelist_eng = row[37] if len(row) > 37 else None
        cvelist_rus = row[38] if len(row) > 38 else None
        bdu_start = 39
        raw_desc = row[2] or ""

        descriptions_payload = (
            self._extract_descriptions_payload(modern_desc)
            or self._extract_descriptions_payload(row[18] if len(row) > 18 else None)
            or self._extract_descriptions_payload(legacy_nvd_desc)
        )

        best_desc = (
            self._extract_description(modern_desc)
            or self._extract_description(row[18] if len(row) > 18 else None)
            or self._extract_description(legacy_nvd_desc)
            or (cvelist_eng or cvelist_rus or "")
            or raw_desc
        )

        vuln = Vulnerability(
            id=row[0],
            title=row[1] or (row[13] or "Unknown"),
            description=best_desc or "",
            severity=row[3] or "medium",
            status=row[4] or "new",
            assigned_operator=row[5],
            created_date=row[6],
            completed_date=row[7],
            approved=bool(row[8]) if row[8] is not None else False,
            modifications=row[9] or 0,
            cvss_score=float(row[10] or 0.0),
            risk_level=row[11] or "medium",
            category=row[12] or "web",
            cve_id=display_cve,
            source_identifier=row[14],
            published=row[15],
            last_modified=row[16],
            vuln_status=row[17],
            descriptions=descriptions_payload,
            metrics=row[19] or {},
            weaknesses=row[20] or [],
            configurations=row[21] or [],
            references=row[22] or [],
            vendor_comments=row[23] or [],
            is_ai_related=bool(row[24]) if row[24] is not None else False,
            ai_confidence=float(row[25] or 0.0),
            has_kev=bool(row[26]) if row[26] is not None else False,
            has_cert_alerts=bool(row[27]) if row[27] is not None else False,
            ai_keywords_found=row[28] or [],
            ai_categories=row[29] or [],
            ai_reasoning=row[30],
        )
        setattr(vuln, "raw_cve_id", primary_cve or modern_cve or legacy_cve)
        tags = self._parse_tags_from_etc(row[31])
        source_value = row[32] if len(row) > 32 else None
        setattr(vuln, "source", source_value or vuln.source_identifier or "")
        setattr(vuln, "tags", tags)

        if len(row) > bdu_start:
            (
                bdu_id,
                bdu_name,
                vendor,
                product_name,
                affected_versions,
                platform,
                software_types,
                registry_number,
                vulnerable_software,
                environment,
                cwes,
                vul_class,
                sl_oper_procs,
                identify_date,
                publication_date,
                last_upd_date,
                cvss2_vector,
                cvss2_score,
                cvss3_vector,
                cvss3_score,
                bdu_severity,
                vul_status,
                exploit_status,
                fix_status,
                solution,
                sources,
                other_identifiers,
                vul_incident,
                vul_state,
                vul_elimination,
            ) = row[bdu_start : bdu_start + 30]

            setattr(vuln, "bdu_id", bdu_id)
            setattr(vuln, "bdu_name", bdu_name)
            setattr(vuln, "vendor", vendor)
            setattr(vuln, "product_name", product_name)
            setattr(vuln, "affected_versions", affected_versions)
            setattr(vuln, "platform", platform)
            setattr(vuln, "registry_number", registry_number)
            setattr(vuln, "vul_class", vul_class)
            setattr(vuln, "sl_oper_procs", sl_oper_procs)
            setattr(vuln, "identify_date", identify_date)
            setattr(vuln, "publication_date", publication_date)
            setattr(vuln, "last_upd_date", last_upd_date)
            setattr(vuln, "cvss2_vector", cvss2_vector)
            setattr(vuln, "cvss2_score", cvss2_score)
            setattr(vuln, "cvss3_vector", cvss3_vector)
            setattr(vuln, "cvss3_score", cvss3_score)
            setattr(vuln, "bdu_severity", bdu_severity)
            setattr(vuln, "vul_status", vul_status)
            setattr(vuln, "exploit_status", exploit_status)
            setattr(vuln, "fix_status", fix_status)
            setattr(vuln, "solution", solution)
            setattr(vuln, "sources", sources)
            setattr(vuln, "vul_incident", vul_incident)
            setattr(vuln, "vul_state", vul_state)
            setattr(vuln, "vul_elimination", vul_elimination)

            if software_types is not None:
                try:
                    if isinstance(software_types, str):
                        software_types = json.loads(software_types)
                except Exception:
                    pass
                setattr(vuln, "software_types", software_types)
            if vulnerable_software is not None:
                try:
                    if isinstance(vulnerable_software, str):
                        vulnerable_software = json.loads(vulnerable_software)
                except Exception:
                    pass
                setattr(vuln, "vulnerable_software", vulnerable_software)
            if environment is not None:
                try:
                    if isinstance(environment, str):
                        environment = json.loads(environment)
                except Exception:
                    pass
                setattr(vuln, "environment", environment)
            if cwes is not None:
                try:
                    if isinstance(cwes, str):
                        cwes = json.loads(cwes)
                except Exception:
                    pass
                setattr(vuln, "cwes", cwes)
            if other_identifiers is not None:
                try:
                    if isinstance(other_identifiers, str):
                        other_identifiers = json.loads(other_identifiers)
                except Exception:
                    pass
                setattr(vuln, "other_identifiers", other_identifiers)

        # Map CVSS/CWE/vendor details from metrics/weaknesses/vendor_comments if present
        metrics = row[19] or {}
        weaknesses = row[20] or []
        vendor_blob = row[23] or {}

        try:
            if isinstance(metrics, str):
                metrics = json.loads(metrics)
        except Exception:
            metrics = {}
        try:
            if isinstance(weaknesses, str):
                weaknesses = json.loads(weaknesses)
        except Exception:
            weaknesses = []
        try:
            if isinstance(vendor_blob, str):
                vendor_blob = json.loads(vendor_blob)
        except Exception:
            vendor_blob = {}

        cvss = None
        vector = None
        if isinstance(metrics, dict):
            if "cvssV3_1" in metrics and isinstance(metrics.get("cvssV3_1"), dict):
                cvss = metrics["cvssV3_1"].get("baseScore")
                vector = metrics["cvssV3_1"].get("vectorString")
            elif "cvssV3_0" in metrics and isinstance(metrics.get("cvssV3_0"), dict):
                cvss = metrics["cvssV3_0"].get("baseScore")
                vector = metrics["cvssV3_0"].get("vectorString")
        elif isinstance(metrics, list):
            for item in metrics:
                if not isinstance(item, dict):
                    continue
                if "cvssV3_1" in item and isinstance(item.get("cvssV3_1"), dict):
                    cvss = item["cvssV3_1"].get("baseScore")
                    vector = item["cvssV3_1"].get("vectorString")
                    break
                if "cvssV3_0" in item and isinstance(item.get("cvssV3_0"), dict):
                    cvss = item["cvssV3_0"].get("baseScore")
                    vector = item["cvssV3_0"].get("vectorString")
                    break
        if cvss is not None:
            try:
                vuln.cvss_score = float(cvss)
            except Exception:
                pass
        if vector:
            setattr(vuln, "cvss_v3_vector", vector)

        cwe_ids = []
        if isinstance(weaknesses, list):
            for item in weaknesses:
                if isinstance(item, dict):
                    cwe_id = item.get("cwe_id") or item.get("cweId")
                    if cwe_id:
                        cwe_ids.append(cwe_id)
        if cwe_ids:
            setattr(vuln, "cwe_ids", cwe_ids)

        if isinstance(vendor_blob, dict):
            products = vendor_blob.get("products") or []
            if products:
                first = products[0]
                if isinstance(first, dict):
                    setattr(vuln, "vendor", first.get("vendor"))
                    setattr(vuln, "product_name", first.get("product"))
                    versions = first.get("versions") or []
                    if versions:
                        setattr(vuln, "affected_versions", json.dumps(versions, ensure_ascii=False))
        return vuln

    def get_paginated(
        self,
        page: int = 1,
        per_page: int = 50,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        source: Optional[str] = None,
        ai_only: Optional[bool] = None,
        tags: Optional[List[str]] = None,
    ) -> Tuple[List[Vulnerability], int]:
        try:
            offset = (page - 1) * per_page
            conditions = []
            params = []

            # no global filters by default; show all unified records

            if status:
                conditions.append("status = %s")
                params.append(status)

            if severity:
                conditions.append("severity = %s")
                params.append(severity)

            if search:
                conditions.append("(title ILIKE %s OR description ILIKE %s OR cve_id ILIKE %s)")
                pattern = f"%{search}%"
                params.extend([pattern, pattern, pattern])

            if source:
                if source.lower() == "bdu":
                    conditions.append("(source_identifier ILIKE %s OR legacy_source ILIKE %s)")
                    params.extend(["%bdu%", "%fstec%"])
                else:
                    conditions.append("(source_identifier ILIKE %s OR legacy_source ILIKE %s)")
                    params.extend([f"%{source}%", f"%{source}%"])

            if ai_only:
                conditions.append("is_ai_related = TRUE")

            if tags:
                # Tags are stored in legacy_etc as JSON text
                for t in tags:
                    if not t:
                        continue
                    conditions.append("legacy_etc ILIKE %s")
                    params.append(f'%"{str(t).strip().lower()}"%')

            where_clause = " AND ".join(conditions) if conditions else "TRUE"

            data_query = f"""
                SELECT
                    id, title, description, severity, status, assigned_operator,
                    created_date, completed_date, approved, modifications, cvss_score,
                    risk_level, category, cve_id, source_identifier,
                    published, last_modified, vuln_status, descriptions, metrics,
                    weaknesses, configurations, "references", vendor_comments,
                    is_ai_related, ai_confidence, has_kev, has_cert_alerts,
                    ai_keywords_found, ai_categories, ai_reasoning,
                    legacy_etc, legacy_source, legacy_cve, modern_cve_id,
                    legacy_nvd_descriptions, modern_descriptions,
                    legacy_cvelist_ff_eng, legacy_cvelist_ff_rus
                FROM {self.table}
                WHERE {where_clause}
                ORDER BY
                    CASE
                        WHEN (cve_id ILIKE 'CVE-%%' OR legacy_cve ILIKE 'CVE-%%' OR modern_cve_id ILIKE 'CVE-%%')
                        THEN 0 ELSE 1
                    END,
                    created_date DESC NULLS LAST,
                    id DESC
                LIMIT %s OFFSET %s
            """
            query_params = list(params) + [per_page, offset]

            with self.db.cursor() as cursor:
                cursor.execute(data_query, query_params)
                rows = cursor.fetchall()
                vulnerabilities = [self._map_row_to_vulnerability(row) for row in rows]

                count_query = f"SELECT COUNT(*) FROM {self.table} WHERE {where_clause}"
                cursor.execute(count_query, params)
                total_count = cursor.fetchone()[0]

            return vulnerabilities, total_count
        except Exception as e:
            logger.error(f"Error getting unified paginated vulnerabilities: {e}", exc_info=True)
            return [], 0

    def get_by_id(self, vuln_id: int) -> Optional[Vulnerability]:
        try:
            query = f"""
                SELECT
                    u.id, u.title, u.description, u.severity, u.status, u.assigned_operator,
                    u.created_date, u.completed_date, u.approved, u.modifications, u.cvss_score,
                    u.risk_level, u.category, u.cve_id, u.source_identifier,
                    u.published, u.last_modified, u.vuln_status, u.descriptions, u.metrics,
                    u.weaknesses, u.configurations, u."references", u.vendor_comments,
                    u.is_ai_related, u.ai_confidence, u.has_kev, u.has_cert_alerts,
                    u.ai_keywords_found, u.ai_categories, u.ai_reasoning,
                    u.legacy_etc, u.legacy_source, u.legacy_cve, u.modern_cve_id,
                    u.legacy_nvd_descriptions, u.modern_descriptions,
                    u.legacy_cvelist_ff_eng, u.legacy_cvelist_ff_rus,
                    v.bdu_id, v.bdu_name, v.vendor, v.product_name, v.affected_versions,
                    v.platform, v.software_types, v.registry_number, v.vulnerable_software,
                    v.environment, v.cwes, v.vul_class, v.sl_oper_procs, v.identify_date,
                    v.publication_date, v.last_upd_date, v.cvss2_vector, v.cvss2_score,
                    v.cvss3_vector, v.cvss3_score, v.bdu_severity, v.vul_status,
                    v.exploit_status, v.fix_status, v.solution, v.sources, v.other_identifiers,
                    v.vul_incident, v.vul_state, v.vul_elimination
                FROM {self.table} u
                LEFT JOIN vulnerabilities v ON v.id = u.modern_id
                WHERE u.id = %s
            """
            with self.db.cursor() as cursor:
                cursor.execute(query, (vuln_id,))
                row = cursor.fetchone()
            return self._map_row_to_vulnerability(row) if row else None
        except Exception as e:
            logger.error(f"Error getting unified vulnerability by id {vuln_id}: {e}", exc_info=True)
            return None

    def get_by_cve_id(self, cve_id: str) -> Optional[Vulnerability]:
        try:
            query = f"""
                SELECT
                    id, title, description, severity, status, assigned_operator,
                    created_date, completed_date, approved, modifications, cvss_score,
                    risk_level, category, cve_id, source_identifier,
                    published, last_modified, vuln_status, descriptions, metrics,
                    weaknesses, configurations, "references", vendor_comments,
                    is_ai_related, ai_confidence, has_kev, has_cert_alerts,
                    ai_keywords_found, ai_categories, ai_reasoning,
                    legacy_etc, legacy_source, legacy_cve, modern_cve_id,
                    legacy_nvd_descriptions, modern_descriptions,
                    legacy_cvelist_ff_eng, legacy_cvelist_ff_rus
                FROM {self.table}
                WHERE cve_id = %s OR legacy_cve = %s
                LIMIT 1
            """
            with self.db.cursor() as cursor:
                cursor.execute(query, (cve_id, cve_id))
                row = cursor.fetchone()
            return self._map_row_to_vulnerability(row) if row else None
        except Exception as e:
            logger.error(f"Error getting unified vulnerability by cve {cve_id}: {e}", exc_info=True)
            return None

    def get_vulnerabilities_by_operator(self, operator_id: int) -> List[Vulnerability]:
        try:
            query = f"""
                SELECT
                    id, title, description, severity, status, assigned_operator,
                    created_date, completed_date, approved, modifications, cvss_score,
                    risk_level, category, cve_id, source_identifier,
                    published, last_modified, vuln_status, descriptions, metrics,
                    weaknesses, configurations, "references", vendor_comments,
                    is_ai_related, ai_confidence, has_kev, has_cert_alerts,
                    ai_keywords_found, ai_categories, ai_reasoning,
                    legacy_etc, legacy_source, legacy_cve, modern_cve_id,
                    legacy_nvd_descriptions, modern_descriptions,
                    legacy_cvelist_ff_eng, legacy_cvelist_ff_rus
                FROM {self.table}
                WHERE assigned_operator = %s
                ORDER BY created_date DESC NULLS LAST, id DESC
            """
            with self.db.cursor() as cursor:
                cursor.execute(query, (operator_id,))
                rows = cursor.fetchall()
            return [self._map_row_to_vulnerability(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting unified vulnerabilities by operator {operator_id}: {e}", exc_info=True)
            return []

    # === Tags (stored in legacy_etc on turn) ===
    def _load_legacy_target(self, vuln_id: int):
        query = f"SELECT legacy_id, legacy_etc FROM {self.table} WHERE id = %s"
        with self.db.cursor() as cursor:
            cursor.execute(query, (vuln_id,))
            return cursor.fetchone()

    def get_tags(self, vuln_id: int) -> List[str]:
        try:
            row = self._load_legacy_target(vuln_id)
            if not row:
                return []
            return self._parse_tags_from_etc(row[1])
        except Exception as e:
            logger.error(f"Error getting unified tags for {vuln_id}: {e}", exc_info=True)
            return []

    def set_tags(self, vuln_id: int, tags) -> bool:
        try:
            row = self._load_legacy_target(vuln_id)
            if not row:
                return False
            legacy_id, legacy_etc = row
            data = {}
            try:
                data = json.loads(legacy_etc) if legacy_etc else {}
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}
            data["tags"] = tags if isinstance(tags, list) else [str(tags)]
            new_etc = json.dumps(data, ensure_ascii=False)
            with self.db.cursor() as cursor:
                if legacy_id:
                    cursor.execute("UPDATE turn SET etc = %s WHERE id = %s", (new_etc, legacy_id))
                cursor.execute(
                    f"UPDATE {self.table} SET legacy_etc = %s WHERE id = %s",
                    (new_etc, vuln_id),
                )
            self.db.commit()
            return True
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error setting unified tags for {vuln_id}: {e}", exc_info=True)
            return False

    def add_tag(self, vuln_id: int, tag: str) -> List[str]:
        current = self.get_tags(vuln_id)
        if tag not in current:
            current.append(tag)
        self.set_tags(vuln_id, current)
        return current

    def remove_tag(self, vuln_id: int, tag: str) -> List[str]:
        current = [t for t in self.get_tags(vuln_id) if t != tag]
        self.set_tags(vuln_id, current)
        return current
