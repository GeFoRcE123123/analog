#!/usr/bin/env python3
"""
Merge legacy (turn/cvelist) and modern (vulnerabilities) data into a unified table.

Creates a superset table `vulnerabilities_unified` and inserts a merged view that
preserves all information from both schemas.
"""
from __future__ import annotations

import sys
from typing import Dict, List, Set

import psycopg
from models.database import DatabaseManager


UNIFIED_TABLE = "vulnerabilities_unified"


def _get_columns(conn: psycopg.Connection, table_name: str) -> Set[str]:
    query = """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
    """
    with conn.cursor() as cursor:
        cursor.execute(query, (table_name,))
        return {row[0] for row in cursor.fetchall()}


def _table_exists(conn: psycopg.Connection, table_name: str) -> bool:
    query = "SELECT to_regclass(%s) IS NOT NULL"
    with conn.cursor() as cursor:
        cursor.execute(query, (f"public.{table_name}",))
        return bool(cursor.fetchone()[0])


def _col(alias: str, name: str, columns: Set[str]) -> str:
    if name in columns:
        return f'{alias}."{name}"'
    return "NULL"


def _build_create_table_sql() -> str:
    return f"""
    CREATE TABLE IF NOT EXISTS {UNIFIED_TABLE} (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(50),
        source_identifier VARCHAR(200),
        title VARCHAR(500),
        description TEXT,
        severity VARCHAR(50),
        status VARCHAR(50),
        cvss_score DECIMAL(3,1),
        risk_level VARCHAR(50),
        category VARCHAR(100),
        created_date TIMESTAMP,
        completed_date TIMESTAMP,
        approved BOOLEAN,
        modifications INTEGER,
        assigned_operator INTEGER,
        published TIMESTAMP,
        last_modified TIMESTAMP,
        vuln_status VARCHAR(50),
        descriptions JSONB,
        metrics JSONB,
        weaknesses JSONB,
        configurations JSONB,
        "references" JSONB,
        vendor_comments JSONB,
        is_ai_related BOOLEAN,
        ai_confidence DECIMAL(3,2),
        ai_keywords_found TEXT[],
        ai_categories TEXT[],
        ai_reasoning TEXT,
        has_kev BOOLEAN,
        has_cert_alerts BOOLEAN,
        bdu_id VARCHAR(50),
        bdu_name TEXT,
        vendor VARCHAR(300),
        product_name VARCHAR(300),
        affected_versions TEXT,
        platform VARCHAR(100),
        software_types JSONB,
        registry_number VARCHAR(100),
        vulnerable_software JSONB,
        environment JSONB,
        cwes JSONB,
        vul_class VARCHAR(200),
        sl_oper_procs JSONB,
        identify_date DATE,
        publication_date DATE,
        last_upd_date DATE,
        cvss2_vector VARCHAR(100),
        cvss2_score DECIMAL(3,1),
        cvss3_vector VARCHAR(100),
        cvss3_score DECIMAL(3,1),
        bdu_severity TEXT,
        vul_status VARCHAR(200),
        exploit_status VARCHAR(200),
        fix_status VARCHAR(200),
        solution TEXT,
        sources TEXT,
        other_identifiers JSONB,
        vul_incident VARCHAR(200),
        vul_state VARCHAR(100),
        vul_elimination VARCHAR(200),

        -- Legacy raw fields
        legacy_id INTEGER,
        legacy_source TEXT,
        legacy_link TEXT,
        legacy_cve TEXT,
        legacy_joining_date TIMESTAMP,
        legacy_name TEXT,
        legacy_cvss REAL,
        legacy_price_one REAL,
        legacy_priority REAL,
        legacy_start_date TIMESTAMP,
        legacy_end_date TIMESTAMP,
        legacy_etc TEXT,
        legacy_status BOOLEAN,
        legacy_cvss_v2_vector TEXT,
        legacy_cvss_v3_vector TEXT,
        legacy_cvss_v4_vector TEXT,
        legacy_cvss_version VARCHAR(10),
        legacy_cvss_v2_metrics JSONB,
        legacy_cvss_v3_metrics JSONB,
        legacy_cvss_v4_metrics JSONB,
        legacy_epss_score DECIMAL(5,4),
        legacy_epss_percentile DECIMAL(5,2),
        legacy_cwe_ids TEXT[],
        legacy_affected_products JSONB,
        legacy_nvd_references JSONB,
        legacy_vendor_comments JSONB,
        legacy_cpe_configurations JSONB,
        legacy_nvd_weaknesses JSONB,
        legacy_source_identifier VARCHAR(200),
        legacy_nvd_status VARCHAR(50),
        legacy_nvd_published TIMESTAMP,
        legacy_nvd_last_modified TIMESTAMP,
        legacy_nvd_descriptions JSONB,
        legacy_nvd_metrics JSONB,
        legacy_has_kev BOOLEAN,
        legacy_has_cert_alerts BOOLEAN,
        legacy_cve_json5_data JSONB,
        legacy_cvelist_ff_eng TEXT,
        legacy_cvelist_ff_rus TEXT,

        -- Modern raw fields
        modern_id INTEGER,
        modern_title VARCHAR(500),
        modern_description TEXT,
        modern_severity VARCHAR(50),
        modern_status VARCHAR(50),
        modern_assigned_operator INTEGER,
        modern_created_date TIMESTAMP,
        modern_completed_date TIMESTAMP,
        modern_approved BOOLEAN,
        modern_modifications INTEGER,
        modern_cvss_score DECIMAL(3,1),
        modern_risk_level VARCHAR(50),
        modern_category VARCHAR(100),
        modern_cve_id VARCHAR(50),
        modern_source_identifier VARCHAR(100),
        modern_published TIMESTAMP,
        modern_last_modified TIMESTAMP,
        modern_vuln_status VARCHAR(50),
        modern_descriptions JSONB,
        modern_metrics JSONB,
        modern_weaknesses JSONB,
        modern_configurations JSONB,
        modern_references JSONB,
        modern_vendor_comments JSONB,
        modern_is_ai_related BOOLEAN,
        modern_ai_confidence DECIMAL(3,2),
        modern_ai_keywords_found TEXT[],
        modern_ai_categories TEXT[],
        modern_ai_reasoning TEXT,
        modern_has_kev BOOLEAN,
        modern_has_cert_alerts BOOLEAN
    );
    """


def _build_insert_sql(
    turn_cols: Set[str],
    vuln_cols: Set[str],
    cvelist_cols: Set[str],
    has_cvelist: bool,
) -> str:
    t = lambda name: _col("t", name, turn_cols)
    v = lambda name: _col("v", name, vuln_cols)
    c = lambda name: _col("c", name, cvelist_cols)

    legacy_cvss_expr = t("cvss")
    legacy_severity_expr = (
        "CASE "
        "WHEN t.cvss >= 9.0 THEN 'critical' "
        "WHEN t.cvss >= 7.0 THEN 'high' "
        "WHEN t.cvss >= 4.0 THEN 'medium' "
        "ELSE 'low' END"
        if "cvss" in turn_cols
        else "NULL"
    )
    legacy_status_expr = (
        "CASE WHEN t.status = TRUE THEN 'new' ELSE 'completed' END"
        if "status" in turn_cols
        else "NULL"
    )

    description_expr = (
        f"COALESCE({v('description')}, {c('ff_eng')}, {c('ff_rus')})"
        if has_cvelist
        else f"COALESCE({v('description')}, NULL)"
    )

    select_columns: List[str] = [
        f"COALESCE({v('cve_id')}, {t('cve')}) AS cve_id",
        f"COALESCE({v('source_identifier')}, {t('source_identifier')}, {t('source')}) AS source_identifier",
        f"COALESCE({v('title')}, {t('name')}, {t('cve')}) AS title",
        f"{description_expr} AS description",
        f"COALESCE({v('severity')}, {legacy_severity_expr}) AS severity",
        f"COALESCE({v('status')}, {legacy_status_expr}) AS status",
        f"COALESCE({v('cvss_score')}, {legacy_cvss_expr}) AS cvss_score",
        f"COALESCE({v('risk_level')}, 'medium') AS risk_level",
        f"COALESCE({v('category')}, {t('source')}) AS category",
        f"COALESCE({v('created_date')}, {t('joining_date')}) AS created_date",
        f"COALESCE({v('completed_date')}, {t('end_date')}) AS completed_date",
        f"{v('approved')} AS approved",
        f"{v('modifications')} AS modifications",
        f"{v('assigned_operator')} AS assigned_operator",
        f"COALESCE({v('published')}, {t('start_date')}, {t('nvd_published')}) AS published",
        f"COALESCE({v('last_modified')}, {t('nvd_last_modified')}) AS last_modified",
        f"COALESCE({v('vuln_status')}, {t('nvd_status')}) AS vuln_status",
        f"{v('descriptions')} AS descriptions",
        f"{v('metrics')} AS metrics",
        f"{v('weaknesses')} AS weaknesses",
        f"{v('configurations')} AS configurations",
        f"{v('references')} AS \"references\"",
        f"{v('vendor_comments')} AS vendor_comments",
        f"COALESCE({v('is_ai_related')}, FALSE) AS is_ai_related",
        f"COALESCE({v('ai_confidence')}, 0.0) AS ai_confidence",
        f"{v('ai_keywords_found')} AS ai_keywords_found",
        f"{v('ai_categories')} AS ai_categories",
        f"{v('ai_reasoning')} AS ai_reasoning",
        f"COALESCE({v('has_kev')}, {t('has_kev')}) AS has_kev",
        f"COALESCE({v('has_cert_alerts')}, {t('has_cert_alerts')}) AS has_cert_alerts",
        f"{v('bdu_id')} AS bdu_id",
        f"{v('bdu_name')} AS bdu_name",
        f"{v('vendor')} AS vendor",
        f"{v('product_name')} AS product_name",
        f"{v('affected_versions')} AS affected_versions",
        f"{v('platform')} AS platform",
        f"{v('software_types')} AS software_types",
        f"{v('registry_number')} AS registry_number",
        f"{v('vulnerable_software')} AS vulnerable_software",
        f"{v('environment')} AS environment",
        f"{v('cwes')} AS cwes",
        f"{v('vul_class')} AS vul_class",
        f"{v('sl_oper_procs')} AS sl_oper_procs",
        f"{v('identify_date')} AS identify_date",
        f"{v('publication_date')} AS publication_date",
        f"{v('last_upd_date')} AS last_upd_date",
        f"{v('cvss2_vector')} AS cvss2_vector",
        f"{v('cvss2_score')} AS cvss2_score",
        f"{v('cvss3_vector')} AS cvss3_vector",
        f"{v('cvss3_score')} AS cvss3_score",
        f"{v('bdu_severity')} AS bdu_severity",
        f"{v('vul_status')} AS vul_status",
        f"{v('exploit_status')} AS exploit_status",
        f"{v('fix_status')} AS fix_status",
        f"{v('solution')} AS solution",
        f"{v('sources')} AS sources",
        f"{v('other_identifiers')} AS other_identifiers",
        f"{v('vul_incident')} AS vul_incident",
        f"{v('vul_state')} AS vul_state",
        f"{v('vul_elimination')} AS vul_elimination",
        # Legacy raw fields
        f"{t('id')} AS legacy_id",
        f"{t('source')} AS legacy_source",
        f"{t('link')} AS legacy_link",
        f"{t('cve')} AS legacy_cve",
        f"{t('joining_date')} AS legacy_joining_date",
        f"{t('name')} AS legacy_name",
        f"{t('cvss')} AS legacy_cvss",
        f"{t('price_one')} AS legacy_price_one",
        f"{t('priority')} AS legacy_priority",
        f"{t('start_date')} AS legacy_start_date",
        f"{t('end_date')} AS legacy_end_date",
        f"{t('etc')} AS legacy_etc",
        f"{t('status')} AS legacy_status",
        f"{t('cvss_v2_vector')} AS legacy_cvss_v2_vector",
        f"{t('cvss_v3_vector')} AS legacy_cvss_v3_vector",
        f"{t('cvss_v4_vector')} AS legacy_cvss_v4_vector",
        f"{t('cvss_version')} AS legacy_cvss_version",
        f"{t('cvss_v2_metrics')} AS legacy_cvss_v2_metrics",
        f"{t('cvss_v3_metrics')} AS legacy_cvss_v3_metrics",
        f"{t('cvss_v4_metrics')} AS legacy_cvss_v4_metrics",
        f"{t('epss_score')} AS legacy_epss_score",
        f"{t('epss_percentile')} AS legacy_epss_percentile",
        f"{t('cwe_ids')} AS legacy_cwe_ids",
        f"{t('affected_products')} AS legacy_affected_products",
        f"{t('nvd_references')} AS legacy_nvd_references",
        f"{t('vendor_comments')} AS legacy_vendor_comments",
        f"{t('cpe_configurations')} AS legacy_cpe_configurations",
        f"{t('nvd_weaknesses')} AS legacy_nvd_weaknesses",
        f"{t('source_identifier')} AS legacy_source_identifier",
        f"{t('nvd_status')} AS legacy_nvd_status",
        f"{t('nvd_published')} AS legacy_nvd_published",
        f"{t('nvd_last_modified')} AS legacy_nvd_last_modified",
        f"{t('nvd_descriptions')} AS legacy_nvd_descriptions",
        f"{t('nvd_metrics')} AS legacy_nvd_metrics",
        f"{t('has_kev')} AS legacy_has_kev",
        f"{t('has_cert_alerts')} AS legacy_has_cert_alerts",
        f"{t('cve_json5_data')} AS legacy_cve_json5_data",
        f"{c('ff_eng')} AS legacy_cvelist_ff_eng",
        f"{c('ff_rus')} AS legacy_cvelist_ff_rus",
        # Modern raw fields
        f"{v('id')} AS modern_id",
        f"{v('title')} AS modern_title",
        f"{v('description')} AS modern_description",
        f"{v('severity')} AS modern_severity",
        f"{v('status')} AS modern_status",
        f"{v('assigned_operator')} AS modern_assigned_operator",
        f"{v('created_date')} AS modern_created_date",
        f"{v('completed_date')} AS modern_completed_date",
        f"{v('approved')} AS modern_approved",
        f"{v('modifications')} AS modern_modifications",
        f"{v('cvss_score')} AS modern_cvss_score",
        f"{v('risk_level')} AS modern_risk_level",
        f"{v('category')} AS modern_category",
        f"{v('cve_id')} AS modern_cve_id",
        f"{v('source_identifier')} AS modern_source_identifier",
        f"{v('published')} AS modern_published",
        f"{v('last_modified')} AS modern_last_modified",
        f"{v('vuln_status')} AS modern_vuln_status",
        f"{v('descriptions')} AS modern_descriptions",
        f"{v('metrics')} AS modern_metrics",
        f"{v('weaknesses')} AS modern_weaknesses",
        f"{v('configurations')} AS modern_configurations",
        f"{v('references')} AS modern_references",
        f"{v('vendor_comments')} AS modern_vendor_comments",
        f"{v('is_ai_related')} AS modern_is_ai_related",
        f"{v('ai_confidence')} AS modern_ai_confidence",
        f"{v('ai_keywords_found')} AS modern_ai_keywords_found",
        f"{v('ai_categories')} AS modern_ai_categories",
        f"{v('ai_reasoning')} AS modern_ai_reasoning",
        f"{v('has_kev')} AS modern_has_kev",
        f"{v('has_cert_alerts')} AS modern_has_cert_alerts",
    ]

    join_cvelist = "LEFT JOIN cvelist c ON c.cve = t.cve" if has_cvelist else ""

    return f"""
    INSERT INTO {UNIFIED_TABLE} (
        cve_id, source_identifier, title, description, severity, status, cvss_score, risk_level, category,
        created_date, completed_date, approved, modifications, assigned_operator, published, last_modified,
        vuln_status, descriptions, metrics, weaknesses, configurations, "references", vendor_comments,
        is_ai_related, ai_confidence, ai_keywords_found, ai_categories, ai_reasoning, has_kev, has_cert_alerts,
        bdu_id, bdu_name, vendor, product_name, affected_versions, platform, software_types, registry_number,
        vulnerable_software, environment, cwes, vul_class, sl_oper_procs, identify_date, publication_date,
        last_upd_date, cvss2_vector, cvss2_score, cvss3_vector, cvss3_score, bdu_severity, vul_status,
        exploit_status, fix_status, solution, sources, other_identifiers, vul_incident, vul_state,
        vul_elimination,
        legacy_id, legacy_source, legacy_link, legacy_cve, legacy_joining_date, legacy_name, legacy_cvss,
        legacy_price_one, legacy_priority, legacy_start_date, legacy_end_date, legacy_etc, legacy_status,
        legacy_cvss_v2_vector, legacy_cvss_v3_vector, legacy_cvss_v4_vector, legacy_cvss_version,
        legacy_cvss_v2_metrics, legacy_cvss_v3_metrics, legacy_cvss_v4_metrics, legacy_epss_score,
        legacy_epss_percentile, legacy_cwe_ids, legacy_affected_products, legacy_nvd_references,
        legacy_vendor_comments, legacy_cpe_configurations, legacy_nvd_weaknesses, legacy_source_identifier,
        legacy_nvd_status, legacy_nvd_published, legacy_nvd_last_modified, legacy_nvd_descriptions,
        legacy_nvd_metrics, legacy_has_kev, legacy_has_cert_alerts, legacy_cve_json5_data,
        legacy_cvelist_ff_eng, legacy_cvelist_ff_rus,
        modern_id, modern_title, modern_description, modern_severity, modern_status, modern_assigned_operator,
        modern_created_date, modern_completed_date, modern_approved, modern_modifications, modern_cvss_score,
        modern_risk_level, modern_category, modern_cve_id, modern_source_identifier, modern_published,
        modern_last_modified, modern_vuln_status, modern_descriptions, modern_metrics, modern_weaknesses,
        modern_configurations, modern_references, modern_vendor_comments, modern_is_ai_related,
        modern_ai_confidence, modern_ai_keywords_found, modern_ai_categories, modern_ai_reasoning,
        modern_has_kev, modern_has_cert_alerts
    )
    SELECT
        {", ".join(select_columns)}
    FROM turn t
    FULL OUTER JOIN vulnerabilities v
        ON v.cve_id = t.cve
    {join_cvelist}
    """


def main() -> int:
    dbm = DatabaseManager()
    conn = dbm.connection
    try:
        turn_cols = _get_columns(conn, "turn") if _table_exists(conn, "turn") else set()
        vuln_cols = _get_columns(conn, "vulnerabilities") if _table_exists(conn, "vulnerabilities") else set()
        cvelist_exists = _table_exists(conn, "cvelist")
        cvelist_cols = _get_columns(conn, "cvelist") if cvelist_exists else set()

        if not turn_cols and not vuln_cols:
            print("❌ Не найдены таблицы turn или vulnerabilities.")
            return 1

        with conn.cursor() as cursor:
            cursor.execute(_build_create_table_sql())
            cursor.execute(f"TRUNCATE TABLE {UNIFIED_TABLE}")
            cursor.execute(_build_insert_sql(turn_cols, vuln_cols, cvelist_cols, cvelist_exists))
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{UNIFIED_TABLE}_cve_id ON {UNIFIED_TABLE}(cve_id)")
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{UNIFIED_TABLE}_legacy_cve ON {UNIFIED_TABLE}(legacy_cve)")
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{UNIFIED_TABLE}_modern_cve_id ON {UNIFIED_TABLE}(modern_cve_id)")
        conn.commit()

        with conn.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {UNIFIED_TABLE}")
            total = cursor.fetchone()[0]
        print(f"✅ Объединено записей: {total}")
        return 0
    except Exception as exc:
        conn.rollback()
        print(f"❌ Ошибка объединения: {exc}")
        return 1
    finally:
        dbm.close()


if __name__ == "__main__":
    sys.exit(main())
