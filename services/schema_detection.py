import logging
from typing import Optional

from config import Config

logger = logging.getLogger(__name__)


def auto_detect_schema(db_connection, prefer_legacy: Optional[bool] = None) -> bool:
    """
    Detect whether legacy or modern schema should be used.

    Returns True for legacy schema, False for modern schema.
    """
    if prefer_legacy is None:
        prefer_legacy = bool(Config.USE_LEGACY_SCHEMA)

    if db_connection is None or getattr(db_connection, "closed", True):
        logger.warning("Schema auto-detect skipped: DB connection not available.")
        return prefer_legacy

    try:
        with db_connection.cursor() as cursor:
            cursor.execute(
                "SELECT "
                "to_regclass('public.turn') IS NOT NULL, "
                "to_regclass('public.vulnerabilities') IS NOT NULL"
            )
            has_turn, has_vuln = cursor.fetchone()

            legacy_has_data = False
            modern_has_data = False

            if has_turn:
                cursor.execute("SELECT 1 FROM turn WHERE cve IS NOT NULL AND cve != '' LIMIT 1")
                legacy_has_data = cursor.fetchone() is not None

            if has_vuln:
                cursor.execute("SELECT 1 FROM vulnerabilities LIMIT 1")
                modern_has_data = cursor.fetchone() is not None

        if legacy_has_data and not modern_has_data:
            return True
        if modern_has_data and not legacy_has_data:
            return False

        if legacy_has_data and modern_has_data:
            return prefer_legacy

        if has_turn and not has_vuln:
            return True
        if has_vuln and not has_turn:
            return False

        return prefer_legacy
    except Exception as exc:
        logger.warning(f"Schema auto-detect failed, using default. Error: {exc}")
        return prefer_legacy


def has_unified_table(db_connection, table_name: str = "vulnerabilities_unified") -> bool:
    """Проверить наличие объединенной таблицы."""
    if db_connection is None or getattr(db_connection, "closed", True):
        return False
    try:
        with db_connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{table_name}",))
            return bool(cursor.fetchone()[0])
    except Exception:
        return False
