import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import psycopg


OSINT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = OSINT_ROOT.parent
sys.path.insert(0, str(REPO_ROOT))

try:
    from config import Config
except Exception:
    Config = None


class BDUAdapterError(RuntimeError):
    pass


@dataclass
class DBConfig:
    host: str
    port: int
    database: str
    username: str
    password: str

    def dsn(self) -> str:
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"


class BDUAdapter:
    def __init__(self) -> None:
        self.db_config = self._load_db_config()

    def _load_db_config(self) -> DBConfig:
        if Config is not None and hasattr(Config, "DATABASE_CONFIG"):
            cfg = Config.DATABASE_CONFIG
            return DBConfig(
                host=cfg.host,
                port=int(cfg.port),
                database=cfg.database,
                username=cfg.username,
                password=cfg.password,
            )
        return DBConfig(
            host=os.getenv("OSINT_DB_HOST", "10.0.88.11"),
            port=int(os.getenv("OSINT_DB_PORT", "5432")),
            database=os.getenv("OSINT_DB_NAME", "vuln_db"),
            username=os.getenv("OSINT_DB_USER", "admin"),
            password=os.getenv("OSINT_DB_PASSWORD", "123"),
        )

    def _connect(self):
        return psycopg.connect(self.db_config.dsn())

    def _table_exists(self, cursor, table: str) -> bool:
        cursor.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_name = %s
            )
            """,
            (table,),
        )
        row = cursor.fetchone()
        return bool(row and row[0])

    def _column_exists(self, cursor, table: str, column: str) -> bool:
        cursor.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = %s AND column_name = %s
            )
            """,
            (table, column),
        )
        row = cursor.fetchone()
        return bool(row and row[0])

    def _detect_schema(self, cursor) -> str:
        if Config is not None and hasattr(Config, "USE_LEGACY_SCHEMA"):
            if Config.USE_LEGACY_SCHEMA:
                return "legacy"
            return "modern"
        if self._table_exists(cursor, "turn"):
            return "legacy"
        if self._table_exists(cursor, "vulnerabilities"):
            return "modern"
        return "legacy"

    def _load_from_modern(self, cursor, vulnerability_id: Optional[int], cve_id: Optional[str]) -> Dict[str, Any]:
        base_columns = [
            "id",
            "title",
            "description",
            "severity",
            "cve_id",
            "vendor",
            "product_name",
            "affected_versions",
            "platform",
            "environment",
            "cwes",
            "vul_class",
            "identify_date",
            "bdu_severity",
            "cvss2_vector",
            "cvss3_vector",
            "solution",
            "vul_status",
            "vul_state",
            "vul_elimination",
            "vul_incident",
            "exploit_status",
            "sources",
            "references",
            "bdu_id",
            "bdu_name",
        ]

        columns = []
        for col in base_columns:
            if self._column_exists(cursor, "vulnerabilities", col):
                columns.append(col)

        if not columns:
            raise BDUAdapterError("В таблице vulnerabilities нет доступных колонок для БДУ.")

        where_clause = ""
        params = []
        if vulnerability_id is not None:
            where_clause = "WHERE id = %s"
            params.append(vulnerability_id)
        elif cve_id:
            where_clause = "WHERE cve_id = %s"
            params.append(cve_id)
        else:
            raise BDUAdapterError("Нужен vulnerability_id или cve_id для modern схемы.")

        query = f"SELECT {', '.join(columns)} FROM vulnerabilities {where_clause} LIMIT 1"
        cursor.execute(query, params)
        row = cursor.fetchone()
        if not row:
            raise BDUAdapterError("Уязвимость не найдена в modern схеме.")

        data = dict(zip(columns, row))
        return data

    def _load_from_legacy(self, cursor, vulnerability_id: Optional[int], cve_id: Optional[str]) -> Dict[str, Any]:
        if vulnerability_id is not None:
            cursor.execute(
                "SELECT id, cve, name, etc, cvss, link, start_date, end_date FROM turn WHERE id = %s",
                (vulnerability_id,),
            )
        elif cve_id:
            cursor.execute(
                "SELECT id, cve, name, etc, cvss, link, start_date, end_date FROM turn WHERE cve = %s",
                (cve_id,),
            )
        else:
            raise BDUAdapterError("Нужен vulnerability_id или cve_id для legacy схемы.")

        row = cursor.fetchone()
        if not row:
            raise BDUAdapterError("Уязвимость не найдена в legacy схеме.")

        etc_data: Dict[str, Any] = {}
        try:
            if row[3]:
                etc_data = json.loads(row[3]) if isinstance(row[3], str) else row[3]
        except Exception:
            etc_data = {}

        data = {
            "id": row[0],
            "cve_id": row[1],
            "title": row[2],
            "description": etc_data.get("description") or "",
            "severity": etc_data.get("severity") or "",
            "vendor": etc_data.get("vendor"),
            "product_name": etc_data.get("product_name"),
            "affected_versions": etc_data.get("affected_versions"),
            "platform": etc_data.get("platform"),
            "environment": etc_data.get("environment"),
            "cwes": etc_data.get("cwes"),
            "vul_class": etc_data.get("vul_class"),
            "identify_date": etc_data.get("identify_date"),
            "bdu_severity": etc_data.get("bdu_severity"),
            "cvss2_vector": etc_data.get("cvss2_vector"),
            "cvss3_vector": etc_data.get("cvss3_vector"),
            "solution": etc_data.get("solution"),
            "vul_status": etc_data.get("vul_status"),
            "vul_state": etc_data.get("vul_state"),
            "vul_elimination": etc_data.get("vul_elimination"),
            "vul_incident": etc_data.get("vul_incident"),
            "exploit_status": etc_data.get("exploit_status"),
            "sources": etc_data.get("sources"),
            "references": etc_data.get("references"),
            "bdu_id": etc_data.get("bdu_id"),
            "bdu_name": etc_data.get("bdu_name"),
        }

        return data

    def _format_os_platform(self, data: Dict[str, Any]) -> str:
        env_parts = []
        environment = data.get("environment")
        if isinstance(environment, list):
            for item in environment:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("os") or item.get("title")
                    if name:
                        env_parts.append(str(name))
                elif item:
                    env_parts.append(str(item))
        platform = data.get("platform")
        if platform:
            env_parts.append(str(platform))
        return ", ".join([p for p in env_parts if p])

    def _format_sources(self, data: Dict[str, Any]) -> str:
        sources = data.get("sources")
        if isinstance(sources, str):
            return sources
        references = data.get("references")
        if isinstance(references, list):
            urls = []
            for ref in references:
                if isinstance(ref, dict) and ref.get("url"):
                    urls.append(ref["url"])
            return "; ".join(urls)
        return ""

    def _format_cwe(self, data: Dict[str, Any]) -> str:
        cwes = data.get("cwes")
        if isinstance(cwes, list):
            parts = []
            for cwe in cwes:
                if isinstance(cwe, dict):
                    identifier = cwe.get("identifier") or cwe.get("cwe_id") or ""
                    description = cwe.get("description") or ""
                    value = f"{identifier} {description}".strip()
                    if value:
                        parts.append(value)
            return "; ".join(parts)
        weaknesses = data.get("weaknesses")
        if isinstance(weaknesses, list):
            descriptions = []
            for weakness in weaknesses:
                if isinstance(weakness, dict):
                    for desc in weakness.get("description", []):
                        value = desc.get("value")
                        if value:
                            descriptions.append(value)
            return "; ".join(descriptions)
        return ""

    def _format_cwe_ids(self, data: Dict[str, Any]) -> str:
        cwes = data.get("cwes")
        ids = []
        if isinstance(cwes, list):
            for cwe in cwes:
                if isinstance(cwe, dict):
                    identifier = cwe.get("identifier") or cwe.get("cwe_id")
                    if identifier:
                        ids.append(identifier)
        return ", ".join([c for c in ids if c])

    def build_bdu_row(
        self,
        vulnerability_id: Optional[int] = None,
        cve_id: Optional[str] = None,
        bdu_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if vulnerability_id is None and not cve_id and not bdu_id:
            raise BDUAdapterError("Нужно указать vulnerability_id, cve_id или bdu_id.")

        with self._connect() as conn:
            with conn.cursor() as cursor:
                schema = self._detect_schema(cursor)
                if schema == "modern":
                    data = self._load_from_modern(cursor, vulnerability_id, cve_id)
                else:
                    data = self._load_from_legacy(cursor, vulnerability_id, cve_id)

        if bdu_id and data.get("bdu_id") != bdu_id:
            raise BDUAdapterError("Указанный bdu_id не соответствует найденной уязвимости.")

        return {
            "Статус": "True" if data.get("bdu_id") else "",
            "Идентификатор": "True" if data.get("bdu_id") else "",
            "Наименование уязвимости": data.get("bdu_name") or data.get("title") or "",
            "Идентификаторы других систем описаний уязвимости": data.get("cve_id") or "",
            "Описание уязвимости": data.get("description") or "",
            "Вендор ПО": data.get("vendor") or "",
            "Название ПО": data.get("product_name") or "",
            "Версия ПО": data.get("affected_versions") or "",
            "Класс уязвимости": data.get("vul_class") or "",
            "Наименование ОС и тип аппаратной платформы": self._format_os_platform(data),
            "Дата выявления": self._format_date(data.get("identify_date")),
            "Уровень опасности уязвимости": data.get("bdu_severity") or data.get("severity") or "",
            "CVSS 2.0": data.get("cvss2_vector") or "",
            "CVSS 3.1": data.get("cvss3_vector") or "",
            "CVSS 4.0": "",
            "Возможные меры по устранению": data.get("solution") or "",
            "Статус уязвимости": data.get("vul_status") or data.get("vul_state") or "",
            "Информация об устранении": self._cleanup_text(data.get("vul_elimination") or data.get("vul_incident") or ""),
            "Дата устранения": "",
            "Наличие эксплойта": data.get("exploit_status") or "",
            "Способ устранения": data.get("vul_elimination") or "",
            "Способ эксплуатации": "",
            "Ссылки на источники": self._format_sources(data),
            "cnt_arch": "",
            "Описание ошибки CWE": self._format_cwe(data),
            "Тип ошибки CWE": self._format_cwe_ids(data),
        }

    def _cleanup_text(self, value: Any) -> str:
        text = str(value) if value is not None else ""
        return text.replace("_x000D_", "").strip()

    def _format_date(self, value: Any) -> str:
        if value is None:
            return ""
        try:
            if hasattr(value, "strftime"):
                return value.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        return str(value)
