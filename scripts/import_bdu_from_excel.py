#!/usr/bin/env python3
"""
Импорт уязвимостей из Excel BDU/FSTEC в БД напрямую (в обход HTTP и CSRF).

Использует тот же формат, что и /api/bdu/import в app.py:
- файл: docs/парсеры ии бду.xlsx
- строка с заголовками: вторая (header=1)

Запуск из корня проекта:
    source venv/bin/activate
    python scripts/import_bdu_from_excel.py
"""

import os
import re
import pandas as pd

from services.vulnerability_service import VulnerabilityService
from models.entities import Vulnerability as BaseVulnerability


def _detect_severity_from_bdu(text: str) -> str:
    """Грубое определение severity из русской формулировки BDU."""
    if not text:
        return "medium"
    t = text.lower()
    if "критическ" in t:
        return "critical"
    if "высокий" in t or "высокая" in t:
        return "high"
    if "низк" in t:
        return "low"
    return "medium"


def _parse_cvss_from_text(text: str) -> float:
    """Попробовать вытащить числовое значение CVSS из текстового описания."""
    if not text:
        return 0.0
    nums = re.findall(r"(\\d+(?:[\\.,]\\d+)?)", str(text))
    if not nums:
        return 0.0
    try:
        val = nums[-1].replace(",", ".")
        return float(val)
    except Exception:
        return 0.0


def import_bdu_from_excel() -> dict:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    excel_path = os.path.join(project_root, "docs", "парсеры ии бду.xlsx")

    if not os.path.exists(excel_path):
        raise FileNotFoundError(f"Файл не найден: {excel_path}")

    print(f"📄 Используется файл: {excel_path}")

    df = pd.read_excel(excel_path, header=1)
    cols = {c: str(c).strip() for c in df.columns}
    df.rename(columns=cols, inplace=True)

    # Карта колонок
    col_bdu_id = "Идентификатор"
    col_name = "Наименование уязвимости"
    col_ids_other = "Идентификаторы других систем описаний уязвимости"
    col_desc = "Описание уязвимости"
    col_vendor = "Вендор ПО"
    col_product = "Название ПО"
    col_version = "Версия ПО"
    col_os = "Наименование ОС и тип аппаратной платформы"
    col_date_found = "Дата выявления"
    col_severity_text = "Уровень опасности уязвимости"
    col_cvss2 = "CVSS 2.0"
    col_cvss3 = "CVSS 3.1"
    col_mitigation = "Возможные меры по устранению"
    col_fix_status = "Статус уязвимости"
    col_fix_info = "Информация об устранении"
    col_fix_date = "Дата устранения"
    col_exploit = "Наличие эксплойта"
    col_fix_method = "Способ устранения"
    col_exploit_method = "Способ эксплуатации"
    col_refs = "Ссылки на источники"
    col_cwe_desc = "Описание ошибки CWE"
    col_cwe_type = "Тип ошибки CWE"

    svc = VulnerabilityService(use_optimized=False)

    # Индекс существующих уязвимостей по CVE
    existing_by_cve = {}
    try:
        all_vulns = svc.get_all_vulnerabilities_unlimited()
        for v in all_vulns:
            cve = getattr(v, "cve_id", None)
            if cve:
                existing_by_cve.setdefault(cve.upper(), []).append(v)
        print(f"🔍 Найдено существующих уязвимостей: {len(all_vulns)}")
    except Exception as e:
        print(f"⚠️ Не удалось получить существующие уязвимости: {e}")

    created = 0
    updated = 0
    errors = []

    for idx, row in df.iterrows():
        try:
            bdu_id = str(row.get(col_bdu_id, "")).strip()
            name = str(row.get(col_name, "")).strip()
            base_desc = str(row.get(col_desc, "")).strip()

            if not bdu_id and not name and not base_desc:
                continue

            # CVE из поля идентификаторов других систем
            cve_raw = str(row.get(col_ids_other, "") or "")
            cve_id = None
            if "CVE-" in cve_raw:
                m = re.search(r"(CVE-\\d{4}-\\d+)", cve_raw)
                if m:
                    cve_id = m.group(1).upper()

            severity_text = str(row.get(col_severity_text, "") or "")
            severity = _detect_severity_from_bdu(severity_text)

            cvss3_text = str(row.get(col_cvss3, "") or "")
            cvss2_text = str(row.get(col_cvss2, "") or "")
            cvss_score = _parse_cvss_from_text(cvss3_text) or _parse_cvss_from_text(cvss2_text)

            vendor = str(row.get(col_vendor, "") or "").strip()
            product = str(row.get(col_product, "") or "").strip()
            version = str(row.get(col_version, "") or "").strip()
            os_platform = str(row.get(col_os, "") or "").strip()
            date_found = row.get(col_date_found, None)
            mitigation = str(row.get(col_mitigation, "") or "").strip()
            fix_status = str(row.get(col_fix_status, "") or "").strip()
            fix_info = str(row.get(col_fix_info, "") or "").strip()
            date_fix = row.get(col_fix_date, None)
            exploit = str(row.get(col_exploit, "") or "").strip()
            fix_method = str(row.get(col_fix_method, "") or "").strip()
            exploit_method = str(row.get(col_exploit_method, "") or "").strip()
            refs = str(row.get(col_refs, "") or "").strip()
            cwe_desc = str(row.get(col_cwe_desc, "") or "").strip()
            cwe_type = str(row.get(col_cwe_type, "") or "").strip()

            parts = []
            if base_desc:
                parts.append(base_desc)
            if vendor or product or version:
                parts.append(f"[ПО] Вендор: {vendor or '-'}, продукт: {product or '-'}, версия: {version or '-'}")
            if os_platform:
                parts.append(f"[Платформа] {os_platform}")
            if date_found:
                parts.append(f"[Дата выявления] {date_found}")
            if severity_text:
                parts.append(f"[Уровень опасности] {severity_text}")
            if cvss2_text or cvss3_text:
                parts.append(f"[CVSS] 2.0: {cvss2_text or '-'}; 3.1: {cvss3_text or '-'}")
            if mitigation:
                parts.append(f"[Меры по устранению] {mitigation}")
            if fix_status:
                parts.append(f"[Статус BDU] {fix_status}")
            if fix_info:
                parts.append(f"[Информация об устранении] {fix_info}")
            if date_fix:
                parts.append(f"[Дата устранения] {date_fix}")
            if exploit:
                parts.append(f"[Наличие эксплойта] {exploit}")
            if fix_method or exploit_method:
                parts.append(f"[Методы] Устранение: {fix_method or '-'}; Эксплуатация: {exploit_method or '-'}")
            if refs:
                parts.append(f"[Источники] {refs}")
            if cwe_type or cwe_desc:
                parts.append(f"[CWE] {cwe_type or ''} {cwe_desc or ''}".strip())

            full_description = "\n\n".join([p for p in parts if p])

            target_vuln = None
            if cve_id and cve_id in existing_by_cve:
                target_vuln = existing_by_cve[cve_id][0]

            if target_vuln:
                new_desc = target_vuln.description or ""
                if full_description and full_description not in new_desc:
                    if new_desc:
                        new_desc = new_desc + "\n\n[BDU/FSTEC]\n" + full_description
                    else:
                        new_desc = full_description

                new_cvss = max(float(target_vuln.cvss_score or 0.0), float(cvss_score or 0.0))
                new_severity = target_vuln.severity or severity
                order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                if order.get(severity, 1) > order.get(new_severity, 1):
                    new_severity = severity

                svc.update_vulnerability(
                    target_vuln.id,
                    description=new_desc,
                    cvss_score=new_cvss,
                    severity=new_severity,
                )
                updated += 1
            else:
                title_parts = []
                if cve_id:
                    title_parts.append(cve_id)
                if bdu_id:
                    title_parts.append(bdu_id)
                if name:
                    title_parts.append(name)
                title = " - ".join(title_parts)[:255] or (name or bdu_id or "BDU Vulnerability")

                vuln = BaseVulnerability(
                    id=0,
                    title=title,
                    description=full_description or base_desc or name,
                    severity=severity,
                    status="new",
                    cvss_score=float(cvss_score or 0.0),
                    risk_level=severity,
                    category="bdu",
                    cve_id=cve_id,
                )

                if svc.add_vulnerability(vuln):
                    created += 1
                else:
                    errors.append(f"Строка {idx + 2}: не удалось добавить уязвимость")

        except Exception as e:
            errors.append(f"Строка {idx + 2}: {e}")

    return {
        "created": created,
        "updated": updated,
        "errors": errors,
        "total_rows": int(df.shape[0]),
    }


if __name__ == "__main__":
    print("🚀 Импорт BDU из Excel в базу данных")
    result = import_bdu_from_excel()
    print("✅ Импорт завершен")
    print("  Создано:", result["created"])
    print("  Обновлено:", result["updated"])
    print("  Всего строк в Excel:", result["total_rows"])
    if result["errors"]:
        print("  ⚠️ Ошибки:")
        for e in result["errors"][:10]:
            print("   -", e)


