#!/usr/bin/env python3
import json
import os
from pathlib import Path

import requests


def main() -> None:
    base_url = os.getenv("OSINT_API_URL", "http://127.0.0.1:8010")
    output_dir = Path("results/osint_demo")
    output_dir.mkdir(parents=True, exist_ok=True)

    queries = [
        "Как найти открытые сервисы компании example.com с помощью Shodan?",
        "Проведи OSINT разведку для домена google.com",
    ]

    for idx, query in enumerate(queries, 1):
        payload = {"query": query, "include_tools": True, "use_cyberintel": True}
        response = requests.post(f"{base_url}/osint/query", json=payload, timeout=120)
        response.raise_for_status()
        data = response.json()
        output_file = output_dir / f"osint_query_{idx}.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"✅ Ответ сохранен: {output_file}")

    bdu_payload = {
        "query": "Сформируй краткий отчет по уязвимости",
        "vulnerability_id": int(os.getenv("OSINT_DEMO_VULN_ID", "1")),
        "include_tools": True,
        "use_cyberintel": True,
    }
    response = requests.post(f"{base_url}/osint/query-with-bdu", json=bdu_payload, timeout=120)
    response.raise_for_status()
    data = response.json()
    output_file = output_dir / "osint_query_with_bdu.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"✅ BDU-ответ сохранен: {output_file}")


if __name__ == "__main__":
    main()
