import logging
from typing import Any, Dict, Optional

import requests

from config import Config

logger = logging.getLogger(__name__)


class OSINTClient:
    """Клиент для OSINT нейросети (ML VM)."""

    def __init__(self) -> None:
        self.base_url = Config.OSINT_API_URL.rstrip("/")

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            if method == "GET":
                response = requests.get(url, timeout=30)
            else:
                response = requests.post(url, json=payload, timeout=120)
            response.raise_for_status()
            return {"success": True, "data": response.json() if response.content else {}}
        except requests.exceptions.RequestException as exc:
            logger.error("OSINT API error: %s", exc)
            return {"success": False, "error": str(exc), "url": url}

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health")

    def query(self, query: str, include_tools: bool = True, use_cyberintel: bool = True) -> Dict[str, Any]:
        payload = {
            "query": query,
            "include_tools": include_tools,
            "use_cyberintel": use_cyberintel,
        }
        return self._request("POST", "/osint/query", payload)

    def query_with_bdu(
        self,
        query: str,
        vulnerability_id: Optional[int] = None,
        cve_id: Optional[str] = None,
        bdu_id: Optional[str] = None,
        include_tools: bool = True,
        use_cyberintel: bool = True,
    ) -> Dict[str, Any]:
        payload = {
            "query": query,
            "vulnerability_id": vulnerability_id,
            "cve_id": cve_id,
            "bdu_id": bdu_id,
            "include_tools": include_tools,
            "use_cyberintel": use_cyberintel,
        }
        return self._request("POST", "/osint/query-with-bdu", payload)


osint_client = OSINTClient()
