import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Iterable

import dns.resolver
import whois

from .cert_search import CertificateSearch


class DNSIntelService:
    """
    Легковесная OSINT-интеграция для DNS и WHOIS без платных ключей.
    Использует crt.sh для поиска поддоменов и стандартные DNS запросы.
    """

    def __init__(
        self,
        cache_dir: str = "data/cache/dns_intel",
        cache_ttl: int = 3600,
        max_subdomains: int = 200,
        resolve_subdomains: bool = True
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = cache_ttl
        self.max_subdomains = max_subdomains
        self.resolve_subdomains = resolve_subdomains
        self.cert_search = CertificateSearch()

    def _cache_path(self, key: str) -> Path:
        safe_key = "".join(c for c in key if c.isalnum() or c in ["_", "-"])[:120]
        return self.cache_dir / f"{safe_key}.json"

    def _load_cache(self, key: str) -> Optional[Dict[str, Any]]:
        cache_path = self._cache_path(key)
        if not cache_path.exists():
            return None
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if time.time() - payload.get("timestamp", 0) <= self.cache_ttl:
                return payload.get("data")
        except Exception:
            return None
        return None

    def _save_cache(self, key: str, data: Dict[str, Any]) -> None:
        cache_path = self._cache_path(key)
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump({"timestamp": time.time(), "data": data}, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def resolve_records(self, domain: str, record_types: Iterable[str] = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")) -> Dict[str, List[str]]:
        """Получение DNS-записей для домена."""
        results: Dict[str, List[str]] = {}
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                results[record_type] = []
        return results

    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Поиск поддоменов через crt.sh."""
        response = self.cert_search.search_domain(domain, include_subdomains=True, use_cache=True)
        subdomains = response.get("domains", [])
        return subdomains[: self.max_subdomains]

    def _filter_resolvable(self, domains: List[str]) -> List[str]:
        """Фильтрация только резолвящихся поддоменов."""
        resolvable = []
        for entry in domains:
            try:
                answers = dns.resolver.resolve(entry, "A")
                if answers:
                    resolvable.append(entry)
            except Exception:
                continue
        return resolvable

    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """WHOIS информация (лучшее усилие, зависит от регистратора)."""
        try:
            data = whois.whois(domain)
            return {
                "domain_name": data.domain_name,
                "registrar": data.registrar,
                "creation_date": str(data.creation_date) if data.creation_date else None,
                "expiration_date": str(data.expiration_date) if data.expiration_date else None,
                "name_servers": data.name_servers,
                "emails": data.emails
            }
        except Exception:
            return {}

    def get_domain_intel(self, domain: str, use_cache: bool = True) -> Dict[str, Any]:
        """Комплексная сводка по домену без платных API."""
        cache_key = f"dns_intel_{domain}"
        if use_cache:
            cached = self._load_cache(cache_key)
            if cached:
                return cached

        subdomains = self.enumerate_subdomains(domain)
        if self.resolve_subdomains:
            subdomains = self._filter_resolvable(subdomains)

        data = {
            "domain": domain,
            "dns_records": self.resolve_records(domain),
            "subdomains": subdomains,
            "subdomain_count": len(subdomains),
            "whois": self.whois_lookup(domain)
        }

        if use_cache:
            self._save_cache(cache_key, data)

        return data
