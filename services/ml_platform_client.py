"""
Клиент для взаимодействия с ML платформой на k8s-worker VM
"""
import requests
import paramiko
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import subprocess
import os
from collections import Counter

logger = logging.getLogger(__name__)


class MLPlatformClient:
    """Клиент для взаимодействия с ML платформой на k8s-worker"""
    
    def __init__(self):
        # Настройки подключения к k8s-worker (из конфига/ENV)
        from config import Config
        self.vm_host = Config.ML_PLATFORM_VM_IP
        self.vm_user = Config.ML_PLATFORM_SSH_USER
        self.vm_password = Config.ML_PLATFORM_SSH_PASSWORD
        self.ml_api_url = f"http://{self.vm_host}:{Config.ML_PLATFORM_API_PORT}"  # FastAPI на k8s-worker
        self.ssh_port = Config.ML_PLATFORM_SSH_PORT
        self.jupyter_port = 8888
        
        # Настройки подключения к БД проекта
        self.db_config = Config.DATABASE_CONFIG
        
        # Настройки батчинга для анализа (из конфига)
        self.max_analysis_batch = Config.ML_ANALYSIS_MAX_BATCH  # Максимальное количество уязвимостей для анализа за раз
        self.analysis_timeout = Config.ML_ANALYSIS_TIMEOUT  # Таймаут для анализа (секунды)
        self.ml_batch_size = 5000  # Размер батча для отправки на ML платформу (чтобы не перегружать)

        # Для диагностик связности
        self.backend_url = Config.ML_PLATFORM_BACKEND_URL
        self.frontend_url = Config.ML_PLATFORM_FRONTEND_URL

    @staticmethod
    def _tcp_check(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        """Проверка TCP коннекта (без внешних утилит)."""
        import socket
        start = datetime.now()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                ms = int((datetime.now() - start).total_seconds() * 1000)
                return {"ok": True, "host": host, "port": port, "latency_ms": ms}
        except Exception as e:
            ms = int((datetime.now() - start).total_seconds() * 1000)
            return {"ok": False, "host": host, "port": port, "latency_ms": ms, "error": str(e)}

    def _remote_tcp_check_via_ssh(self, host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        """Проверка TCP коннекта с k8s-worker до цели (host:port) через SSH."""
        py = (
            "python3 - <<'PY'\n"
            "import socket, sys, time\n"
            f"host={host!r}\n"
            f"port={int(port)}\n"
            f"timeout={float(timeout)}\n"
            "t=time.time()\n"
            "try:\n"
            "  s=socket.create_connection((host, port), timeout=timeout)\n"
            "  s.close()\n"
            "  ms=int((time.time()-t)*1000)\n"
            "  print('OK', ms)\n"
            "except Exception as e:\n"
            "  ms=int((time.time()-t)*1000)\n"
            "  print('ERR', ms, str(e))\n"
            "  sys.exit(2)\n"
            "PY"
        )
        res = self._execute_ssh_command(py)
        out = (res.get("output") or "").strip()
        if res.get("success") and out.startswith("OK"):
            try:
                ms = int(out.split()[1])
            except Exception:
                ms = None
            return {"ok": True, "host": host, "port": port, "latency_ms": ms, "via": "k8s-worker"}
        return {"ok": False, "host": host, "port": port, "via": "k8s-worker", "error": res.get("error") or out}

    def _remote_http_check_via_ssh(self, url: str, timeout: float = 5.0) -> Dict[str, Any]:
        """Проверка HTTP GET с k8s-worker (без curl) через python urllib."""
        py = (
            "python3 - <<'PY'\n"
            "import sys, time\n"
            "from urllib.request import urlopen, Request\n"
            "from urllib.error import URLError, HTTPError\n"
            f"url={url!r}\n"
            f"timeout={float(timeout)}\n"
            "t=time.time()\n"
            "try:\n"
            "  req=Request(url, headers={'User-Agent':'vm-check/1.0'})\n"
            "  with urlopen(req, timeout=timeout) as r:\n"
            "    code=getattr(r, 'status', 200)\n"
            "    ms=int((time.time()-t)*1000)\n"
            "    print('OK', code, ms)\n"
            "except HTTPError as e:\n"
            "  ms=int((time.time()-t)*1000)\n"
            "  print('HTTPERR', e.code, ms)\n"
            "  sys.exit(2)\n"
            "except URLError as e:\n"
            "  ms=int((time.time()-t)*1000)\n"
            "  print('URLERR', ms, str(e))\n"
            "  sys.exit(3)\n"
            "except Exception as e:\n"
            "  ms=int((time.time()-t)*1000)\n"
            "  print('ERR', ms, str(e))\n"
            "  sys.exit(4)\n"
            "PY"
        )
        res = self._execute_ssh_command(py)
        out = (res.get("output") or "").strip()
        if res.get("success") and out.startswith("OK"):
            parts = out.split()
            code = int(parts[1]) if len(parts) > 1 else 200
            ms = int(parts[2]) if len(parts) > 2 else None
            return {"ok": True, "url": url, "http_code": code, "latency_ms": ms, "via": "k8s-worker"}
        # HTTPERR returns non-zero exit; still useful
        if out.startswith("HTTPERR"):
            parts = out.split()
            code = int(parts[1]) if len(parts) > 1 else None
            ms = int(parts[2]) if len(parts) > 2 else None
            return {"ok": False, "url": url, "http_code": code, "latency_ms": ms, "via": "k8s-worker", "error": "HTTP error"}
        return {"ok": False, "url": url, "via": "k8s-worker", "error": res.get("error") or out}

    def diagnose_connectivity(self) -> Dict[str, Any]:
        """
        Полная диагностика связности:
        - backend -> DB (SQL)
        - backend -> ML API (HTTP)
        - backend -> k8s-worker (SSH)
        - k8s-worker -> DB (TCP)
        - k8s-worker -> backend (TCP)
        - k8s-worker -> ML API self-check (HTTP)
        """
        results: Dict[str, Any] = {"success": True, "checks": {}, "ts": datetime.now().isoformat()}

        # 1) backend -> DB (SQL)
        try:
            from models.database import DatabaseManager
            db = DatabaseManager()
            with db.connection.cursor() as cur:
                cur.execute("SELECT 1;")
                cur.fetchone()
            results["checks"]["backend_to_db_sql"] = {"ok": True}
        except Exception as e:
            results["checks"]["backend_to_db_sql"] = {"ok": False, "error": str(e)}
            results["success"] = False

        # 2) backend -> DB (TCP)
        results["checks"]["backend_to_db_tcp"] = self._tcp_check(self.db_config.host, int(self.db_config.port), timeout=3.0)
        if not results["checks"]["backend_to_db_tcp"]["ok"]:
            results["success"] = False

        # 3) backend -> ML API
        api_status = self._make_api_request("GET", "/health")
        results["checks"]["backend_to_ml_api"] = {
            "ok": bool(api_status.get("success")),
            "url": f"{self.ml_api_url}/health",
            "error": api_status.get("error"),
            "data": api_status.get("data", {}),
        }
        if not results["checks"]["backend_to_ml_api"]["ok"]:
            results["success"] = False

        # 4) backend -> k8s-worker SSH
        ssh_status = self._execute_ssh_command('echo "OK"')
        results["checks"]["backend_to_k8s_worker_ssh"] = {
            "ok": bool(ssh_status.get("success")),
            "host": self.vm_host,
            "error": ssh_status.get("error"),
        }
        if not results["checks"]["backend_to_k8s_worker_ssh"]["ok"]:
            results["success"] = False

        # 5) k8s-worker -> DB (TCP) and backend (TCP)
        results["checks"]["k8s_worker_to_db_tcp"] = self._remote_tcp_check_via_ssh(self.db_config.host, int(self.db_config.port), timeout=3.0)
        if not results["checks"]["k8s_worker_to_db_tcp"]["ok"]:
            results["success"] = False

        # backend url parse -> host/port
        try:
            from urllib.parse import urlparse
            u = urlparse(self.backend_url)
            backend_host = u.hostname or "10.0.88.20"
            backend_port = u.port or 5000
        except Exception:
            backend_host, backend_port = "10.0.88.20", 5000

        results["checks"]["k8s_worker_to_backend_tcp"] = self._remote_tcp_check_via_ssh(backend_host, int(backend_port), timeout=3.0)
        if not results["checks"]["k8s_worker_to_backend_tcp"]["ok"]:
            results["success"] = False

        # k8s-worker -> backend HTTP health (фактическая проверка обмена по HTTP)
        results["checks"]["k8s_worker_to_backend_http"] = self._remote_http_check_via_ssh(f"{self.backend_url.rstrip('/')}/api/health", timeout=5.0)
        if not results["checks"]["k8s_worker_to_backend_http"]["ok"]:
            results["success"] = False

        # 6) k8s-worker -> ML API self-check (TCP)
        try:
            from urllib.parse import urlparse
            mu = urlparse(self.ml_api_url)
            ml_host = mu.hostname or self.vm_host
            ml_port = mu.port or 8000
        except Exception:
            ml_host, ml_port = self.vm_host, 8000
        results["checks"]["k8s_worker_to_ml_api_tcp"] = self._remote_tcp_check_via_ssh(ml_host, int(ml_port), timeout=3.0)

        return results
        
    def _execute_ssh_command(self, command: str) -> Dict[str, Any]:
        """
        Выполнение команды через SSH на k8s-worker
        
        Args:
            command: Команда для выполнения
            
        Returns:
            Результат выполнения
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                self.vm_host,
                username=self.vm_user,
                password=self.vm_password,
                port=self.ssh_port,
                timeout=10
            )
            
            stdin, stdout, stderr = ssh.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            ssh.close()
            
            return {
                'success': exit_status == 0,
                'output': output,
                'error': error,
                'exit_status': exit_status
            }
        except Exception as e:
            logger.error(f"Ошибка SSH подключения: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _make_api_request(self, method: str, endpoint: str, data: Optional[Any] = None) -> Dict[str, Any]:
        """
        Выполнение HTTP запроса к ML API
        
        Args:
            method: HTTP метод
            endpoint: API endpoint
            data: Данные для отправки (Dict, List или None)
            
        Returns:
            Ответ API
        """
        try:
            url = f"{self.ml_api_url}{endpoint}"
            headers = {'Content-Type': 'application/json'}
            
            if method.upper() == 'GET':
                response = requests.get(url, timeout=30)
            elif method.upper() == 'POST':
                # Если data это список, отправляем как JSON массив
                if isinstance(data, list):
                    response = requests.post(url, json=data, headers=headers, timeout=30)
                else:
                    response = requests.post(url, json=data, headers=headers, timeout=30)
            elif method.upper() == 'PUT':
                response = requests.put(url, json=data, headers=headers, timeout=30)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, timeout=30)
            else:
                return {'success': False, 'error': f'Unsupported method: {method}'}
            
            response.raise_for_status()
            return {
                'success': True,
                'data': response.json() if response.content else {}
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Ошибка API запроса к {url}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    # ========== ИИ-АНАЛИЗ ==========
    
    def start_ai_analysis(self, vulnerability_ids: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Запуск ИИ-анализа уязвимостей
        
        Args:
            vulnerability_ids: Список ID уязвимостей (None = все)
            
        Returns:
            Результат запуска
        """
        try:
            # Получаем данные уязвимостей из БД проекта
            from models.database import DatabaseManager
            from models.legacy_repositories import LegacyVulnerabilityRepository
            
            db = DatabaseManager()
            repo = LegacyVulnerabilityRepository(db.connection)
            
            if vulnerability_ids:
                vulnerabilities = []
                for vuln_id in vulnerability_ids:
                    vuln = repo.get_by_id(vuln_id)
                    if vuln:
                        vulnerabilities.append(self._vulnerability_to_dict(vuln))
            else:
                # Получаем все уязвимости с большим лимитом
                logger.info(f"🔍 Получение уязвимостей из БД (лимит: {self.max_analysis_batch})...")
                all_vulns = repo.get_all_vulnerabilities(limit=self.max_analysis_batch)
                logger.info(f"📊 Получено {len(all_vulns)} уязвимостей из БД")
                
                if not all_vulns:
                    return {
                        'success': False, 
                        'error': 'Нет уязвимостей для анализа. Сначала запустите парсинг уязвимостей.',
                        'hint': 'Используйте раздел "Парсинг" для загрузки уязвимостей из различных источников (NVD, Red Hat, OSV и т.д.)'
                    }
                
                # Преобразуем в словари
                vulnerabilities = [self._vulnerability_to_dict(v) for v in all_vulns]
                logger.info(f"📊 Подготовлено {len(vulnerabilities)} уязвимостей для анализа")
            
            # Нормализуем и строим маппинги
            cve_to_vuln_id: Dict[str, int] = {}
            cve_to_payload: Dict[str, Dict[str, Any]] = {}
            for v in vulnerabilities:
                cve = (v.get('cve_id') or '').strip()
                if not cve:
                    continue
                # id обязателен для сохранения результата в legacy turn
                if v.get('id') is not None:
                    cve_to_vuln_id[cve] = int(v['id'])
                cve_to_payload[cve] = {
                    "cve_id": cve,
                    "title": v.get("title") or "",
                    "description": v.get("description") or "",
                }

            cve_ids = list(cve_to_payload.keys())

            if not cve_ids:
                return {
                    'success': False, 
                    'error': 'Нет CVE ID для анализа. У уязвимостей отсутствуют CVE идентификаторы.',
                    'hint': f'Найдено {len(vulnerabilities)} уязвимостей, но у них нет CVE ID. Проверьте данные в БД.'
                }
            
            logger.info(f"📊 Подготовлено {len(cve_ids)} CVE для анализа")
            
            # Разбиваем на батчи для обработки больших объемов
            all_results = []
            total_batches = (len(cve_ids) + self.ml_batch_size - 1) // self.ml_batch_size
            
            for batch_num in range(total_batches):
                start_idx = batch_num * self.ml_batch_size
                end_idx = min(start_idx + self.ml_batch_size, len(cve_ids))
                batch_cve_ids = cve_ids[start_idx:end_idx]
                
                logger.info(f"🔄 Обработка батча {batch_num + 1}/{total_batches} ({len(batch_cve_ids)} CVE)...")
                
                try:
                    # 1) Пытаемся "новый" API (FastAPI ml_platform): /security/ai/batch-analyze (ожидает list[str])
                    url = f"{self.ml_api_url}/security/ai/batch-analyze"
                    response = requests.post(
                        url,
                        json=batch_cve_ids,
                        headers={'Content-Type': 'application/json'},
                        timeout=self.analysis_timeout
                    )

                    # 2) Если на VM поднят Flask ai_service_server.py — там другой payload:
                    #    POST /api/batch-analyze с {"vulnerabilities":[{cve_id,title,description},...]}
                    #    У него может не быть /security/ai/batch-analyze (404) или он может вернуть 400/422 на list[str].
                    # Важно: Flask-сервис может вернуть 500 на list[str] (AttributeError внутри),
                    # поэтому при любом не-2xx пробуем fallback.
                    if response.status_code >= 400:
                        url2 = f"{self.ml_api_url}/api/batch-analyze"
                        batch_payload = [cve_to_payload[c] for c in batch_cve_ids if c in cve_to_payload]
                        response = requests.post(
                            url2,
                            json={"vulnerabilities": batch_payload},
                            headers={'Content-Type': 'application/json'},
                            timeout=self.analysis_timeout
                        )

                    response.raise_for_status()
                    batch_result = response.json() if response.content else {}
                    all_results.append(batch_result)
                    logger.info(f"✅ Батч {batch_num + 1}/{total_batches} обработан успешно")
                except requests.exceptions.RequestException as e:
                    logger.error(f"❌ Ошибка при обработке батча {batch_num + 1}: {e}")
                    # Продолжаем обработку следующих батчей даже при ошибке
                    all_results.append({'error': str(e), 'batch': batch_num + 1})
            
            # Объединяем результаты всех батчей
            combined_results = {
                'total_batches': total_batches,
                'total_cves': len(cve_ids),
                'processed_batches': len([r for r in all_results if 'error' not in r]),
                'results': []
            }
            
            # Собираем все результаты из батчей
            for batch_result in all_results:
                if 'results' in batch_result:
                    combined_results['results'].extend(batch_result['results'])

            # Проставляем vulnerability_id для сохранения в legacy turn.etc
            enriched_results = []
            for r in combined_results.get('results', []):
                if not isinstance(r, dict):
                    continue
                cve = (r.get('cve_id') or '').strip()
                vuln_id = cve_to_vuln_id.get(cve)
                enriched = dict(r)
                if vuln_id:
                    enriched['vulnerability_id'] = vuln_id
                # сохраняем что именно подавали в модель (для прозрачности)
                payload = cve_to_payload.get(cve) or {}
                text = f"{payload.get('title','')} {payload.get('description','')}".strip()
                enriched["input_text_len"] = len(text)
                enriched["input_excerpt"] = (text[:500] + "…") if len(text) > 500 else text
                enriched_results.append(enriched)
            combined_results['results'] = enriched_results
            
            result = {
                'success': combined_results['processed_batches'] > 0,
                'data': combined_results
            }
            
            if result['success']:
                logger.info(f"✅ Анализ завершен: обработано {combined_results['processed_batches']}/{total_batches} батчей, {len(combined_results['results'])} результатов")
                # Сохраняем результаты в БД
                self._save_analysis_results(combined_results)
            else:
                logger.error(f"❌ Не удалось обработать ни одного батча")
            
            return result
        except Exception as e:
            logger.error(f"Ошибка запуска ИИ-анализа: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_ai_statistics(self) -> Dict[str, Any]:
        """
        Получение статистики по ключевым словам
        
        Returns:
            Статистика
        """
        result = self._make_api_request('GET', '/security/ai/stats')
        if not result.get('success'):
            return result

        # Преобразуем формат для совместимости
        stats = result.get('data', {}) or {}
        keyword_dist = stats.get('keyword_distribution', {}) if isinstance(stats.get('keyword_distribution', {}), dict) else {}
        top_keywords = stats.get('top_keywords', []) if isinstance(stats.get('top_keywords', []), list) else []
        top_attacks = stats.get('top_attacks', []) if isinstance(stats.get('top_attacks', []), list) else []

        mapped = {
            'total_analyzed': stats.get('total_cves', 0),
            'ai_related': stats.get('ai_related_count', 0),
            # k8s-worker отдаёт процент (0..100)
            'avg_confidence': float(stats.get('avg_confidence', 0.0) or 0.0),
            'total_keywords': int(stats.get('total_keywords', len(keyword_dist) if keyword_dist else 0) or 0),
            'category_distribution': stats.get('category_distribution', {}),
            'keyword_distribution': keyword_dist,
            'top_keywords': top_keywords,
            'top_attacks': top_attacks,
        }

        # Aha: на сервере часто возвращается "total_keywords=2" (только AI_RELATED/NON_AI) и без top_keywords.
        # Чтобы UI всегда показывал реальные keyword_hits, считаем топ-слова напрямую из БД (turn.etc.ai_analysis).
        need_db_fallback = (not mapped.get('top_keywords')) or (not mapped.get('keyword_distribution')) or int(mapped.get('total_keywords') or 0) <= 2
        if need_db_fallback:
            try:
                db_stats = self._compute_ai_keyword_stats_from_db(max_rows=300000, top_n=30)
                # Мержим: базовые числа берём из БД (источник истины), но оставляем категориальную разметку от API если есть
                mapped.update(db_stats)
                if not mapped.get('category_distribution'):
                    mapped['category_distribution'] = {
                        'AI_RELATED': int(mapped.get('ai_related') or 0),
                        'NON_AI': int((mapped.get('total_analyzed') or 0) - (mapped.get('ai_related') or 0)),
                    }
            except Exception as e:
                logger.warning(f"DB fallback для ai statistics не сработал: {e}")

        return {'success': True, 'data': mapped}

    def _compute_ai_keyword_stats_from_db(self, max_rows: int = 300000, top_n: int = 30) -> Dict[str, Any]:
        """
        Считает статистику по реальным результатам анализа, сохранённым в legacy БД:
        - turn.etc (TEXT JSON) -> etc.ai_analysis.keyword_hits / attack_hits / confidence / is_ai_related
        """
        from models.database import DatabaseManager

        db = DatabaseManager()
        cur = db.connection.cursor()
        cur.execute(
            "SELECT etc FROM turn WHERE etc IS NOT NULL AND etc != '' AND etc ILIKE %s",
            ('%"ai_analysis"%',),
        )

        keyword_counter: Counter[str] = Counter()
        attack_counter: Counter[str] = Counter()
        total = 0
        ai_related = 0
        conf_sum = 0.0
        conf_count = 0

        def _norm_list(v: Any) -> List[str]:
            if v is None:
                return []
            if isinstance(v, list):
                return [str(x).strip() for x in v if str(x).strip()]
            if isinstance(v, str):
                s = v.strip()
                return [s] if s else []
            return [str(v).strip()] if str(v).strip() else []

        while total < max_rows:
            rows = cur.fetchmany(2000)
            if not rows:
                break
            for (etc_text,) in rows:
                if total >= max_rows:
                    break
                try:
                    etc = json.loads(etc_text) if isinstance(etc_text, str) else (etc_text or {})
                    if not isinstance(etc, dict):
                        continue
                    ai = etc.get('ai_analysis')
                    if not isinstance(ai, dict):
                        continue
                except Exception:
                    continue

                total += 1
                if bool(ai.get('is_ai_related')):
                    ai_related += 1

                for kw in _norm_list(ai.get('keyword_hits')):
                    keyword_counter[kw.lower()] += 1
                for atk in _norm_list(ai.get('attack_hits')):
                    attack_counter[atk.lower()] += 1

                conf = ai.get('confidence')
                try:
                    if conf is not None:
                        c = float(conf)
                        # нормализация: если это 0..1 -> переведём в проценты
                        if 0.0 <= c <= 1.0:
                            c *= 100.0
                        conf_sum += c
                        conf_count += 1
                except Exception:
                    pass

        cur.close()

        top_kw = [{'keyword': k, 'count': int(v)} for k, v in keyword_counter.most_common(top_n)]
        top_atk = [{'keyword': k, 'count': int(v)} for k, v in attack_counter.most_common(top_n)]
        keyword_dist = dict(keyword_counter)

        avg_conf = (conf_sum / conf_count) if conf_count else 0.0
        return {
            'total_analyzed': total,
            'ai_related': ai_related,
            'avg_confidence': float(avg_conf),
            'total_keywords': int(len(keyword_dist)),
            'keyword_distribution': keyword_dist,
            'top_keywords': top_kw,
            'top_attacks': top_atk,
        }
    
    # ========== УПРАВЛЕНИЕ ОБУЧЕНИЕМ ==========
    
    def start_training(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Запуск обучения модели
        
        Args:
            config: Конфигурация обучения (epochs, batch_size, learning_rate, training_scenario)
            
        Returns:
            Результат запуска
        """
        try:
            # Получаем уязвимости из БД для обучения
            from models.database import DatabaseManager
            from models.legacy_repositories import LegacyVulnerabilityRepository
            
            logger.info("📊 Подготовка данных для обучения из БД...")
            db = DatabaseManager()
            repo = LegacyVulnerabilityRepository(db.connection)
            
            # Получаем уязвимости для обучения (до 10000 для начала)
            training_vulns = repo.get_all_vulnerabilities(limit=10000)
            logger.info(f"📊 Получено {len(training_vulns)} уязвимостей для обучения")
            
            if not training_vulns:
                return {
                    'success': False,
                    'error': 'Нет данных для обучения. Сначала запустите парсинг уязвимостей.',
                    'hint': 'Используйте раздел "Парсинг" для загрузки уязвимостей'
                }
            
            # Подготавливаем данные для обучения на k8s-worker.
            # Важно: target_column = is_ai_related, поэтому нужно давать не только False.
            training_data = []
            # Примитивная разметка: по тегам + по ключевым словам (weak supervision).
            ai_keywords = [
                "artificial intelligence", "machine learning", "deep learning", "neural",
                "llm", "gpt", "bert", "transformer", "pytorch", "tensorflow",
                "prompt", "inference", "training", "fine-tune", "finetune",
                "model", "embedding", "vector", "rag", "agent"
            ]

            for vuln in training_vulns[:5000]:  # Ограничиваем для первого обучения
                tags = getattr(vuln, 'tags', []) or []
                text = f"{vuln.title or ''} {vuln.description or ''}".lower()
                tag_hit = any(str(t).strip().lower() in {'ai','ml','llm','model','neural','training'} for t in tags)
                kw_hit = any(k in text for k in ai_keywords)
                is_ai_related = bool(tag_hit or kw_hit)
                training_data.append({
                    'cve_id': getattr(vuln, 'cve_id', ''),
                    'title': vuln.title,
                    'description': vuln.description or '',
                    'severity': vuln.severity,
                    'cvss_score': vuln.cvss_score,
                    'tags': tags,
                    'is_ai_related': is_ai_related
                })
            
            # Подготовка конфигурации для ML платформы
            training_config = {
                'model_class': config.get('model_class', 'VulnerabilityClassifier'),
                'model_config': config.get('model_config', {
                    'input_size': 50,
                    'num_severity_classes': 5,
                    'num_attack_types': 28
                }),
                'training_data': training_data,  # Отправляем данные напрямую
                'epochs': config.get('epochs', 200),
                'batch_size': config.get('batch_size', 64),
                'learning_rate': config.get('learning_rate', 0.001),
                'optimizer': config.get('optimizer', 'adam'),
                'loss_function': config.get('loss_function', 'cross_entropy'),
                'early_stopping_patience': config.get('early_stopping_patience', 20),
                'target_column': config.get('target_column', 'is_ai_related'),
                'weights_path': config.get('weights_path'),
                'training_scenario': config.get('training_scenario', 'standard')
            }
            
            logger.info(f"🚀 Запуск обучения: epochs={training_config['epochs']}, batch_size={training_config['batch_size']}, lr={training_config['learning_rate']}, samples={len(training_data)}")
            
            return self._make_api_request('POST', '/training/start', training_config)
        except Exception as e:
            logger.error(f"❌ Ошибка подготовки данных для обучения: {e}", exc_info=True)
            return {
                'success': False,
                'error': f'Ошибка подготовки данных: {str(e)}'
            }
    
    def get_training_status(self, task_id: str) -> Dict[str, Any]:
        """
        Получение статуса обучения с детальным прогрессом эпох
        
        Args:
            task_id: ID задачи
            
        Returns:
            Статус с прогрессом эпох в формате для визуализации
        """
        result = self._make_api_request('GET', f'/training/status/{task_id}')
        
        if result['success']:
            status_data = result.get('data', {})
            status = status_data.get('status', 'unknown')
            progress = status_data.get('progress') or {}
            
            # Нормализация формата прогресса
            normalized_progress = {}
            
            # Если прогресс содержит историю эпох
            if isinstance(progress, dict):
                if 'history' in progress and isinstance(progress['history'], list):
                    history = progress['history']
                    if len(history) > 0:
                        latest = history[-1]
                        normalized_progress = {
                            'current_epoch': latest.get('epoch', len(history)),
                            'total_epochs': progress.get('total_epochs', len(history)),
                            'train_loss': latest.get('train_loss', latest.get('loss', 0)),
                            'val_loss': latest.get('val_loss', latest.get('validation_loss', 0)),
                            'train_accuracy': latest.get('train_accuracy', latest.get('accuracy', 0)),
                            'val_accuracy': latest.get('val_accuracy', latest.get('validation_accuracy', 0)),
                            'history': history  # Сохраняем всю историю для графиков
                        }
                
                # Если есть прямые метрики
                if 'current_epoch' not in normalized_progress:
                    normalized_progress.update({
                        'current_epoch': progress.get('epoch', progress.get('current_epoch', 0)),
                        'total_epochs': progress.get('total_epochs', progress.get('epochs', 0)),
                        'train_loss': progress.get('train_loss', progress.get('loss', 0)),
                        'val_loss': progress.get('val_loss', progress.get('validation_loss', 0)),
                        'train_accuracy': progress.get('train_accuracy', progress.get('accuracy', 0)),
                        'val_accuracy': progress.get('val_accuracy', progress.get('validation_accuracy', 0))
                    })
                
                # Добавляем финальные метрики если обучение завершено
                if status == 'completed' and 'final_metrics' in progress:
                    normalized_progress['final_metrics'] = progress['final_metrics']
            
            result['data'] = {
                'status': status,
                'progress': normalized_progress,
                'error': status_data.get('error'),
                'task_id': task_id
            }
        
        return result
    
    def get_training_history(self) -> Dict[str, Any]:
        """
        Получение истории обучения
        
        Returns:
            История
        """
        return self._make_api_request('GET', '/training/history')
    
    # ========== МОНИТОРИНГ САЙТОВ ==========
    
    def start_site_monitoring(self, sites: List[str]) -> Dict[str, Any]:
        """
        Запуск мониторинга сайтов
        
        Args:
            sites: Список сайтов для мониторинга
            
        Returns:
            Результат запуска
        """
        return self._make_api_request('POST', '/security/monitoring/start', {'sites': sites})
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """
        Получение статуса мониторинга
        
        Returns:
            Статус
        """
        return self._make_api_request('GET', '/security/monitoring/status')
    
    # ========== ПАСПОРТА УЯЗВИМОСТЕЙ ==========
    
    def get_cve_passport(self, cve_id: str) -> Dict[str, Any]:
        """
        Получение паспорта CVE
        
        Args:
            cve_id: ID CVE
            
        Returns:
            Паспорт
        """
        return self._make_api_request('GET', f'/security/cve/{cve_id}')
    
    def get_all_passports(self, limit: int = 100) -> Dict[str, Any]:
        """
        Получение всех паспортов
        
        Args:
            limit: Лимит
            
        Returns:
            Список паспортов
        """
        return self._make_api_request('GET', f'/security/passports?limit={limit}')
    
    # ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========
    
    def _vulnerability_to_dict(self, vuln) -> Dict[str, Any]:
        """Преобразование Vulnerability в словарь"""
        return {
            'id': vuln.id,
            'cve_id': getattr(vuln, 'cve_id', None),
            'title': vuln.title,
            'description': vuln.description,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'status': vuln.status,
            'created_date': vuln.created_date.isoformat() if vuln.created_date else None,
            'source': getattr(vuln, 'source_identifier', 'unknown')
        }
    
    def _save_analysis_results(self, results: Dict[str, Any]) -> None:
        """Сохранение результатов анализа в БД"""
        try:
            from models.database import DatabaseManager
            from models.legacy_repositories import LegacyVulnerabilityRepository
            
            db = DatabaseManager()
            repo = LegacyVulnerabilityRepository(db.connection)

            def _norm_tags(tags_any):
                try:
                    return repo._normalize_tags(tags_any)  # reuse canonical normalizer
                except Exception:
                    # fallback: best-effort
                    if tags_any is None:
                        return []
                    if isinstance(tags_any, str):
                        tags_any = [t.strip() for t in tags_any.split(',')]
                    if not isinstance(tags_any, list):
                        return []
                    out = []
                    seen = set()
                    for t in tags_any:
                        s = str(t).strip()
                        if not s:
                            continue
                        k = s.lower()
                        if k in seen:
                            continue
                        seen.add(k)
                        out.append(s[:40])
                    return out

            def _derive_tags_from_analysis(ai: Dict[str, Any]) -> List[str]:
                # Важно: тег "ml" должен означать принадлежность к AI/ML тематике,
                # а не просто факт того, что запись была обработана моделью.
                if not ai.get("is_ai_related"):
                    return []

                tags = ["ml", "ai"]

                hits = ai.get("keyword_hits") or []
                if isinstance(hits, str):
                    hits = [hits]
                hit_text = " ".join([str(x).lower() for x in hits])

                # high-signal tags
                if "llm" in hit_text or "gpt" in hit_text or "chatgpt" in hit_text:
                    tags.append("llm")
                if "prompt injection" in hit_text or "jailbreak" in hit_text:
                    tags.append("prompt-injection")
                if "poison" in hit_text or "data poisoning" in hit_text or "backdoor" in hit_text:
                    tags.append("data-poisoning")
                if "model extraction" in hit_text or "model stealing" in hit_text:
                    tags.append("model-extraction")
                if "embedding" in hit_text:
                    tags.append("embedding")
                if "rag" in hit_text or "retrieval" in hit_text:
                    tags.append("rag")
                if "agent" in hit_text:
                    tags.append("agent")
                if "pytorch" in hit_text:
                    tags.append("pytorch")
                if "tensorflow" in hit_text:
                    tags.append("tensorflow")
                if "onnx" in hit_text:
                    tags.append("onnx")
                if "cuda" in hit_text:
                    tags.append("cuda")

                # any explicit categories passed by ML platform
                cats = ai.get("categories") or []
                if isinstance(cats, str):
                    cats = [cats]
                for c in cats:
                    c = str(c).strip().lower().replace(" ", "-")
                    if c:
                        tags.append(c[:40])

                return _norm_tags(tags)

            with db.connection.cursor() as cursor:
                for result in results.get('results', []):
                    vuln_id = result.get('vulnerability_id')
                    if not vuln_id:
                        continue

                    # turn.etc может быть TEXT (JSON-строка), поэтому обновляем через merge (без jsonb_set)
                    cursor.execute("SELECT etc FROM turn WHERE id = %s", (vuln_id,))
                    row = cursor.fetchone()
                    try:
                        etc_data = json.loads(row[0]) if row and row[0] else {}
                        if not isinstance(etc_data, dict):
                            etc_data = {}
                    except Exception:
                        etc_data = {}

                    # сохраняем максимальную прозрачность (реальные поля от k8s-worker + наши input-метрики)
                    ai_analysis = {
                        "is_ai_related": bool(result.get("is_ai_related", False)),
                        "confidence": float(result.get("confidence", 0.0) or 0.0),
                        "ml_score": float(result.get("ml_score", 0.0) or 0.0) if result.get("ml_score") is not None else None,
                        "ai_context_score": float(result.get("ai_context_score", 0.0) or 0.0) if result.get("ai_context_score") is not None else None,
                        "prediction": result.get("prediction"),
                        "categories": result.get("categories", []),
                        "keyword_hits": result.get("keyword_hits", []),
                        "attack_hits": result.get("attack_hits", []),
                        "negative_hits": result.get("negative_hits", []),
                        "reasoning": result.get("reasoning", ""),
                        "input_text_len": result.get("input_text_len"),
                        "input_excerpt": result.get("input_excerpt"),
                        "decision_basis": "combined=0.7*ml_score+0.3*ai_context_score; ai_related if combined>=0.55 and (ctx>=0.15 or ml>=0.65)",
                        "analyzed_at": datetime.now().isoformat(),
                    }
                    etc_data["ai_analysis"] = ai_analysis

                    # автотеги: обязательный ml + категорийные
                    existing_tags = etc_data.get("tags", [])
                    merged = _norm_tags(existing_tags + _derive_tags_from_analysis(ai_analysis))
                    etc_data["tags"] = merged

                    cursor.execute("UPDATE turn SET etc = %s WHERE id = %s", (json.dumps(etc_data, ensure_ascii=False), vuln_id))
            
            db.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка сохранения результатов анализа: {e}")
    
    def check_connection(self) -> Dict[str, Any]:
        """
        Проверка подключения к ML платформе
        
        Returns:
            Статус подключения
        """
        try:
            # Проверка HTTP API
            api_status = self._make_api_request('GET', '/health')
            
            # Проверка SSH
            ssh_status = self._execute_ssh_command('echo "OK"')
            
            return {
                'success': api_status['success'] and ssh_status['success'],
                'api_available': api_status['success'],
                'ssh_available': ssh_status['success'],
                'api_url': self.ml_api_url,
                'vm_host': self.vm_host
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


# Глобальный экземпляр клиента
ml_platform_client = MLPlatformClient()

