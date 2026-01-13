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

logger = logging.getLogger(__name__)


class MLPlatformClient:
    """Клиент для взаимодействия с ML платформой на k8s-worker"""
    
    def __init__(self):
        # Настройки подключения к k8s-worker
        self.vm_host = "10.0.88.25"
        self.vm_user = "k8s-worker"
        self.vm_password = "k8s-worker"
        self.ml_api_url = f"http://{self.vm_host}:8000"  # FastAPI на k8s-worker
        self.ssh_port = 22
        self.jupyter_port = 8888
        
        # Настройки подключения к БД проекта
        from config import Config
        self.db_config = Config.DATABASE_CONFIG
        
        # Настройки батчинга для анализа (из конфига)
        self.max_analysis_batch = Config.ML_ANALYSIS_MAX_BATCH  # Максимальное количество уязвимостей для анализа за раз
        self.analysis_timeout = Config.ML_ANALYSIS_TIMEOUT  # Таймаут для анализа (секунды)
        self.ml_batch_size = 5000  # Размер батча для отправки на ML платформу (чтобы не перегружать)
        
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
            
            # Отправляем на ML платформу для анализа
            # Используем batch-analyze endpoint с CVE IDs
            cve_ids = [v.get('cve_id') for v in vulnerabilities if v.get('cve_id')]
            
            # Фильтруем пустые CVE ID
            cve_ids = [cve_id for cve_id in cve_ids if cve_id and cve_id.strip()]
            
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
                    url = f"{self.ml_api_url}/security/ai/batch-analyze"
                    response = requests.post(
                        url,
                        json=batch_cve_ids,  # Отправляем батч
                        headers={'Content-Type': 'application/json'},
                        timeout=self.analysis_timeout  # Увеличенный таймаут для большого количества
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
        if result['success']:
            # Преобразуем формат для совместимости
            stats = result.get('data', {})
            return {
                'success': True,
                'data': {
                    'total_analyzed': stats.get('total_cves', 0),
                    'ai_related': stats.get('ai_related_count', 0),
                    'avg_confidence': 0.0,  # TODO: добавить в ML платформу
                    'total_keywords': len(stats.get('category_distribution', {})),
                    'category_distribution': stats.get('category_distribution', {})
                }
            }
        return result
    
    # ========== УПРАВЛЕНИЕ ОБУЧЕНИЕМ ==========
    
    def start_training(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Запуск обучения модели
        
        Args:
            config: Конфигурация обучения
            
        Returns:
            Результат запуска
        """
        return self._make_api_request('POST', '/training/start', config)
    
    def get_training_status(self, task_id: str) -> Dict[str, Any]:
        """
        Получение статуса обучения
        
        Args:
            task_id: ID задачи
            
        Returns:
            Статус
        """
        return self._make_api_request('GET', f'/training/status/{task_id}')
    
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
            
            db = DatabaseManager()
            with db.connection.cursor() as cursor:
                for result in results.get('results', []):
                    vuln_id = result.get('vulnerability_id')
                    if not vuln_id:
                        continue
                    
                    # Обновляем уязвимость с результатами анализа
                    cursor.execute("""
                        UPDATE turn 
                        SET etc = jsonb_set(
                            COALESCE(etc, '{}'::jsonb),
                            '{ai_analysis}',
                            %s::jsonb
                        )
                        WHERE id = %s
                    """, (
                        json.dumps({
                            'is_ai_related': result.get('is_ai_related', False),
                            'confidence': result.get('confidence', 0.0),
                            'categories': result.get('categories', []),
                            'reasoning': result.get('reasoning', ''),
                            'analyzed_at': datetime.now().isoformat()
                        }),
                        vuln_id
                    ))
            
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

