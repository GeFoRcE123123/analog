"""
Модуль для хранения статуса синхронизации CVE
Используется для передачи данных о прогрессе на фронтенд
"""

import threading
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class SyncStatus:
    """Статус синхронизации CVE"""
    status: str = 'idle'  # idle, running, completed, error
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_cves: int = 0
    processed_cves: int = 0
    saved_cves: int = 0
    current_batch: int = 0
    total_batches: int = 0
    progress_percent: float = 0.0
    errors: list = field(default_factory=list)
    last_update: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь для JSON"""
        result = asdict(self)
        # Конвертируем datetime в строки
        if self.start_time:
            result['start_time'] = self.start_time.isoformat()
        if self.end_time:
            result['end_time'] = self.end_time.isoformat()
        if self.last_update:
            result['last_update'] = self.last_update.isoformat()
        return result
    
    def update_progress(self, processed: int, saved: int, batch: int, total_batches: int):
        """Обновление прогресса"""
        self.processed_cves = processed
        self.saved_cves = saved
        self.current_batch = batch
        self.total_batches = total_batches
        if self.total_cves > 0:
            self.progress_percent = (saved / self.total_cves) * 100
        self.last_update = datetime.now()


# Глобальный статус синхронизации (thread-safe)
_sync_status = SyncStatus()
_status_lock = threading.Lock()


def get_sync_status() -> SyncStatus:
    """Получить текущий статус синхронизации"""
    with _status_lock:
        return _sync_status


def update_sync_status(**kwargs):
    """Обновить статус синхронизации"""
    with _status_lock:
        for key, value in kwargs.items():
            if hasattr(_sync_status, key):
                setattr(_sync_status, key, value)
        _sync_status.last_update = datetime.now()


def reset_sync_status():
    """Сбросить статус синхронизации"""
    with _status_lock:
        global _sync_status
        _sync_status = SyncStatus()


def start_sync(total_cves: int):
    """Начать синхронизацию"""
    with _status_lock:
        _sync_status.status = 'running'
        _sync_status.start_time = datetime.now()
        _sync_status.end_time = None
        _sync_status.total_cves = total_cves
        _sync_status.processed_cves = 0
        _sync_status.saved_cves = 0
        _sync_status.current_batch = 0
        _sync_status.errors = []
        _sync_status.last_update = datetime.now()


def complete_sync(saved_cves: int):
    """Завершить синхронизацию"""
    with _status_lock:
        _sync_status.status = 'completed'
        _sync_status.end_time = datetime.now()
        _sync_status.saved_cves = saved_cves
        _sync_status.processed_cves = saved_cves
        _sync_status.progress_percent = 100.0
        _sync_status.last_update = datetime.now()


def error_sync(error_message: str):
    """Установить ошибку синхронизации"""
    with _status_lock:
        _sync_status.status = 'error'
        _sync_status.end_time = datetime.now()
        _sync_status.errors.append({
            'message': error_message,
            'timestamp': datetime.now().isoformat()
        })
        _sync_status.last_update = datetime.now()

