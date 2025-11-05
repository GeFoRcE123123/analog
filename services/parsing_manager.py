import threading
import time
import json
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum


class ParsingStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"


class ParsingProgressManager:
    """Менеджер для отслеживания прогресса парсинга с реальным временем"""

    _instance = None
    _progress_data: Dict[str, Any] = {}
    _vulnerability_callbacks: List[Callable] = []

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ParsingProgressManager, cls).__new__(cls)
            cls._instance._init_manager()
        return cls._instance

    def _init_manager(self):
        """Инициализация менеджера"""
        self.logger = logging.getLogger(__name__)
        self._progress_data = {
            'status': ParsingStatus.PENDING.value,
            'progress': 0,
            'message': 'Готов к парсингу',
            'current_step': '',
            'total_steps': 0,
            'current_step_number': 0,
            'start_time': None,
            'end_time': None,
            'vulnerabilities_found': 0,
            'vulnerabilities_saved': 0,
            'error': None,
            'recent_vulnerabilities': []  # Уязвимости добавленные во время этого парсинга
        }
        self._vulnerability_callbacks = []

    def add_vulnerability_callback(self, callback: Callable):
        """Добавить callback для уведомлений о новых уязвимостях"""
        if callback not in self._vulnerability_callbacks:
            self._vulnerability_callbacks.append(callback)

    def remove_vulnerability_callback(self, callback: Callable):
        """Удалить callback"""
        if callback in self._vulnerability_callbacks:
            self._vulnerability_callbacks.remove(callback)

    def notify_vulnerability_added(self, vulnerability_data: Dict[str, Any]):
        """Уведомить о добавленной уязвимости"""
        # Добавляем в список недавно добавленных
        if 'recent_vulnerabilities' not in self._progress_data:
            self._progress_data['recent_vulnerabilities'] = []

        self._progress_data['recent_vulnerabilities'].append(vulnerability_data)

        # Уведомляем все callback'и
        for callback in self._vulnerability_callbacks:
            try:
                callback(vulnerability_data)
            except Exception as e:
                self.logger.error(f"Ошибка в callback уязвимости: {e}")

    def start_parsing(self, total_steps: int = 5):
        """Начать новый процесс парсинга"""
        self._progress_data = {
            'status': ParsingStatus.RUNNING.value,
            'progress': 0,
            'message': 'Начало парсинга...',
            'current_step': 'initialization',
            'total_steps': total_steps,
            'current_step_number': 0,
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'vulnerabilities_found': 0,
            'vulnerabilities_saved': 0,
            'error': None,
            'recent_vulnerabilities': []  # Очищаем список для нового парсинга
        }

    def update_progress(self, progress: int, message: str, current_step: str = None):
        """Обновить прогресс парсинга"""
        if current_step:
            self._progress_data['current_step'] = current_step
            self._progress_data['current_step_number'] += 1

        self._progress_data['progress'] = max(0, min(100, progress))
        self._progress_data['message'] = message

        self.logger.info(f"Progress: {progress}% - {message}")

    def update_vulnerability_stats(self, found: int = 0, saved: int = 0):
        """Обновить статистику по уязвимостям"""
        if found > 0:
            self._progress_data['vulnerabilities_found'] = found
        if saved > 0:
            self._progress_data['vulnerabilities_saved'] = saved

    def complete_parsing(self, message: str = "Парсинг завершен"):
        """Завершить парсинг успешно"""
        self._progress_data.update({
            'status': ParsingStatus.COMPLETED.value,
            'progress': 100,
            'message': message,
            'end_time': datetime.now().isoformat()
        })

    def error_parsing(self, error_message: str):
        """Завершить парсинг с ошибкой"""
        self._progress_data.update({
            'status': ParsingStatus.ERROR.value,
            'message': 'Ошибка парсинга',
            'error': error_message,
            'end_time': datetime.now().isoformat()
        })

    def get_progress(self) -> Dict[str, Any]:
        """Получить текущий прогресс"""
        return self._progress_data.copy()

    def reset(self):
        """Сбросить менеджер прогресса"""
        self._init_manager()


class AsyncParser:
    """Асинхронный парсер с реальным временем добавления уязвимостей"""

    def __init__(self):
        self.progress_manager = ParsingProgressManager()
        self.parsing_thread = None
        self.is_running = False
        self.recently_added_vulnerabilities = []

    def _run_parsing(self):
        """Основная логика парсинга в отдельном потоке"""
        try:
            from services.fast_osv_parser import fast_parse_ai_vulnerabilities_with_status

            # Инициализация парсинга
            self.progress_manager.start_parsing(total_steps=6)
            self.progress_manager.update_progress(5, "Инициализация...")

            # Запуск AI парсинга с callback для реального времени
            def on_vulnerability_parsed(vuln_data):
                """Callback вызывается при парсинге каждой уязвимости"""
                self._handle_new_vulnerability(vuln_data)

            result = fast_parse_ai_vulnerabilities_with_status(
                self.progress_manager,
                on_vulnerability_parsed  # Передаем callback
            )

            # Завершение
            if result['success']:
                final_msg = f"🎯 AI парсинг завершен! Сохранено {result['count']} уязвимостей"
                self.progress_manager.complete_parsing(final_msg)
            else:
                self.progress_manager.error_parsing(result['message'])

        except Exception as e:
            error_message = f"❌ Ошибка при AI парсинге: {str(e)}"
            self.progress_manager.error_parsing(error_message)
            logging.error(error_message)
        finally:
            self.is_running = False

    def _handle_new_vulnerability(self, vuln_data: Dict[str, Any]):
        """Обработать новую уязвимость в реальном времени"""
        try:
            # Сохраняем для истории
            self.recently_added_vulnerabilities.append(vuln_data)

            # Уведомляем менеджер прогресса
            self.progress_manager.notify_vulnerability_added(vuln_data)

            # Логируем
            logger.info(f"✅ Добавлена уязвимость: {vuln_data.get('title', 'Unknown')}")

        except Exception as e:
            logger.error(f"Ошибка обработки новой уязвимости: {e}")

    def start_async_parsing(self):
        """Запустить парсинг в отдельном потоке"""
        if self.is_running:
            return False

        self.is_running = True
        self.parsing_thread = threading.Thread(target=self._run_parsing)
        self.parsing_thread.daemon = True
        self.parsing_thread.start()
        return True

    def get_parsing_status(self) -> Dict[str, Any]:
        """Получить статус парсинга"""
        return self.progress_manager.get_progress()

    def is_parsing_active(self) -> bool:
        """Проверить, активен ли парсинг"""
        return self.is_running

    def get_recent_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Получить недавно добавленные уязвимости"""
        return self.recently_added_vulnerabilities.copy()