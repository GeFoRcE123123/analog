"""
WebSocket менеджер для отслеживания прогресса обучения
"""

from fastapi import WebSocket
from typing import Dict, List, Optional
import json
import asyncio


class WebSocketManager:
    """Менеджер WebSocket соединений"""
    
    def __init__(self):
        """Инициализация менеджера"""
        self.active_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, task_id: str):
        """
        Подключение WebSocket клиента
        
        Args:
            websocket: WebSocket соединение
            task_id: ID задачи обучения
        """
        await websocket.accept()
        
        if task_id not in self.active_connections:
            self.active_connections[task_id] = []
        
        self.active_connections[task_id].append(websocket)
    
    def disconnect(self, task_id: str, websocket: Optional[WebSocket] = None):
        """
        Отключение WebSocket клиента
        
        Args:
            task_id: ID задачи обучения
            websocket: WebSocket соединение (если None, отключаются все)
        """
        if task_id not in self.active_connections:
            return
        
        if websocket:
            if websocket in self.active_connections[task_id]:
                self.active_connections[task_id].remove(websocket)
        else:
            self.active_connections[task_id].clear()
        
        if not self.active_connections[task_id]:
            del self.active_connections[task_id]
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """
        Отправка личного сообщения
        
        Args:
            message: Сообщение для отправки
            websocket: WebSocket соединение
        """
        try:
            await websocket.send_text(json.dumps(message))
        except Exception:
            pass  # Соединение закрыто
    
    async def broadcast_progress(self, task_id: str, progress: dict):
        """
        Рассылка прогресса всем подключенным клиентам
        
        Args:
            task_id: ID задачи обучения
            progress: Данные прогресса
        """
        if task_id not in self.active_connections:
            return
        
        message = {
            "type": "progress",
            "task_id": task_id,
            "data": progress
        }
        
        disconnected = []
        for websocket in self.active_connections[task_id]:
            try:
                await websocket.send_text(json.dumps(message))
            except Exception:
                disconnected.append(websocket)
        
        # Удаление отключенных соединений
        for ws in disconnected:
            self.disconnect(task_id, ws)
    
    async def broadcast_status(self, task_id: str, status: str, error: Optional[str] = None):
        """
        Рассылка статуса
        
        Args:
            task_id: ID задачи обучения
            status: Статус (completed, failed)
            error: Сообщение об ошибке (если есть)
        """
        if task_id not in self.active_connections:
            return
        
        message = {
            "type": "status",
            "task_id": task_id,
            "status": status,
            "error": error
        }
        
        disconnected = []
        for websocket in self.active_connections[task_id]:
            try:
                await websocket.send_text(json.dumps(message))
            except Exception:
                disconnected.append(websocket)
        
        for ws in disconnected:
            self.disconnect(task_id, ws)
