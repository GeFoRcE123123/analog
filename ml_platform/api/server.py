"""
FastAPI сервер для платформы обучения моделей
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import asyncio
import json
import uuid
from pathlib import Path

from ml_platform.core.config_manager import ConfigManager
from ml_platform.core.logger import PlatformLogger
from ml_platform.core.model_trainer import ModelTrainer
from ml_platform.core.data_loader import DataLoader
from ml_platform.utils.prometheus_metrics import MetricsCollector
from ml_platform.api.websocket import WebSocketManager
from ml_platform.security.api.security_api import router as security_router
from ml_platform.security.api.ai_security_api import router as ai_security_router


app = FastAPI(title="ML Platform API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Инициализация компонентов
config = ConfigManager()
logger = PlatformLogger.get_logger()
metrics = MetricsCollector()
ws_manager = WebSocketManager()

# Хранилище активных задач обучения
active_trainings: Dict[str, Dict[str, Any]] = {}

# Подключение security API
app.include_router(security_router)
app.include_router(ai_security_router)


class TrainingRequest(BaseModel):
    """Запрос на обучение модели"""
    model_class: str
    model_config: Dict[str, Any]
    data_path: Optional[str] = None  # Опционально, если передается training_data
    training_data: Optional[List[Dict[str, Any]]] = None  # Данные для обучения напрямую
    target_column: Optional[str] = None
    epochs: int = 100
    batch_size: int = 32
    learning_rate: float = 0.001
    optimizer: str = "adam"
    loss_function: str = "cross_entropy"
    weights_path: Optional[str] = None
    early_stopping_patience: Optional[int] = None
    training_scenario: Optional[str] = None


class TrainingStatus(BaseModel):
    """Статус обучения"""
    task_id: str
    status: str  # pending, running, completed, failed
    progress: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@app.on_event("startup")
async def startup_event():
    """Инициализация при запуске"""
    logger.info("ML Platform API сервер запущен")


@app.on_event("shutdown")
async def shutdown_event():
    """Очистка при остановке"""
    logger.info("ML Platform API сервер остановлен")


@app.get("/")
async def root():
    """Корневой endpoint"""
    return {
        "service": "ML Platform API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Проверка здоровья сервиса"""
    return {"status": "healthy"}


@app.get("/gpu/status")
async def gpu_status():
    """Статус GPU"""
    from ml_platform.core.gpu_manager import GPUManager
    gpu_manager = GPUManager()
    
    cuda_available = gpu_manager.check_cuda_available()
    gpu_info = gpu_manager.get_gpu_info()
    
    metrics.record_gpu_available(cuda_available)
    
    return {
        "cuda_available": cuda_available,
        "gpu_info": gpu_info
    }


@app.post("/training/start", response_model=TrainingStatus)
async def start_training(request: TrainingRequest):
    """
    Запуск обучения модели
    
    Args:
        request: Параметры обучения
        
    Returns:
        Статус задачи обучения
    """
    task_id = str(uuid.uuid4())
    
    # Валидация: должен быть либо data_path, либо training_data
    if not request.training_data and (not request.data_path or not Path(request.data_path).exists()):
        if request.training_data is None:
            raise HTTPException(status_code=400, detail="training_data required")
        raise HTTPException(status_code=400, detail=f"Файл данных не найден: {request.data_path}")
    
    # Создание задачи
    active_trainings[task_id] = {
        "status": "pending",
        "request": request.dict(),
        "progress": None,
        "error": None
    }
    
    # Запуск обучения в фоне
    asyncio.create_task(run_training(task_id, request))
    
    metrics.record_training_start()
    
    return TrainingStatus(
        task_id=task_id,
        status="pending"
    )


async def run_training(task_id: str, request: TrainingRequest):
    """Запуск обучения в фоновом режиме"""
    try:
        active_trainings[task_id]["status"] = "running"
        
        # Импорт модели (упрощенная версия - в реальности нужен более сложный механизм)
        # Здесь предполагается, что модель будет передана через API или загружена из модуля
        
        # Загрузка данных
        data_loader = DataLoader()
        
        # Если переданы данные напрямую, сохраняем во временный файл
        if request.training_data:
            import tempfile
            import json
            import pandas as pd
            
            # Создаем временный файл
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(request.training_data, temp_file)
            temp_file.close()
            
            # Конвертируем в CSV для DataLoader
            df = pd.DataFrame(request.training_data)
            csv_path = temp_file.name.replace('.json', '.csv')
            df.to_csv(csv_path, index=False)
            
            data_path = csv_path
            logger.info(f"📊 Использованы переданные данные: {len(request.training_data)} записей")
        else:
            data_path = request.data_path
        
        train_loader, val_loader, test_loader = data_loader.load_and_prepare(
            data_path,
            target_column=request.target_column,
            batch_size=request.batch_size
        )
        
        # Создание модели (упрощенно - нужна фабрика моделей)
        # Для примера используем простую модель
        import torch.nn as nn
        
        # Определение размера входных данных
        sample_input, _ = next(iter(train_loader))
        input_size = sample_input.shape[1]
        
        # Простая модель для примера
        model = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 2)  # Предполагаем бинарную классификацию
        )
        
        # Создание тренера
        trainer = ModelTrainer(config=config)
        trainer.prepare_model(model, weights_path=request.weights_path)
        
        # Callback для прогресса
        def progress_callback(progress: Dict[str, Any]):
            active_trainings[task_id]["progress"] = progress
            # Отправка через WebSocket
            ws_manager.broadcast_progress(task_id, progress)
        
        # Обучение
        results = trainer.train(
            train_loader=train_loader,
            val_loader=val_loader,
            epochs=request.epochs,
            learning_rate=request.learning_rate,
            optimizer_type=request.optimizer,
            loss_type=request.loss_function,
            early_stopping_patience=request.early_stopping_patience,
            progress_callback=progress_callback
        )
        
        # Оценка на тесте
        test_results = trainer.evaluate_on_test(test_loader)
        
        # Сохранение модели
        models_dir = Path(config.get('paths.models_dir', '/home/user/projects/models'))
        model_path = models_dir / f"model_{task_id}.pth"
        trainer.save_model(str(model_path))
        
        # Обновление статуса
        active_trainings[task_id]["status"] = "completed"
        active_trainings[task_id]["progress"] = {
            **results,
            "test_results": test_results,
            "model_path": str(model_path)
        }
        
        metrics.record_training_complete("success")
        metrics.record_training_duration(results.get('training_time', 0))
        
        logger.info(f"Обучение завершено: task_id={task_id}")
        
    except Exception as e:
        active_trainings[task_id]["status"] = "failed"
        active_trainings[task_id]["error"] = str(e)
        metrics.record_training_complete("failed")
        logger.error(f"Ошибка обучения: task_id={task_id}, error={e}")


@app.get("/training/status/{task_id}", response_model=TrainingStatus)
async def get_training_status(task_id: str):
    """
    Получение статуса обучения
    
    Args:
        task_id: ID задачи
        
    Returns:
        Статус обучения
    """
    if task_id not in active_trainings:
        raise HTTPException(status_code=404, detail="Задача не найдена")
    
    task = active_trainings[task_id]
    return TrainingStatus(
        task_id=task_id,
        status=task["status"],
        progress=task.get("progress"),
        error=task.get("error")
    )


@app.get("/training/list")
async def list_trainings():
    """Список всех задач обучения"""
    return {
        "tasks": [
            {
                "task_id": task_id,
                "status": task["status"],
                "created_at": task.get("created_at")
            }
            for task_id, task in active_trainings.items()
        ]
    }


@app.websocket("/ws/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    """WebSocket endpoint для отслеживания прогресса"""
    await ws_manager.connect(websocket, task_id)
    try:
        while True:
            data = await websocket.receive_text()
            # Эхо для поддержания соединения
            await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(task_id)


@app.get("/metrics")
async def get_metrics():
    """Prometheus метрики"""
    return Response(
        content=metrics.get_metrics(),
        media_type="text/plain"
    )


def main():
    """Точка входа для запуска сервера"""
    import uvicorn
    config = ConfigManager()
    uvicorn.run(
        app,
        host=config.get("api.host", "0.0.0.0"),
        port=config.get("api.port", 8000)
    )


if __name__ == "__main__":
    main()
