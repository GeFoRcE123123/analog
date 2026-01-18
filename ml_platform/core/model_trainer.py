"""
Основной класс для обучения нейросетевых моделей
Реализует полный алгоритм обучения согласно UML-диаграмме
"""

import torch
import torch.nn as nn
import torch.optim as optim
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable, Tuple
import numpy as np
import time

from ml_platform.core.logger import PlatformLogger
from ml_platform.core.gpu_manager import GPUManager
from ml_platform.core.data_loader import DataLoader
from ml_platform.core.model_validator import ModelValidator
from ml_platform.core.visualization import Visualization
from ml_platform.core.config_manager import ConfigManager


class ModelTrainer:
    """Основной класс для обучения нейросетевых моделей"""
    
    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        model: Optional[nn.Module] = None,
        device: Optional[torch.device] = None
    ):
        """
        Инициализация тренера
        
        Args:
            config: Менеджер конфигурации
            model: Модель для обучения (опционально)
            device: Устройство для вычислений (опционально)
        """
        self.config = config or ConfigManager()
        self.logger = PlatformLogger.get_logger()
        self.gpu_manager = GPUManager(
            min_memory_gb=self.config.get('gpu.min_memory_gb', 2.0),
            auto_clear_cache=self.config.get('gpu.auto_clear_cache', True)
        )
        self.data_loader = DataLoader(
            train_split=self.config.get('data.train_split', 0.7),
            val_split=self.config.get('data.val_split', 0.15),
            test_split=self.config.get('data.test_split', 0.15),
            normalize=self.config.get('data.normalize', True)
        )
        self.validator = ModelValidator()
        self.visualizer = Visualization(
            output_dir=self.config.get('paths.models_dir', '/home/user/projects/models')
        )
        
        # Устройство
        if device is None:
            self.device = self.gpu_manager.prepare_device()
        else:
            self.device = device
        
        # Модель
        self.model = model
        
        # История обучения
        self.training_history: Dict[str, List[float]] = {
            'train_loss': [],
            'val_loss': [],
            'train_accuracy': [],
            'val_accuracy': []
        }
        
        # Лучшие веса
        self.best_weights: Optional[Dict[str, torch.Tensor]] = None
        self.best_accuracy: float = 0.0
        self.best_epoch: int = 0
    
    def validate_script_syntax(self, script_path: str) -> Tuple[bool, Optional[str]]:
        """
        Проверка синтаксиса скрипта
        
        Args:
            script_path: Путь к скрипту
            
        Returns:
            Tuple (валиден ли скрипт, сообщение об ошибке)
        """
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            compile(code, script_path, 'exec')
            return True, None
        except SyntaxError as e:
            return False, f"Синтаксическая ошибка: {e}"
        except Exception as e:
            return False, f"Ошибка при проверке скрипта: {e}"
    
    def load_model_weights(self, weights_path: str) -> bool:
        """
        Загрузка предобученных весов
        
        Args:
            weights_path: Путь к файлу весов
            
        Returns:
            True если загрузка успешна
        """
        if not Path(weights_path).exists():
            self.logger.warning(f"Файл весов не найден: {weights_path}")
            return False
        
        try:
            self.logger.info(f"Загрузка весов из {weights_path}")
            checkpoint = torch.load(weights_path, map_location=self.device)
            
            if isinstance(checkpoint, dict) and 'state_dict' in checkpoint:
                self.model.load_state_dict(checkpoint['state_dict'])
            else:
                self.model.load_state_dict(checkpoint)
            
            self.logger.info("Веса успешно загружены")
            return True
        except Exception as e:
            self.logger.error(f"Ошибка при загрузке весов: {e}")
            return False
    
    def initialize_model_weights(self):
        """Инициализация случайных весов модели"""
        self.logger.info("Инициализация случайных весов")
        for param in self.model.parameters():
            if len(param.shape) >= 2:
                nn.init.xavier_uniform_(param)
            else:
                nn.init.zeros_(param)
    
    def prepare_model(
        self,
        model: nn.Module,
        weights_path: Optional[str] = None
    ) -> nn.Module:
        """
        Подготовка модели к обучению
        
        Args:
            model: Модель PyTorch
            weights_path: Путь к предобученным весам (опционально)
            
        Returns:
            Подготовленная модель
        """
        self.model = model
        
        # Валидация архитектуры
        is_valid, error_msg = self.validator.validate_model_architecture(model)
        if not is_valid:
            raise ValueError(f"Модель невалидна: {error_msg}")
        
        # Загрузка или инициализация весов
        if weights_path and Path(weights_path).exists():
            if not self.load_model_weights(weights_path):
                self.logger.info("Загрузка весов не удалась, инициализация случайных весов")
                self.initialize_model_weights()
        else:
            self.initialize_model_weights()
        
        # Перемещение на устройство
        self.model = self.gpu_manager.move_to_device(self.model, self.device)
        self.logger.info(f"Модель перемещена на {self.device}")
        
        return self.model
    
    def create_optimizer(
        self,
        learning_rate: float,
        optimizer_type: str = 'adam'
    ) -> optim.Optimizer:
        """
        Создание оптимизатора
        
        Args:
            learning_rate: Скорость обучения
            optimizer_type: Тип оптимизатора ('adam', 'sgd')
            
        Returns:
            Оптимизатор
        """
        if optimizer_type.lower() == 'adam':
            optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        elif optimizer_type.lower() == 'sgd':
            optimizer = optim.SGD(self.model.parameters(), lr=learning_rate, momentum=0.9)
        else:
            raise ValueError(f"Неподдерживаемый тип оптимизатора: {optimizer_type}")
        
        self.logger.info(f"Создан оптимизатор: {optimizer_type}, lr={learning_rate}")
        return optimizer
    
    def create_criterion(self, loss_type: str = 'cross_entropy') -> nn.Module:
        """
        Создание функции потерь
        
        Args:
            loss_type: Тип функции потерь ('cross_entropy', 'mse')
            
        Returns:
            Функция потерь
        """
        if loss_type.lower() == 'cross_entropy':
            criterion = nn.CrossEntropyLoss()
        elif loss_type.lower() == 'mse':
            criterion = nn.MSELoss()
        else:
            raise ValueError(f"Неподдерживаемый тип функции потерь: {loss_type}")
        
        self.logger.info(f"Создана функция потерь: {loss_type}")
        return criterion
    
    def train_epoch(
        self,
        train_loader: torch.utils.data.DataLoader,
        optimizer: optim.Optimizer,
        criterion: nn.Module
    ) -> Tuple[float, float]:
        """
        Обучение на одной эпохе
        
        Args:
            train_loader: DataLoader с обучающими данными
            optimizer: Оптимизатор
            criterion: Функция потерь
            
        Returns:
            Tuple (средняя потеря, точность)
        """
        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        num_batches = 0
        
        for batch_idx, batch in enumerate(train_loader):
            # Подготовка батча
            if len(batch) == 2:
                inputs, targets = batch
                inputs = self.gpu_manager.move_to_device(inputs, self.device)
                targets = self.gpu_manager.move_to_device(targets, self.device)
            else:
                inputs = self.gpu_manager.move_to_device(batch[0], self.device)
                targets = None
            
            # Проверка размера батча
            if inputs.size(0) == 0:
                self.logger.warning("Пустой батч, пропуск")
                continue
            
            # Прямой проход
            optimizer.zero_grad()
            outputs = self.model(inputs)
            
            if targets is None:
                # Для unsupervised learning
                loss = outputs.mean() if outputs.numel() > 0 else torch.tensor(0.0)
            else:
                loss = criterion(outputs, targets)
            
            # Проверка на численную стабильность
            if not torch.isfinite(loss) or torch.isnan(loss):
                self.logger.error(f"Нестабильная потеря на батче {batch_idx}: {loss.item()}")
                continue
            
            # Обратное распространение
            loss.backward()
            optimizer.step()
            
            # Статистика
            total_loss += loss.item()
            num_batches += 1
            
            if targets is not None:
                if outputs.dim() > 1:
                    predictions = torch.argmax(outputs, dim=1)
                else:
                    predictions = (outputs > 0.5).long()
                correct += (predictions == targets).sum().item()
                total += targets.size(0)
        
        avg_loss = total_loss / num_batches if num_batches > 0 else 0.0
        accuracy = correct / total if total > 0 else 0.0
        
        return avg_loss, accuracy
    
    def validate_epoch(
        self,
        val_loader: torch.utils.data.DataLoader,
        criterion: nn.Module
    ) -> Tuple[float, float]:
        """
        Валидация на одной эпохе
        
        Args:
            val_loader: DataLoader с валидационными данными
            criterion: Функция потерь
            
        Returns:
            Tuple (средняя потеря, точность)
        """
        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0
        num_batches = 0
        
        with torch.no_grad():
            for batch in val_loader:
                if len(batch) == 2:
                    inputs, targets = batch
                    inputs = self.gpu_manager.move_to_device(inputs, self.device)
                    targets = self.gpu_manager.move_to_device(targets, self.device)
                else:
                    inputs = self.gpu_manager.move_to_device(batch[0], self.device)
                    targets = None
                
                outputs = self.model(inputs)
                
                if targets is None:
                    loss = outputs.mean() if outputs.numel() > 0 else torch.tensor(0.0)
                else:
                    loss = criterion(outputs, targets)
                
                total_loss += loss.item()
                num_batches += 1
                
                if targets is not None:
                    if outputs.dim() > 1:
                        predictions = torch.argmax(outputs, dim=1)
                    else:
                        predictions = (outputs > 0.5).long()
                    correct += (predictions == targets).sum().item()
                    total += targets.size(0)
        
        avg_loss = total_loss / num_batches if num_batches > 0 else 0.0
        accuracy = correct / total if total > 0 else 0.0
        
        return avg_loss, accuracy
    
    def train(
        self,
        train_loader: torch.utils.data.DataLoader,
        val_loader: torch.utils.data.DataLoader,
        epochs: int,
        learning_rate: float = 0.001,
        optimizer_type: str = 'adam',
        loss_type: str = 'cross_entropy',
        early_stopping_patience: Optional[int] = None,
        save_best: bool = True,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Полный цикл обучения модели
        
        Args:
            train_loader: DataLoader с обучающими данными
            val_loader: DataLoader с валидационными данными
            epochs: Количество эпох
            learning_rate: Скорость обучения
            optimizer_type: Тип оптимизатора
            loss_type: Тип функции потерь
            early_stopping_patience: Терпение для early stopping
            save_best: Сохранять ли лучшие веса
            progress_callback: Callback для отслеживания прогресса
            
        Returns:
            Словарь с результатами обучения
        """
        if self.model is None:
            raise ValueError("Модель не инициализирована")
        
        # Настройка параметров
        patience = early_stopping_patience or self.config.get('training.early_stopping_patience', 10)
        save_best = save_best or self.config.get('training.save_best_only', True)
        
        # Создание оптимизатора и функции потерь
        optimizer = self.create_optimizer(learning_rate, optimizer_type)
        criterion = self.create_criterion(loss_type)
        
        # Инициализация счетчиков
        epoch = 0
        bad_epochs = 0
        
        self.logger.log_training_start(
            model_name=str(type(self.model).__name__),
            epochs=epochs,
            batch_size=train_loader.batch_size
        )
        
        start_time = time.time()
        
        # Цикл обучения
        while epoch < epochs:
            epoch += 1
            
            # Обучение
            train_loss, train_accuracy = self.train_epoch(train_loader, optimizer, criterion)
            
            # Валидация
            val_loss, val_accuracy = self.validate_epoch(val_loader, criterion)
            
            # Сохранение истории
            self.training_history['train_loss'].append(train_loss)
            self.training_history['val_loss'].append(val_loss)
            self.training_history['train_accuracy'].append(train_accuracy)
            self.training_history['val_accuracy'].append(val_accuracy)
            
            # Логирование
            self.logger.log_epoch(epoch, train_loss, train_accuracy, val_loss, val_accuracy)
            
            # Проверка улучшения
            if val_accuracy > self.best_accuracy:
                self.best_accuracy = val_accuracy
                self.best_epoch = epoch
                bad_epochs = 0
                
                if save_best:
                    self.best_weights = self.model.state_dict().copy()
                    self.logger.info(f"Новые лучшие веса сохранены (accuracy={val_accuracy:.4f})")
            else:
                bad_epochs += 1
            
            # Callback прогресса
            if progress_callback:
                progress_callback({
                    'epoch': epoch,
                    'train_loss': train_loss,
                    'val_loss': val_loss,
                    'train_accuracy': train_accuracy,
                    'val_accuracy': val_accuracy,
                    'best_accuracy': self.best_accuracy
                })
            
            # Early stopping
            if bad_epochs >= patience:
                self.logger.info(f"Early stopping на эпохе {epoch} (patience={patience})")
                break
        
        # Загрузка лучших весов
        if save_best and self.best_weights:
            self.model.load_state_dict(self.best_weights)
            self.logger.info(f"Загружены лучшие веса из эпохи {self.best_epoch}")
        
        training_time = time.time() - start_time
        
        self.logger.log_training_complete(
            model_name=str(type(self.model).__name__),
            final_accuracy=self.best_accuracy,
            epochs_trained=epoch
        )
        
        return {
            'epochs_trained': epoch,
            'best_epoch': self.best_epoch,
            'best_accuracy': self.best_accuracy,
            'training_time': training_time,
            'history': self.training_history
        }
    
    def save_model(
        self,
        save_path: str,
        include_optimizer: bool = False,
        optimizer: Optional[optim.Optimizer] = None
    ):
        """
        Сохранение модели
        
        Args:
            save_path: Путь для сохранения
            include_optimizer: Сохранять ли оптимизатор
            optimizer: Оптимизатор для сохранения
        """
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        checkpoint = {
            'model_state_dict': self.model.state_dict(),
            'best_accuracy': self.best_accuracy,
            'best_epoch': self.best_epoch,
            'training_history': self.training_history
        }
        
        if include_optimizer and optimizer:
            checkpoint['optimizer_state_dict'] = optimizer.state_dict()
        
        torch.save(checkpoint, save_path)
        self.logger.info(f"Модель сохранена: {save_path}")
    
    def evaluate_on_test(
        self,
        test_loader: torch.utils.data.DataLoader,
        accuracy_threshold: float = 0.7
    ) -> Dict[str, Any]:
        """
        Оценка модели на тестовом наборе
        
        Args:
            test_loader: DataLoader с тестовыми данными
            accuracy_threshold: Порог точности
            
        Returns:
            Словарь с результатами оценки
        """
        criterion = self.create_criterion(
            self.config.get('training.loss_function', 'cross_entropy')
        )
        
        metrics = self.validator.test_model(self.model, test_loader, self.device, criterion)
        
        # Проверка порога
        accuracy = metrics.get('accuracy', 0.0)
        meets_threshold, recommendations = self.validator.check_accuracy_threshold(
            accuracy, accuracy_threshold
        )
        
        results = {
            'metrics': metrics,
            'meets_threshold': meets_threshold,
            'recommendations': recommendations
        }
        
        if not meets_threshold:
            # Анализ причин низкой точности
            analysis = self.validator.analyze_low_accuracy(
                self.model, None, None, self.device  # Нужны train и val loaders для полного анализа
            )
            results['low_accuracy_analysis'] = analysis
        
        return results
    
    def generate_graph_data(self, training_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Генерация данных для 3D force-directed графа из результатов обучения
        
        Args:
            training_results: Результаты обучения (если None, использует self.training_history)
            
        Returns:
            Словарь с nodes и links для графа
        """
        if training_results is None:
            training_results = {
                'train_loss': self.training_history.get('train_loss', []),
                'val_loss': self.training_history.get('val_loss', []),
                'train_accuracy': self.training_history.get('train_accuracy', []),
                'val_accuracy': self.training_history.get('val_accuracy', []),
                'learning_rate': [self.config.get('training.learning_rate', 0.001)] * len(self.training_history.get('train_loss', [])),
                'batch_size': [self.config.get('training.batch_size', 32)] * len(self.training_history.get('train_loss', [])),
                'cuda_version': self.gpu_manager.get_gpu_info().get('cuda_version', '12.4') if self.gpu_manager.check_cuda_available() else 'N/A',
                'gpu_mem_used_percent': 80  # Примерное значение
            }
        
        num_epochs = len(training_results.get('train_loss', []))
        if num_epochs == 0:
            num_epochs = 50  # Дефолтное значение для демо
        
        return self.visualizer.generate_graph_data(training_results, num_epochs, include_core_modules=True)
    
    def visualize_graph(self, port: int = 5001, host: str = '0.0.0.0') -> None:
        """
        Запуск Flask сервера для 3D визуализации графа
        
        Args:
            port: Порт для Flask сервера
            host: Хост для Flask сервера
        """
        import subprocess
        import sys
        import json
        import tempfile
        from pathlib import Path
        
        # Путь к viz_server
        viz_server_path = Path(__file__).parent.parent / 'viz_server' / 'app.py'
        
        if not viz_server_path.exists():
            self.logger.error(f"Viz server not found at {viz_server_path}")
            self.logger.info("Please ensure viz_server/app.py exists")
            return
        
        # Генерация данных графа
        graph_data = self.generate_graph_data()
        
        # Сохранение данных во временный файл для передачи в сервер
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(graph_data, temp_file)
        temp_file.close()
        
        self.logger.info(f"Starting visualization server on http://{host}:{port}")
        self.logger.info(f"Graph data saved to {temp_file.name}")
        
        # Запуск Flask сервера
        try:
            os.environ['GRAPH_DATA_FILE'] = temp_file.name
            subprocess.Popen([
                sys.executable, str(viz_server_path),
                '--port', str(port),
                '--host', host
            ])
            self.logger.info(f"✅ Visualization server started! Open http://{host}:{port}")
        except Exception as e:
            self.logger.error(f"Error starting viz server: {e}")