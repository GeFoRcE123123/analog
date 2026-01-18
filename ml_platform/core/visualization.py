"""
Визуализация результатов обучения
"""

import matplotlib
matplotlib.use('Agg')  # Для работы без GUI
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from ml_platform.core.logger import PlatformLogger


class Visualization:
    """Создание графиков и визуализаций"""
    
    def __init__(self, output_dir: str = "/home/user/projects/models"):
        """
        Инициализация визуализатора
        
        Args:
            output_dir: Директория для сохранения графиков
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = PlatformLogger.get_logger()
    
    def plot_training_curves(
        self,
        train_losses: List[float],
        val_losses: Optional[List[float]] = None,
        train_accuracies: Optional[List[float]] = None,
        val_accuracies: Optional[List[float]] = None,
        save_path: Optional[str] = None
    ) -> str:
        """
        Построение кривых обучения
        
        Args:
            train_losses: Список значений потерь на обучении
            val_losses: Список значений потерь на валидации
            train_accuracies: Список значений точности на обучении
            val_accuracies: Список значений точности на валидации
            save_path: Путь для сохранения (если None, генерируется автоматически)
            
        Returns:
            Путь к сохраненному файлу
        """
        epochs = range(1, len(train_losses) + 1)
        
        fig, axes = plt.subplots(1, 2, figsize=(15, 5))
        
        # График потерь
        axes[0].plot(epochs, train_losses, 'b-', label='Train Loss', linewidth=2)
        if val_losses:
            axes[0].plot(epochs, val_losses, 'r-', label='Val Loss', linewidth=2)
        axes[0].set_xlabel('Epoch', fontsize=12)
        axes[0].set_ylabel('Loss', fontsize=12)
        axes[0].set_title('Training and Validation Loss', fontsize=14, fontweight='bold')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
        
        # График точности
        if train_accuracies:
            axes[1].plot(epochs, train_accuracies, 'b-', label='Train Accuracy', linewidth=2)
        if val_accuracies:
            axes[1].plot(epochs, val_accuracies, 'r-', label='Val Accuracy', linewidth=2)
        axes[1].set_xlabel('Epoch', fontsize=12)
        axes[1].set_ylabel('Accuracy', fontsize=12)
        axes[1].set_title('Training and Validation Accuracy', fontsize=14, fontweight='bold')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        # Сохранение
        if save_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = self.output_dir / f"training_curves_{timestamp}.png"
        else:
            save_path = Path(save_path)
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"Графики обучения сохранены: {save_path}")
        
        return str(save_path)
    
    def plot_confusion_matrix(
        self,
        confusion_matrix: np.ndarray,
        class_names: Optional[List[str]] = None,
        save_path: Optional[str] = None
    ) -> str:
        """
        Визуализация матрицы ошибок
        
        Args:
            confusion_matrix: Матрица ошибок
            class_names: Названия классов
            save_path: Путь для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        fig, ax = plt.subplots(figsize=(10, 8))
        
        im = ax.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.Blues)
        ax.figure.colorbar(im, ax=ax)
        
        if class_names is None:
            class_names = [f'Class {i}' for i in range(len(confusion_matrix))]
        
        ax.set(
            xticks=np.arange(len(class_names)),
            yticks=np.arange(len(class_names)),
            xticklabels=class_names,
            yticklabels=class_names,
            ylabel='True Label',
            xlabel='Predicted Label',
            title='Confusion Matrix'
        )
        
        # Добавление текста в ячейки
        thresh = confusion_matrix.max() / 2.
        for i in range(len(class_names)):
            for j in range(len(class_names)):
                ax.text(j, i, format(confusion_matrix[i, j], 'd'),
                       ha="center", va="center",
                       color="white" if confusion_matrix[i, j] > thresh else "black")
        
        plt.tight_layout()
        
        if save_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = self.output_dir / f"confusion_matrix_{timestamp}.png"
        else:
            save_path = Path(save_path)
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"Матрица ошибок сохранена: {save_path}")
        
        return str(save_path)
    
    def plot_metrics_comparison(
        self,
        metrics: Dict[str, float],
        save_path: Optional[str] = None
    ) -> str:
        """
        Визуализация сравнения метрик
        
        Args:
            metrics: Словарь с метриками
            save_path: Путь для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        metric_names = list(metrics.keys())
        metric_values = list(metrics.values())
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        bars = ax.bar(metric_names, metric_values, color='steelblue', alpha=0.7)
        
        # Добавление значений на столбцы
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{height:.4f}',
                   ha='center', va='bottom')
        
        ax.set_ylabel('Value', fontsize=12)
        ax.set_title('Model Metrics Comparison', fontsize=14, fontweight='bold')
        ax.set_ylim([0, max(metric_values) * 1.2])
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        if save_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = self.output_dir / f"metrics_comparison_{timestamp}.png"
        else:
            save_path = Path(save_path)
        
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"Сравнение метрик сохранено: {save_path}")
        
        return str(save_path)
    
    def create_training_report(
        self,
        model_name: str,
        training_history: Dict[str, List[float]],
        final_metrics: Dict[str, float],
        save_path: Optional[str] = None
    ) -> str:
        """
        Создание полного отчета об обучении
        
        Args:
            model_name: Название модели
            training_history: История обучения
            final_metrics: Финальные метрики
            save_path: Путь для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        # Создание графиков
        train_losses = training_history.get('train_loss', [])
        val_losses = training_history.get('val_loss', [])
        train_accuracies = training_history.get('train_accuracy', [])
        val_accuracies = training_history.get('val_accuracy', [])
        
        curves_path = self.plot_training_curves(
            train_losses, val_losses, train_accuracies, val_accuracies
        )
        
        # Создание сравнения метрик
        metrics_path = self.plot_metrics_comparison(final_metrics)
        
        self.logger.info(f"Отчет об обучении создан: {curves_path}, {metrics_path}")
        
        return curves_path
    
    def generate_graph_data(
        self,
        training_results: Dict[str, Any],
        num_epochs: int = 50,
        include_core_modules: bool = True
    ) -> Dict[str, Any]:
        """
        Генерация данных для 3D force-directed графа
        
        Args:
            training_results: Результаты обучения (история, метрики)
            num_epochs: Количество эпох для визуализации
            include_core_modules: Включать ли core модули (data_loader, gpu_manager и т.д.)
            
        Returns:
            Словарь с nodes и links для графа
        """
        nodes = []
        links = []
        
        # Извлекаем историю обучения
        train_losses = training_results.get('train_loss', [])
        val_losses = training_results.get('val_loss', [])
        train_accuracies = training_results.get('train_accuracy', [])
        val_accuracies = training_results.get('val_accuracy', [])
        learning_rates = training_results.get('learning_rate', [0.001] * num_epochs)
        batch_sizes = training_results.get('batch_size', [32] * num_epochs)
        gpu_memory = training_results.get('gpu_memory', [])
        epoch_times = training_results.get('epoch_time', [])
        
        # Core модули (если включены)
        if include_core_modules:
            # Data Loader
            nodes.append({
                'id': 'data_loader',
                'group': 'core',
                'label': 'Data Loader',
                'records': 100000,
                'formats': ['CSV', 'Parquet', 'HDF5'],
                'size': 2.0,
                'x': -200,
                'y': 0,
                'z': 0
            })
            
            # GPU Manager
            cuda_version = training_results.get('cuda_version', '12.4')
            gpu_mem_used = training_results.get('gpu_mem_used_percent', 80)
            nodes.append({
                'id': 'gpu_manager',
                'group': 'core',
                'label': 'GPU Manager',
                'cuda': cuda_version,
                'mem_used': f'{gpu_mem_used}%',
                'size': 1.8,
                'x': -150,
                'y': 100,
                'z': 0
            })
            
            # Model Validator
            nodes.append({
                'id': 'model_validator',
                'group': 'core',
                'label': 'Model Validator',
                'validation_score': 0.85,
                'size': 1.5,
                'x': -100,
                'y': -100,
                'z': 0
            })
            
            # Security Risk Engine (если есть)
            if training_results.get('security_analysis'):
                nodes.append({
                    'id': 'risk_engine',
                    'group': 'security',
                    'label': 'Risk Engine',
                    'cve_analyzed': training_results.get('cve_count', 0),
                    'risk_score': training_results.get('avg_risk', 0.5),
                    'size': 1.6,
                    'x': 200,
                    'y': 0,
                    'z': 0
                })
                
                # Связь от эпох к risk engine
                if num_epochs > 0:
                    links.append({
                        'source': f'epoch_{num_epochs}',
                        'target': 'risk_engine',
                        'value': 0.5,
                        'type': 'security'
                    })
            
            # Связи между core модулями
            links.append({
                'source': 'data_loader',
                'target': 'model_validator',
                'value': 1.0,
                'type': 'data_flow'
            })
            links.append({
                'source': 'gpu_manager',
                'target': 'model_validator',
                'value': 0.8,
                'type': 'resource'
            })
        
        # Эпохи обучения
        for epoch in range(num_epochs):
            epoch_num = epoch + 1
            
            # Метрики для эпохи
            train_loss = train_losses[epoch] if epoch < len(train_losses) else 0.0
            val_loss = val_losses[epoch] if epoch < len(val_losses) else 0.0
            train_acc = train_accuracies[epoch] if epoch < len(train_accuracies) else 0.0
            val_acc = val_accuracies[epoch] if epoch < len(val_accuracies) else 0.0
            lr = learning_rates[epoch] if epoch < len(learning_rates) else 0.001
            batch_size = batch_sizes[epoch] if epoch < len(batch_sizes) else 32
            gpu_mem = gpu_memory[epoch] if epoch < len(gpu_memory) else 4.2
            epoch_time = epoch_times[epoch] if epoch < len(epoch_times) else 45
            
            # Размер узла зависит от accuracy
            node_size = 0.8 + (val_acc * 0.4) if val_acc > 0 else 1.0
            
            nodes.append({
                'id': f'epoch_{epoch_num}',
                'group': 'epoch',
                'label': f'Epoch {epoch_num}',
                'epoch': epoch_num,
                'accuracy': val_acc,
                'loss': val_loss,
                'train_loss': train_loss,
                'train_accuracy': train_acc,
                'lr': lr,
                'batch_size': batch_size,
                'gpu_mem': f'{gpu_mem}GB',
                'val_score': val_acc,
                'time': f'{epoch_time}s',
                'size': node_size,
                'x': epoch * 20 - (num_epochs * 10),
                'y': (val_loss - 1.0) * 50,
                'z': (val_acc - 0.5) * 100
            })
            
            # Связь с предыдущей эпохой
            if epoch > 0:
                delta_acc = val_acc - (val_accuracies[epoch-1] if epoch-1 < len(val_accuracies) else 0.0)
                links.append({
                    'source': f'epoch_{epoch}',
                    'target': f'epoch_{epoch_num}',
                    'value': abs(delta_acc) + 0.1,
                    'type': 'epoch_chain',
                    'delta_acc': delta_acc
                })
        
        # Связь от core модулей к первой эпохе
        if include_core_modules and num_epochs > 0:
            links.append({
                'source': 'model_validator',
                'target': 'epoch_1',
                'value': 1.0,
                'type': 'training_start'
            })
        
        return {
            'nodes': nodes,
            'links': links
        }