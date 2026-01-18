"""
Валидация и тестирование моделей
"""

import torch
import numpy as np
from typing import Dict, Any, Optional, Tuple
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from ml_platform.core.logger import PlatformLogger


class ModelValidator:
    """Валидация и оценка моделей"""
    
    def __init__(self):
        """Инициализация валидатора"""
        self.logger = PlatformLogger.get_logger()
    
    def validate_model_architecture(self, model: torch.nn.Module) -> Tuple[bool, Optional[str]]:
        """
        Проверка архитектуры модели
        
        Args:
            model: Модель PyTorch
            
        Returns:
            Tuple (валидна ли модель, сообщение об ошибке)
        """
        try:
            # Проверка на наличие параметров
            if len(list(model.parameters())) == 0:
                return False, "Модель не содержит параметров"
            
            # Проверка на возможность forward pass
            # Создаем тестовый тензор
            sample_input = torch.randn(1, next(iter(model.parameters())).shape[0] if len(list(model.parameters())) > 0 else 10)
            
            try:
                with torch.no_grad():
                    _ = model(sample_input)
            except Exception as e:
                return False, f"Ошибка при forward pass: {e}"
            
            return True, None
            
        except Exception as e:
            return False, f"Ошибка валидации модели: {e}"
    
    def evaluate(
        self,
        model: torch.nn.Module,
        dataloader: torch.utils.data.DataLoader,
        device: torch.device,
        criterion: Optional[torch.nn.Module] = None
    ) -> Dict[str, float]:
        """
        Оценка модели на данных
        
        Args:
            model: Модель для оценки
            dataloader: DataLoader с данными
            device: Устройство для вычислений
            criterion: Функция потерь (опционально)
            
        Returns:
            Словарь с метриками
        """
        model.eval()
        all_predictions = []
        all_targets = []
        total_loss = 0.0
        num_batches = 0
        
        with torch.no_grad():
            for batch in dataloader:
                if len(batch) == 2:
                    inputs, targets = batch
                    inputs = inputs.to(device)
                    targets = targets.to(device)
                else:
                    inputs = batch[0].to(device)
                    targets = None
                
                outputs = model(inputs)
                
                # Вычисление потерь
                if criterion is not None and targets is not None:
                    loss = criterion(outputs, targets)
                    total_loss += loss.item()
                    num_batches += 1
                
                # Получение предсказаний
                if outputs.dim() > 1:
                    predictions = torch.argmax(outputs, dim=1)
                else:
                    predictions = (outputs > 0.5).long()
                
                all_predictions.append(predictions.cpu().numpy())
                if targets is not None:
                    all_targets.append(targets.cpu().numpy())
        
        # Объединение всех предсказаний
        all_predictions = np.concatenate(all_predictions)
        
        metrics = {}
        
        if len(all_targets) > 0:
            all_targets = np.concatenate(all_targets)
            
            # Классификационные метрики
            metrics['accuracy'] = float(accuracy_score(all_targets, all_predictions))
            metrics['precision'] = float(precision_score(all_targets, all_predictions, average='weighted', zero_division=0))
            metrics['recall'] = float(recall_score(all_targets, all_predictions, average='weighted', zero_division=0))
            metrics['f1_score'] = float(f1_score(all_targets, all_predictions, average='weighted', zero_division=0))
            
            # Confusion matrix
            cm = confusion_matrix(all_targets, all_predictions)
            metrics['confusion_matrix'] = cm.tolist()
        
        if num_batches > 0:
            metrics['loss'] = total_loss / num_batches
        
        return metrics
    
    def test_model(
        self,
        model: torch.nn.Module,
        test_loader: torch.utils.data.DataLoader,
        device: torch.device,
        criterion: Optional[torch.nn.Module] = None
    ) -> Dict[str, Any]:
        """
        Тестирование модели на тестовом наборе
        
        Args:
            model: Модель для тестирования
            test_loader: DataLoader с тестовыми данными
            device: Устройство для вычислений
            criterion: Функция потерь
            
        Returns:
            Словарь с результатами тестирования
        """
        self.logger.info("Начало тестирования модели")
        
        metrics = self.evaluate(model, test_loader, device, criterion)
        
        self.logger.info(
            f"Результаты тестирования: accuracy={metrics.get('accuracy', 0):.4f}, "
            f"f1_score={metrics.get('f1_score', 0):.4f}"
        )
        
        return metrics
    
    def check_accuracy_threshold(
        self,
        accuracy: float,
        threshold: float = 0.7
    ) -> Tuple[bool, str]:
        """
        Проверка превышения порога точности
        
        Args:
            accuracy: Текущая точность
            threshold: Пороговое значение
            
        Returns:
            Tuple (превышен ли порог, рекомендации)
        """
        if accuracy >= threshold:
            return True, "Модель достигла требуемой точности"
        else:
            recommendations = []
            if accuracy < 0.5:
                recommendations.append("Точность очень низкая. Рекомендуется:")
                recommendations.append("- Увеличить объем обучающих данных")
                recommendations.append("- Изменить архитектуру модели")
                recommendations.append("- Проверить качество данных")
            elif accuracy < threshold:
                recommendations.append(f"Точность {accuracy:.4f} ниже порога {threshold}. Рекомендуется:")
                recommendations.append("- Увеличить количество эпох обучения")
                recommendations.append("- Настроить гиперпараметры (learning rate, batch size)")
                recommendations.append("- Попробовать другие техники регуляризации")
            
            return False, "\n".join(recommendations)
    
    def analyze_low_accuracy(
        self,
        model: torch.nn.Module,
        train_loader: torch.utils.data.DataLoader,
        val_loader: torch.utils.data.DataLoader,
        device: torch.device
    ) -> Dict[str, Any]:
        """
        Анализ причин низкой точности
        
        Args:
            model: Модель для анализа
            train_loader: DataLoader с обучающими данными
            val_loader: DataLoader с валидационными данными
            device: Устройство для вычислений
            
        Returns:
            Словарь с результатами анализа
        """
        self.logger.info("Анализ причин низкой точности")
        
        train_metrics = self.evaluate(model, train_loader, device)
        val_metrics = self.evaluate(model, val_loader, device)
        
        analysis = {
            'train_accuracy': train_metrics.get('accuracy', 0),
            'val_accuracy': val_metrics.get('accuracy', 0),
            'overfitting': False,
            'underfitting': False,
            'recommendations': []
        }
        
        # Проверка на переобучение
        if train_metrics.get('accuracy', 0) > val_metrics.get('accuracy', 0) + 0.1:
            analysis['overfitting'] = True
            analysis['recommendations'].append("Обнаружено переобучение:")
            analysis['recommendations'].append("- Увеличить регуляризацию (dropout, weight decay)")
            analysis['recommendations'].append("- Уменьшить сложность модели")
            analysis['recommendations'].append("- Использовать data augmentation")
        
        # Проверка на недообучение
        if train_metrics.get('accuracy', 0) < 0.6:
            analysis['underfitting'] = True
            analysis['recommendations'].append("Обнаружено недообучение:")
            analysis['recommendations'].append("- Увеличить количество эпох")
            analysis['recommendations'].append("- Увеличить сложность модели")
            analysis['recommendations'].append("- Уменьшить learning rate")
        
        return analysis
