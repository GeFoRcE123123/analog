"""
Менеджер GPU для управления ресурсами и памятью
"""

import subprocess
import torch
from typing import Optional, Tuple, Dict
from ml_platform.core.logger import PlatformLogger


class GPUManager:
    """Управление GPU ресурсами"""
    
    def __init__(self, min_memory_gb: float = 2.0, auto_clear_cache: bool = True):
        """
        Инициализация менеджера GPU
        
        Args:
            min_memory_gb: Минимальный объем свободной памяти GPU в GB
            auto_clear_cache: Автоматически очищать кэш при нехватке памяти
        """
        self.min_memory_gb = min_memory_gb
        self.auto_clear_cache = auto_clear_cache
        self.logger = PlatformLogger.get_logger()
        self._gpu_available = None
        self._gpu_info = None
    
    def check_cuda_available(self) -> bool:
        """
        Проверка доступности CUDA
        
        Returns:
            True если CUDA доступна
        """
        if self._gpu_available is None:
            self._gpu_available = torch.cuda.is_available()
            if self._gpu_available:
                self.logger.info("CUDA доступна")
            else:
                self.logger.warning("CUDA недоступна")
        return self._gpu_available
    
    def check_nvidia_drivers(self) -> bool:
        """
        Проверка наличия драйверов NVIDIA через nvidia-smi
        
        Returns:
            True если драйверы установлены
        """
        try:
            result = subprocess.run(
                ['nvidia-smi'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def get_gpu_info(self) -> Dict:
        """
        Получение информации о GPU
        
        Returns:
            Словарь с информацией о GPU
        """
        if self._gpu_info is None:
            self._gpu_info = {}
            
            if not self.check_cuda_available():
                return self._gpu_info
            
            if torch.cuda.is_available():
                device_count = torch.cuda.device_count()
                self._gpu_info['device_count'] = device_count
                
                if device_count > 0:
                    device = torch.cuda.current_device()
                    self._gpu_info['current_device'] = device
                    self._gpu_info['device_name'] = torch.cuda.get_device_name(device)
                    
                    # Получение информации о памяти
                    memory_total = torch.cuda.get_device_properties(device).total_memory / (1024**3)
                    memory_allocated = torch.cuda.memory_allocated(device) / (1024**3)
                    memory_reserved = torch.cuda.memory_reserved(device) / (1024**3)
                    memory_free = memory_total - memory_reserved
                    
                    self._gpu_info['memory_total_gb'] = memory_total
                    self._gpu_info['memory_allocated_gb'] = memory_allocated
                    self._gpu_info['memory_reserved_gb'] = memory_reserved
                    self._gpu_info['memory_free_gb'] = memory_free
        
        return self._gpu_info
    
    def has_sufficient_memory(self, required_memory_gb: Optional[float] = None) -> Tuple[bool, float]:
        """
        Проверка достаточности памяти GPU
        
        Args:
            required_memory_gb: Требуемый объем памяти (если None, используется min_memory_gb)
            
        Returns:
            Tuple (достаточно ли памяти, свободная память в GB)
        """
        if not self.check_cuda_available():
            return False, 0.0
        
        info = self.get_gpu_info()
        free_memory = info.get('memory_free_gb', 0.0)
        required = required_memory_gb or self.min_memory_gb
        
        return free_memory >= required, free_memory
    
    def clear_cache(self) -> bool:
        """
        Очистка кэша GPU
        
        Returns:
            True если очистка прошла успешно
        """
        if not self.check_cuda_available():
            return False
        
        try:
            torch.cuda.empty_cache()
            self.logger.info("Кэш GPU очищен")
            return True
        except Exception as e:
            self.logger.error(f"Ошибка при очистке кэша GPU: {e}")
            return False
    
    def prepare_device(self, model_size_estimate_gb: Optional[float] = None) -> torch.device:
        """
        Подготовка устройства для обучения
        
        Args:
            model_size_estimate_gb: Оценка размера модели в GB
            
        Returns:
            Устройство (GPU или CPU)
        """
        # Проверка CUDA
        if not self.check_cuda_available():
            self.logger.warning("CUDA недоступна, используется CPU")
            return torch.device('cpu')
        
        # Проверка драйверов
        if not self.check_nvidia_drivers():
            self.logger.warning("Драйверы NVIDIA не обнаружены, используется CPU")
            return torch.device('cpu')
        
        # Проверка памяти
        required_memory = model_size_estimate_gb or self.min_memory_gb
        has_memory, free_memory = self.has_sufficient_memory(required_memory)
        
        if not has_memory:
            self.logger.warning(
                f"Недостаточно памяти GPU: требуется {required_memory:.2f} GB, "
                f"доступно {free_memory:.2f} GB"
            )
            
            if self.auto_clear_cache:
                self.clear_cache()
                # Повторная проверка после очистки
                has_memory, free_memory = self.has_sufficient_memory(required_memory)
                
                if has_memory:
                    self.logger.info("Память освобождена, GPU доступна")
                else:
                    self.logger.warning("Памяти все равно недостаточно, используется CPU")
                    return torch.device('cpu')
            else:
                self.logger.warning("Используется CPU из-за нехватки памяти GPU")
                return torch.device('cpu')
        
        device = torch.device('cuda')
        info = self.get_gpu_info()
        self.logger.info(
            f"Используется GPU: {info.get('device_name', 'Unknown')}, "
            f"свободная память: {free_memory:.2f} GB"
        )
        
        return device
    
    def move_to_device(self, obj, device: torch.device):
        """
        Перемещение объекта на устройство
        
        Args:
            obj: Объект для перемещения (модель или тензор)
            device: Целевое устройство
            
        Returns:
            Объект на целевом устройстве
        """
        if isinstance(obj, torch.nn.Module):
            return obj.to(device)
        elif isinstance(obj, torch.Tensor):
            return obj.to(device)
        elif isinstance(obj, (list, tuple)):
            return type(obj)(self.move_to_device(item, device) for item in obj)
        elif isinstance(obj, dict):
            return {k: self.move_to_device(v, device) for k, v in obj.items()}
        else:
            return obj
    
    def get_memory_usage(self) -> Dict[str, float]:
        """
        Получение информации об использовании памяти
        
        Returns:
            Словарь с информацией о памяти
        """
        if not self.check_cuda_available():
            return {}
        
        info = self.get_gpu_info()
        return {
            'total_gb': info.get('memory_total_gb', 0.0),
            'allocated_gb': info.get('memory_allocated_gb', 0.0),
            'reserved_gb': info.get('memory_reserved_gb', 0.0),
            'free_gb': info.get('memory_free_gb', 0.0)
        }
