#!/usr/bin/env python3
"""
Скрипт для проверки установки платформы
"""

import sys
from pathlib import Path


def check_imports():
    """Проверка импортов основных модулей"""
    print("Проверка импортов...")
    
    try:
        import torch
        print(f"✓ PyTorch {torch.__version__}")
        print(f"  CUDA available: {torch.cuda.is_available()}")
        if torch.cuda.is_available():
            print(f"  CUDA version: {torch.version.cuda}")
            print(f"  GPU count: {torch.cuda.device_count()}")
    except ImportError as e:
        print(f"✗ PyTorch не установлен: {e}")
        return False
    
    try:
        import pandas
        print(f"✓ pandas {pandas.__version__}")
    except ImportError as e:
        print(f"✗ pandas не установлен: {e}")
        return False
    
    try:
        import sklearn
        print(f"✓ scikit-learn {sklearn.__version__}")
    except ImportError as e:
        print(f"✗ scikit-learn не установлен: {e}")
        return False
    
    try:
        import matplotlib
        print(f"✓ matplotlib {matplotlib.__version__}")
    except ImportError as e:
        print(f"✗ matplotlib не установлен: {e}")
        return False
    
    try:
        import fastapi
        print(f"✓ FastAPI {fastapi.__version__}")
    except ImportError as e:
        print(f"✗ FastAPI не установлен: {e}")
        return False
    
    try:
        import yaml
        print(f"✓ PyYAML установлен")
    except ImportError as e:
        print(f"✗ PyYAML не установлен: {e}")
        return False
    
    try:
        from prometheus_client import Counter
        print(f"✓ prometheus-client установлен")
    except ImportError as e:
        print(f"✗ prometheus-client не установлен: {e}")
        return False
    
    return True


def check_platform_modules():
    """Проверка модулей платформы"""
    print("\nПроверка модулей платформы...")
    
    modules = [
        'ml_platform.core.config_manager',
        'ml_platform.core.logger',
        'ml_platform.core.gpu_manager',
        'ml_platform.core.data_loader',
        'ml_platform.core.model_validator',
        'ml_platform.core.visualization',
        'ml_platform.core.model_trainer',
        'ml_platform.api.server',
        'ml_platform.models.example_models',
        'ml_platform.utils.prometheus_metrics',
    ]
    
    all_ok = True
    for module in modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError as e:
            print(f"✗ {module}: {e}")
            all_ok = False
    
    return all_ok


def check_directories():
    """Проверка директорий"""
    print("\nПроверка директорий...")
    
    base_dir = Path(__file__).parent
    required_dirs = [
        base_dir / 'core',
        base_dir / 'api',
        base_dir / 'models',
        base_dir / 'utils',
        base_dir / 'config',
        base_dir / 'examples',
    ]
    
    all_ok = True
    for dir_path in required_dirs:
        if dir_path.exists():
            print(f"✓ {dir_path.name}/")
        else:
            print(f"✗ {dir_path.name}/ не найдена")
            all_ok = False
    
    return all_ok


def check_config():
    """Проверка конфигурации"""
    print("\nПроверка конфигурации...")
    
    try:
        from ml_platform.core.config_manager import ConfigManager
        config = ConfigManager()
        print("✓ Конфигурация загружена")
        
        # Проверка основных параметров
        epochs = config.get('training.default_epochs')
        batch_size = config.get('training.batch_size')
        print(f"  Default epochs: {epochs}")
        print(f"  Default batch size: {batch_size}")
        
        return True
    except Exception as e:
        print(f"✗ Ошибка загрузки конфигурации: {e}")
        return False


def check_gpu():
    """Проверка GPU"""
    print("\nПроверка GPU...")
    
    try:
        from ml_platform.core.gpu_manager import GPUManager
        gpu_manager = GPUManager()
        
        cuda_available = gpu_manager.check_cuda_available()
        print(f"  CUDA available: {cuda_available}")
        
        if cuda_available:
            info = gpu_manager.get_gpu_info()
            if info:
                print(f"  GPU: {info.get('device_name', 'Unknown')}")
                print(f"  Memory: {info.get('memory_total_gb', 0):.2f} GB")
                print(f"  Free memory: {info.get('memory_free_gb', 0):.2f} GB")
        
        return True
    except Exception as e:
        print(f"✗ Ошибка проверки GPU: {e}")
        return False


def main():
    """Основная функция"""
    print("=" * 60)
    print("Проверка установки ML Platform")
    print("=" * 60)
    
    results = []
    
    results.append(("Импорты", check_imports()))
    results.append(("Модули платформы", check_platform_modules()))
    results.append(("Директории", check_directories()))
    results.append(("Конфигурация", check_config()))
    results.append(("GPU", check_gpu()))
    
    print("\n" + "=" * 60)
    print("Результаты проверки:")
    print("=" * 60)
    
    all_ok = True
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{name:20} {status}")
        if not result:
            all_ok = False
    
    print("=" * 60)
    
    if all_ok:
        print("Все проверки пройдены успешно!")
        return 0
    else:
        print("Обнаружены проблемы. Проверьте вывод выше.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
