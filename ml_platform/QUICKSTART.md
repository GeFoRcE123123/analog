# Быстрый старт

Краткое руководство по началу работы с платформой.

## Установка

```bash
# Клонирование и переход в директорию
cd ml_platform

# Создание виртуального окружения
python3 -m venv venv
source venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt
```

## Базовое использование

### 1. Через Python скрипт

```python
from ml_platform.core.model_trainer import ModelTrainer
from ml_platform.core.data_loader import DataLoader
from ml_platform.models.example_models import SimpleClassifier

# Загрузка данных
data_loader = DataLoader()
train_loader, val_loader, test_loader = data_loader.load_and_prepare(
    file_path="data.csv",
    target_column="target",
    batch_size=32
)

# Создание модели
sample_input, _ = next(iter(train_loader))
model = SimpleClassifier(input_size=sample_input.shape[1], num_classes=2)

# Обучение
trainer = ModelTrainer()
trainer.prepare_model(model)
results = trainer.train(train_loader, val_loader, epochs=50)

# Сохранение
trainer.save_model("model.pth")
```

### 2. Через Jupyter Lab

Откройте `examples/jupyter_example.ipynb` в Jupyter Lab и следуйте инструкциям.

### 3. Через API

```bash
# Запуск сервера
python -m ml_platform.api.server

# Запуск обучения через API
curl -X POST "http://localhost:8000/training/start" \
  -H "Content-Type: application/json" \
  -d '{
    "model_class": "SimpleClassifier",
    "model_config": {"input_size": 20, "num_classes": 2},
    "data_path": "/path/to/data.csv",
    "target_column": "target",
    "epochs": 50
  }'
```

## Проверка GPU

```python
from ml_platform.core.gpu_manager import GPUManager

gpu_manager = GPUManager()
print(f"CUDA доступна: {gpu_manager.check_cuda_available()}")
print(f"Информация о GPU: {gpu_manager.get_gpu_info()}")
```

## Конфигурация

Скопируйте и отредактируйте `config/config.yaml`:

```yaml
training:
  default_epochs: 100
  batch_size: 32
  learning_rate: 0.001

paths:
  models_dir: /path/to/models
  data_dir: /path/to/data
```

## Примеры

- `examples/training_script.py` - Полный пример обучения
- `examples/jupyter_example.ipynb` - Jupyter notebook пример

## Документация

- `README.md` - Полная документация
- `DEPLOYMENT.md` - Инструкции по развертыванию
