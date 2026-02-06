# Распределенная платформа нейросетевых вычислений

Производственная платформа для обучения нейросетевых моделей на Python с использованием PyTorch. Платформа реализует полный алгоритм обучения согласно UML-диаграмме и поддерживает как GPU, так и CPU вычисления.

## Основные возможности

### ML Platform Core
- ✅ **Автоматическое управление GPU**: Определение доступности, управление памятью, graceful degradation на CPU
- ✅ **Загрузка данных**: Поддержка CSV, Parquet, HDF5, Pickle форматов
- ✅ **Валидация данных**: Проверка целостности и качества данных
- ✅ **Обучение моделей**: Полный цикл обучения с early stopping, сохранением лучших весов
- ✅ **Мониторинг**: Prometheus метрики, логирование в systemd journal
- ✅ **REST API**: FastAPI сервер для удаленного запуска обучения
- ✅ **WebSocket**: Отслеживание прогресса обучения в реальном времени
- ✅ **Визуализация**: Автоматическое создание графиков обучения и метрик

### Security Analysis Module
- ✅ **Сбор данных об уязвимостях**: NVD, OSV, GitHub Security Advisories
- ✅ **Паспортизация CVE**: Единая структура данных об уязвимостях
- ✅ **ML классификация**: Автоматическая классификация по критичности и типу атаки
- ✅ **Расчет рисков**: Контекстуальный расчет с ML коррекцией
- ✅ **Визуализация безопасности**: Тепловые карты, дашборды, отчеты
- ✅ **Security API**: REST API для работы с уязвимостями и рисками

## Структура проекта

```
ml_platform/
├── core/                    # Основные компоненты
│   ├── config_manager.py   # Управление конфигурацией
│   ├── logger.py           # Логирование (systemd journal)
│   ├── gpu_manager.py      # Управление GPU
│   ├── data_loader.py      # Загрузка и подготовка данных
│   ├── model_validator.py  # Валидация моделей
│   ├── visualization.py    # Визуализация результатов
│   └── model_trainer.py    # Основной класс обучения
├── api/                     # API компоненты
│   ├── server.py           # FastAPI сервер
│   └── websocket.py        # WebSocket менеджер
├── security/                # Модуль анализа безопасности
│   ├── collectors/         # Сборщики данных (NVD, OSV, GitHub)
│   ├── cve_passport.py    # Паспортизация CVE
│   ├── ml_models/          # ML модели для классификации
│   ├── risk_engine.py     # Движок расчета рисков
│   ├── visualization/      # Визуализация безопасности
│   └── api/               # Security API endpoints
├── models/                  # Примеры моделей
│   └── example_models.py   # Готовые архитектуры
├── utils/                   # Утилиты
│   └── prometheus_metrics.py # Prometheus метрики
├── config/                  # Конфигурация
│   └── config.yaml         # Файл конфигурации
└── examples/                # Примеры использования
    └── training_script.py  # Пример скрипта обучения
```

## Установка

### 1. Системные требования

- Python 3.8+
- Ubuntu Server 20.04+ (или другая Linux система)
- CUDA 12.4+ (опционально, для GPU)
- NVIDIA драйверы (опционально, для GPU)

### 2. Установка зависимостей

```bash
# Создание виртуального окружения
python3 -m venv venv
source venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt

# Для GPU (если доступна)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu124
```

### 3. Настройка конфигурации

Скопируйте и отредактируйте конфигурационный файл:

```bash
cp config/config.yaml config/config.local.yaml
# Отредактируйте config.local.yaml под ваши нужды
```

## Модули платформы

### ML Platform Core
Базовый функционал для обучения нейросетевых моделей. См. основной README выше.

### Security Analysis Module
Модуль анализа информационной безопасности с ML моделями. Подробности в:
- `SECURITY_PLATFORM.md` - Полное описание модуля безопасности
- `security/README.md` - Документация модуля
- `examples/security_analysis.py` - Пример использования

**Быстрый старт модуля безопасности:**
```python
from ml_platform.security.collectors.nvd_collector import NVDCollector
from ml_platform.security.cve_passport import CVEPassportManager
from ml_platform.security.risk_engine import RiskEngine, Asset

# Сбор и анализ уязвимостей
nvd = NVDCollector()
cves = nvd.get_recent_cves(days=7)

manager = CVEPassportManager()
for cve_data in cves:
    normalized = nvd.normalize_cve_data(cve_data)
    passport = manager.create_passport(normalized["cve_id"], normalized)

# Расчет рисков
risk_engine = RiskEngine()
asset = Asset(asset_id="server-01", name="Web Server", ...)
risk = risk_engine.calculate_risk(passport, asset)
```

## Использование

### Запуск через Python скрипт

```python
from ml_platform.core.model_trainer import ModelTrainer
from ml_platform.core.data_loader import DataLoader
from ml_platform.models.example_models import SimpleClassifier

# Загрузка данных
data_loader = DataLoader()
train_loader, val_loader, test_loader = data_loader.load_and_prepare(
    file_path="data/train.csv",
    target_column="target",
    batch_size=32
)

# Создание модели
model = SimpleClassifier(input_size=20, num_classes=2)

# Обучение
trainer = ModelTrainer()
trainer.prepare_model(model)
results = trainer.train(
    train_loader=train_loader,
    val_loader=val_loader,
    epochs=100,
    learning_rate=0.001
)
```

### Запуск через Jupyter Lab

См. пример в `examples/training_script.py`. Можно запустить в Jupyter Lab 4.1.5:

```python
# В Jupyter notebook
%run examples/training_script.py
```

### Запуск API сервера

```bash
# Запуск сервера
python -m ml_platform.api.server

# Или через uvicorn
uvicorn ml_platform.api.server:app --host 0.0.0.0 --port 8000
```

### Использование API

#### Запуск обучения через API

```bash
curl -X POST "http://localhost:8000/training/start" \
  -H "Content-Type: application/json" \
  -d '{
    "model_class": "SimpleClassifier",
    "model_config": {"input_size": 20, "num_classes": 2},
    "data_path": "/path/to/data.csv",
    "target_column": "target",
    "epochs": 100,
    "batch_size": 32,
    "learning_rate": 0.001
  }'
```

#### Проверка статуса

```bash
curl "http://localhost:8000/training/status/{task_id}"
```

#### WebSocket для прогресса

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/{task_id}');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Progress:', data);
};
```

## Конфигурация

Основные параметры конфигурации в `config/config.yaml`:

- **training**: Параметры обучения (эпохи, batch size, learning rate)
- **gpu**: Настройки GPU (минимальная память, автоочистка кэша)
- **data**: Настройки данных (разделение train/val/test, нормализация)
- **paths**: Пути к директориям (модели, логи, данные)
- **logging**: Настройки логирования
- **api**: Настройки API сервера
- **monitoring**: Настройки мониторинга

## Мониторинг

### Prometheus метрики

Метрики доступны по адресу: `http://localhost:8000/metrics`

Основные метрики:
- `ml_platform_training_started_total` - количество запущенных обучений
- `ml_platform_training_completed_total` - количество завершенных обучений
- `ml_platform_training_duration_seconds` - длительность обучения
- `ml_platform_model_accuracy` - точность модели
- `ml_platform_gpu_memory_usage_bytes` - использование памяти GPU

### Логирование

Логи записываются в:
- Systemd journal (если доступен)
- Файл: `/var/log/ml_platform/training.log`

Просмотр логов:
```bash
# Systemd journal
journalctl -u ml-platform -f

# Файл логов
tail -f /var/log/ml_platform/training.log
```

## Алгоритм обучения

Платформа реализует следующий алгоритм (согласно UML-диаграмме):

1. **Валидация скрипта**: Проверка синтаксиса Python
2. **Инициализация модели**: Загрузка или создание модели
3. **Загрузка весов**: Предобученные веса или случайная инициализация
4. **Определение устройства**: GPU (если доступна) или CPU
5. **Загрузка данных**: Из файла с валидацией
6. **Подготовка данных**: Разделение, нормализация
7. **Цикл обучения**: 
   - Прямой проход
   - Вычисление потерь
   - Обратное распространение
   - Обновление весов
   - Валидация
   - Early stopping
8. **Оценка модели**: Тестирование на тестовом наборе
9. **Сохранение**: Модель и визуализации

## Обработка ошибок

Платформа включает комплексную обработку ошибок:

- **Graceful degradation**: Автоматический переход на CPU при проблемах с GPU
- **Валидация данных**: Проверка целостности перед обучением
- **Численная стабильность**: Обнаружение NaN/Inf в потерях
- **Восстановление**: Автоматические повторы при временных сбоях
- **Подробные логи**: Детальная информация об ошибках

## Примеры моделей

В `models/example_models.py` доступны готовые архитектуры:

- `SimpleClassifier` - простой классификатор
- `MLPRegressor` - регрессионная модель
- `CNNClassifier` - CNN для изображений
- `LSTMClassifier` - LSTM для последовательностей

## Развертывание

См. `DEPLOYMENT.md` для подробных инструкций по развертыванию на сервере.

## Установка зависимостей

### Базовые зависимости
```bash
pip install -r requirements.txt
```

### Дополнительные зависимости для модуля безопасности
```bash
pip install -r requirements_security.txt
```

## Документация

- `README.md` - Этот файл (общая документация)
- `QUICKSTART.md` - Быстрый старт
- `DEPLOYMENT.md` - Инструкции по развертыванию
- `ARCHITECTURE.md` - Описание архитектуры
- `SECURITY_PLATFORM.md` - Документация модуля безопасности
- `security/README.md` - Документация модуля безопасности

## Примеры

- `examples/training_script.py` - Пример обучения модели
- `examples/jupyter_example.ipynb` - Jupyter notebook пример
- `examples/security_analysis.py` - Пример анализа безопасности

## Лицензия

MIT License

## Поддержка

Для вопросов и проблем создавайте issues в репозитории проекта.
