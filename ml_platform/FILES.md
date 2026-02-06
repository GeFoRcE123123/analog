# Список файлов платформы

## Структура проекта

```
ml_platform/
├── __init__.py                    # Инициализация пакета
├── setup.py                       # Setup script для установки
├── requirements.txt               # Зависимости Python
├── .gitignore                     # Git ignore файл
│
├── README.md                      # Основная документация
├── QUICKSTART.md                  # Быстрый старт
├── DEPLOYMENT.md                  # Инструкции по развертыванию
├── ARCHITECTURE.md                # Описание архитектуры
├── FILES.md                       # Этот файл
│
├── check_installation.py          # Скрипт проверки установки
│
├── core/                          # Основные компоненты
│   ├── __init__.py
│   ├── config_manager.py          # Управление конфигурацией
│   ├── logger.py                  # Логирование (systemd journal)
│   ├── gpu_manager.py            # Управление GPU
│   ├── data_loader.py             # Загрузка и подготовка данных
│   ├── model_validator.py         # Валидация моделей
│   ├── visualization.py           # Визуализация результатов
│   └── model_trainer.py           # Основной класс обучения
│
├── api/                           # API компоненты
│   ├── __init__.py
│   ├── server.py                  # FastAPI сервер
│   └── websocket.py               # WebSocket менеджер
│
├── models/                        # Примеры моделей
│   ├── __init__.py
│   └── example_models.py         # Готовые архитектуры моделей
│
├── utils/                         # Утилиты
│   ├── __init__.py
│   └── prometheus_metrics.py     # Prometheus метрики
│
├── config/                        # Конфигурация
│   └── config.yaml               # Файл конфигурации
│
└── examples/                      # Примеры использования
    ├── training_script.py         # Пример скрипта обучения
    └── jupyter_example.ipynb     # Jupyter notebook пример
```

## Описание файлов

### Основные файлы

- **setup.py** - Установка пакета через pip
- **requirements.txt** - Все необходимые зависимости
- **check_installation.py** - Скрипт для проверки корректности установки

### Документация

- **README.md** - Полная документация с примерами
- **QUICKSTART.md** - Краткое руководство по началу работы
- **DEPLOYMENT.md** - Подробные инструкции по развертыванию на сервере
- **ARCHITECTURE.md** - Описание архитектуры системы

### Core компоненты

- **config_manager.py** - Загрузка и управление конфигурацией из YAML/JSON
- **logger.py** - Централизованное логирование с поддержкой systemd journal
- **gpu_manager.py** - Автоматическое определение и управление GPU
- **data_loader.py** - Загрузка данных из CSV, Parquet, HDF5, Pickle
- **model_validator.py** - Валидация моделей и вычисление метрик
- **visualization.py** - Создание графиков обучения и метрик
- **model_trainer.py** - Основной класс, реализующий алгоритм обучения

### API компоненты

- **server.py** - FastAPI сервер с REST API endpoints
- **websocket.py** - WebSocket менеджер для real-time прогресса

### Модели

- **example_models.py** - Примеры готовых архитектур:
  - SimpleClassifier
  - MLPRegressor
  - CNNClassifier
  - LSTMClassifier

### Утилиты

- **prometheus_metrics.py** - Метрики для Prometheus мониторинга

### Примеры

- **training_script.py** - Полный пример обучения модели
- **jupyter_example.ipynb** - Jupyter notebook с пошаговым обучением

## Использование

1. Установка: `pip install -r requirements.txt`
2. Проверка: `python check_installation.py`
3. Запуск примера: `python examples/training_script.py`
4. Запуск API: `python -m ml_platform.api.server`

## Всего файлов

- Python модулей: 15
- Документация: 5
- Конфигурация: 1
- Примеры: 2
- **Итого: 23 файла**
