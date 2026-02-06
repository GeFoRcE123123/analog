# 3D Force-Directed Visualization для ML Platform

Интерактивная 3D визуализация дерева анализа данных ИИ с физикой, вращением и зумом.

## Возможности

- ✅ **3D Force-Directed Graph**: Three.js + D3.js force simulation
- ✅ **Физика**: притяжение/отталкивание, коллизии, гравитация
- ✅ **Интерактивность**: вращение, зум, панорамирование (OrbitControls)
- ✅ **Визуализация эпох**: градиент red->green по accuracy
- ✅ **Core модули**: Data Loader, GPU Manager, Model Validator
- ✅ **Security модули**: Risk Engine с CVE анализом
- ✅ **Real-time tooltips**: hover для просмотра параметров
- ✅ **Анимация**: пульсация узлов, частицы, вращение

## Установка

```bash
cd ml_platform/viz_server
pip install -r requirements.txt
```

## Запуск

### Вариант 1: Прямой запуск Flask сервера

```bash
python app.py --port 5001
```

Откройте в браузере: `http://localhost:5001`

### Вариант 2: Из кода ModelTrainer

```python
from ml_platform.core.model_trainer import ModelTrainer

trainer = ModelTrainer()
# ... обучение модели ...
results = trainer.train(train_loader, val_loader, epochs=50)

# Запуск визуализации
trainer.visualize_graph(port=5001)
```

## Структура данных

### Узлы (Nodes)

**Эпохи:**
```json
{
  "id": "epoch_1",
  "group": "epoch",
  "label": "Epoch 1",
  "epoch": 1,
  "accuracy": 0.65,
  "loss": 1.8,
  "train_loss": 1.9,
  "train_accuracy": 0.62,
  "lr": 0.001,
  "batch_size": 64,
  "gpu_mem": "4.2GB",
  "val_score": 0.65,
  "time": "45s",
  "size": 1.2
}
```

**Core модули:**
```json
{
  "id": "data_loader",
  "group": "core",
  "label": "Data Loader",
  "records": 100000,
  "formats": ["CSV", "Parquet", "HDF5"],
  "size": 2.0
}
```

**Security:**
```json
{
  "id": "risk_engine",
  "group": "security",
  "label": "Risk Engine",
  "cve_analyzed": 5000,
  "risk_score": 0.65,
  "size": 1.6
}
```

### Связи (Links)

```json
{
  "source": "epoch_1",
  "target": "epoch_2",
  "value": 0.5,
  "type": "epoch_chain",
  "delta_acc": 0.01
}
```

Типы связей:
- `epoch_chain`: цепочка эпох
- `data_flow`: поток данных
- `resource`: ресурсы (GPU)
- `security`: связь с security модулями
- `training_start`: начало обучения

## API Endpoints

- `GET /` - HTML страница с визуализацией
- `GET /data` - JSON данные графа (nodes + links)
- `GET /health` - Health check

## Управление

- **Вращение**: зажать левую кнопку мыши и двигать
- **Зум**: колесико мыши или pinch на тачскрине
- **Панорамирование**: зажать среднюю кнопку мыши
- **Hover**: навести на узел для tooltip
- **Click**: выбрать узел (увеличится)
- **Drag**: перетаскивание узлов меняет симуляцию

## Интеграция с ML Platform

Визуализация автоматически генерируется из результатов обучения:

```python
# После обучения
results = trainer.train(...)

# Генерация данных графа
graph_data = trainer.generate_graph_data(results)

# Запуск визуализации
trainer.visualize_graph(port=5001)
```

Данные включают:
- Историю обучения (loss, accuracy по эпохам)
- Метрики GPU (память, CUDA версия)
- Параметры обучения (LR, batch size)
- Security метрики (CVE анализ, risk scores)

## Технологии

- **Three.js r169**: 3D рендеринг
- **D3.js v7**: Force simulation в 3D
- **Flask**: Backend сервер
- **OrbitControls**: Управление камерой

## Расширение

Для добавления WebSocket live обновлений:

```python
# В app.py добавить
from flask_socketio import SocketIO

socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    emit('graph_update', graph_data)
```

## Лицензия

Часть ML Platform проекта.

