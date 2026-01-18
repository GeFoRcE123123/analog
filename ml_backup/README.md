# 📦 Резервная копия ML моделей и Jupyter ноутбуков

## 📋 Описание

Эта папка содержит резервную копию всех Jupyter ноутбуков, обученных моделей и истории обучения, скопированных с VM `k8s-worker` (10.0.88.25).

**Дата создания:** 2025-01-13  
**Источник:** k8s-worker@10.0.88.25

---

## 📁 Структура папок

```
ml_backup/
├── jupyter_notebooks/     # Jupyter ноутбуки (.ipynb)
├── models/                 # Обученные модели (.pth, .pkl, .pt)
├── training_history/       # История обучения и результаты
├── data/                   # Данные для обучения
└── checkpoints/            # Checkpoints моделей (если есть)
```

---

## 📂 Детальное описание

### 1. `jupyter_notebooks/`

Содержит все Jupyter ноутбуки с VM:

- `Untitled_proj.ipynb` - Основной проект ноутбук
- `Untitled.ipynb` - Дополнительный ноутбук
- `.ipynb_checkpoints/` - Автоматические checkpoint'ы Jupyter

**Использование:**
```bash
cd jupyter_notebooks
jupyter notebook Untitled_proj.ipynb
```

### 2. `models/`

Обученные модели машинного обучения:

- `mnist_mlp_model.pth` - PyTorch модель для MNIST (MLP)
- `ai_cve_detector.pkl` - Модель детекции AI-уязвимостей (pickle)
- `tfidf_vectorizer.pkl` - TF-IDF векторизатор для текстовых данных
- `my_tensor.pt` - Сохраненный тензор PyTorch

**Формат моделей:**
- `.pth` - PyTorch модели
- `.pkl` - Pickle файлы (scikit-learn, etc.)
- `.pt` - PyTorch тензоры/данные

**Загрузка модели:**
```python
import torch
import pickle

# PyTorch модель
model = torch.load('models/mnist_mlp_model.pth')

# Scikit-learn модель
with open('models/ai_cve_detector.pkl', 'rb') as f:
    model = pickle.load(f)

# TF-IDF векторизатор
with open('models/tfidf_vectorizer.pkl', 'rb') as f:
    vectorizer = pickle.load(f)
```

### 3. `training_history/`

История обучения и результаты экспериментов:

#### `mnist_coursework/`
- Результаты курсовой работы по MNIST
- `mnist_mlp_model.pth` - Обученная модель
- `training_results.csv` - Метрики обучения
- `training_plot.png` - Графики обучения
- `report_template.txt` - Шаблон отчета

#### `mnist_visualization/`
- Визуализации и анализ данных
- `confusion_heatmap.png` - Confusion matrix
- `probability_distribution.png` - Распределение вероятностей
- `error_examples.png` - Примеры ошибок
- `predictions_gallery.png` - Галерея предсказаний
- `visualization_report.txt` - Отчет по визуализации

**Подпапки:**
- `cve_data/` - Данные CVE для анализа
- `debian_cve/` - Анализ Debian CVE
- `ubuntu_cve/` - Анализ Ubuntu CVE
- `combined_cve/` - Комбинированный анализ
- `output/` - Результаты анализа

### 4. `data/`

Данные для обучения и тестирования:

#### `cve_data/`
- `redhat_cve_365d.json` - Red Hat CVE за 365 дней
- `full/` - Полные данные CVE

#### `MNIST/`
- Данные MNIST для обучения

---

## 🔄 Восстановление на новом месте

### Вариант 1: Копирование в новый проект

```bash
# Скопировать всю папку
cp -r ml_backup /path/to/new/project/

# Или только нужные компоненты
cp -r ml_backup/models /path/to/new/project/
cp -r ml_backup/jupyter_notebooks /path/to/new/project/
```

### Вариант 2: Использование в текущем проекте

```python
# В вашем Python коде
import sys
import os

# Добавить путь к моделям
sys.path.append(os.path.join(os.path.dirname(__file__), 'ml_backup'))

# Загрузить модель
import torch
model = torch.load('ml_backup/models/mnist_mlp_model.pth')
```

### Вариант 3: Интеграция с Jupyter

```bash
# Запустить Jupyter в папке с ноутбуками
cd ml_backup/jupyter_notebooks
jupyter lab

# Или скопировать ноутбуки в проект
cp ml_backup/jupyter_notebooks/*.ipynb /path/to/project/notebooks/
```

---

## 📊 Статистика

- **Всего файлов:** 122
- **Размер данных:** ~66 MB
- **Размер моделей:** ~480 KB
- **Размер истории обучения:** ~333 MB
- **Размер Jupyter ноутбуков:** ~1.8 MB

---

## 🔍 Поиск файлов

### Найти все модели:
```bash
find ml_backup/models -type f -name "*.pth" -o -name "*.pkl" -o -name "*.pt"
```

### Найти все ноутбуки:
```bash
find ml_backup/jupyter_notebooks -name "*.ipynb"
```

### Найти все визуализации:
```bash
find ml_backup/training_history -name "*.png" -o -name "*.jpg"
```

---

## ⚠️ Важные замечания

1. **Зависимости:** Убедитесь, что установлены все необходимые библиотеки:
   ```bash
   pip install torch torchvision scikit-learn pandas numpy matplotlib jupyter
   ```

2. **Версии:** Модели могут быть обучены на конкретных версиях библиотек. Проверьте версии:
   ```python
   import torch
   print(torch.__version__)
   ```

3. **Пути:** При переносе в другое место обновите пути в ноутбуках, если они используют абсолютные пути.

4. **Данные:** Некоторые ноутбуки могут ссылаться на данные, которые нужно скопировать отдельно.

---

## 📝 История изменений

- **2025-01-13:** Первоначальная резервная копия с k8s-worker@10.0.88.25

---

## 🔗 Связанные файлы

- `docs/guides/AI_MODEL_INTEGRATION_GUIDE.md` - Руководство по интеграции AI моделей
- `services/parsers/ai_analyzer.py` - Текущий AI анализатор
- `services/ai_integration_service.py` - Сервис интеграции AI

---

## 💡 Рекомендации

1. **Регулярные бэкапы:** Делайте резервные копии моделей после каждого обучения
2. **Версионирование:** Используйте Git LFS для больших моделей
3. **Документация:** Документируйте параметры обучения каждой модели
4. **Тестирование:** Проверяйте модели на тестовых данных после переноса

---

**Вопросы?** Обратитесь к разработчикам или создайте issue в репозитории.

