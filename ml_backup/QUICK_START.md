# 🚀 Быстрый старт

## Использование моделей

### Загрузка AI детектора CVE:
```python
import pickle

with open('ml_backup/models/ai_cve_detector.pkl', 'rb') as f:
    detector = pickle.load(f)

with open('ml_backup/models/tfidf_vectorizer.pkl', 'rb') as f:
    vectorizer = pickle.load(f)

# Использование
text = "TensorFlow vulnerability in machine learning model"
vectorized = vectorizer.transform([text])
prediction = detector.predict(vectorized)
```

### Загрузка MNIST модели:
```python
import torch

model = torch.load('ml_backup/models/mnist_mlp_model.pth')
model.eval()  # Режим оценки
```

## Запуск Jupyter ноутбуков

```bash
cd ml_backup/jupyter_notebooks
jupyter lab
```

## Перенос в другой проект

```bash
# Скопировать всю папку
cp -r ml_backup /path/to/new/project/

# Или только модели
cp -r ml_backup/models /path/to/new/project/
```
