#!/bin/bash
# train.sh

echo "=== OSINT Neural Network Training Pipeline ==="

# Активация виртуального окружения
source venv/bin/activate

# Установка зависимостей
echo "Установка зависимостей..."
pip install -r requirements.txt

# Подготовка данных
echo "Подготовка датасета..."
python src/data_preparation.py

# Обучение модели
echo "Запуск обучения модели..."
python src/training.py

# Оценка модели
echo "Оценка качества модели..."
python src/evaluate.py

echo "Обучение завершено успешно!"
echo "Финальная модель сохранена в: models/final_model"
