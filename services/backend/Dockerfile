FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Копируем requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Устанавливаем gunicorn для production
RUN pip install gunicorn

# Копируем код приложения
COPY . .

# Копируем templates и static из корня проекта (если есть)
# Templates будут в services/backend/templates через копирование из корня

# Создаем директории для логов
RUN mkdir -p /app/logs

# Переменные окружения
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Открываем порт
EXPOSE 5000

# Запуск через gunicorn с увеличенным таймаутом для длительных операций парсинга
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "600", "--keep-alive", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]

