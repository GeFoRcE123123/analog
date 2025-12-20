FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Копируем requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код парсеров
COPY . .

# Переменные окружения
ENV PYTHONUNBUFFERED=1
ENV CHROMIUM_PATH=/usr/bin/chromium

# Запуск парсеров
CMD ["python", "run_parsers.py"]

