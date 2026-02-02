# Исправление ошибки apt-get update (exit code 100)

## Проблема
При сборке Docker образа возникает ошибка:
```
TASK ERROR: command 'apt-get update' failed: exit code 100
```

## Решение

### Вариант 1: Исправленные Dockerfile (уже применено)
Dockerfile обновлены с улучшенной обработкой ошибок:
- Очистка кэша перед обновлением
- Использование `--fix-missing` флага
- Добавлен `ca-certificates` для SSL соединений
- Использование `--no-install-recommends` для уменьшения размера

### Вариант 2: Если проблема сохраняется

#### 2.1 Использование зеркал Debian
Добавьте в начало Dockerfile (после FROM):
```dockerfile
# Использование зеркал для надежности
RUN echo "deb http://deb.debian.org/debian bullseye main" > /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian-security bullseye-security main" >> /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian bullseye-updates main" >> /etc/apt/sources.list
```

#### 2.2 Разделение команд для отладки
```dockerfile
# Шаг 1: Очистка
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Шаг 2: Обновление (с повторами)
RUN apt-get update || apt-get update || apt-get update

# Шаг 3: Установка пакетов
RUN apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    ca-certificates
```

#### 2.3 Использование buildkit с кэшем
```bash
DOCKER_BUILDKIT=1 docker build --progress=plain -t vulnerability-backend .
```

### Вариант 3: Проверка сетевых настроек

Если проблема в сети/DNS:
```dockerfile
# Добавьте в Dockerfile перед apt-get update
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf && \
    echo "nameserver 8.8.4.4" >> /etc/resolv.conf
```

### Вариант 4: Использование альтернативного базового образа

Если проблема критична, можно использовать:
```dockerfile
FROM python:3.11-slim-bullseye
# или
FROM python:3.11-slim-bookworm
```

## Проверка

После исправления попробуйте:
```bash
cd services/backend
docker build -t vulnerability-backend .
```

Или для парсеров:
```bash
cd services/parsers
docker build -t vulnerability-parsers .
```

## Дополнительная диагностика

Если ошибка сохраняется, проверьте:
1. **Сетевое соединение**: `ping deb.debian.org`
2. **DNS**: `nslookup deb.debian.org`
3. **Прокси**: Если за прокси, настройте в Dockerfile:
   ```dockerfile
   ARG HTTP_PROXY
   ARG HTTPS_PROXY
   ENV HTTP_PROXY=$HTTP_PROXY
   ENV HTTPS_PROXY=$HTTPS_PROXY
   ```

## Текущий статус

✅ Dockerfile обновлены с улучшенной обработкой ошибок
✅ Добавлен `ca-certificates` для SSL
✅ Использован флаг `--fix-missing`
✅ Добавлена очистка кэша перед обновлением

