# 🖥️ СПЕЦИФИКАЦИЯ 6-Й VM ДЛЯ МОНИТОРИНГА И РАЗВЕРТЫВАНИЯ

## 📊 Текущая архитектура проекта

### Существующие VM:

| VM | IP | Назначение | Стек | Порт |
|----|----|-----------|------|------|
| **Frontend** | 10.0.88.10 | Веб-интерфейс | Nginx + HTML/JS | 80 |
| **Backend** | 10.0.88.20 | API сервер | Flask (Python) | 5000 |
| **Database** | 10.0.88.11 | База данных | PostgreSQL | 5432 |
| **Parsers** | 10.0.88.23 | Парсеры уязвимостей | Python + Docker | - |
| **ML Platform** | 10.0.88.25 | AI/ML сервис | Flask + scikit-learn | 8000 |

### Используемые технологии:
- ✅ **Docker** - контейнеризация на всех VM
- ✅ **systemd** - управление сервисами
- ✅ **Flask** - веб-фреймворк (Backend, ML Platform)
- ✅ **PostgreSQL** - база данных
- ✅ **Nginx** - веб-сервер (Frontend)
- ✅ **Python 3** - основной язык разработки

---

## 🎯 6-Я VM: MONITORING & DEPLOYMENT

### Рекомендуемый IP: **10.0.88.30**

---

## 💻 ТЕХНИЧЕСКИЕ ХАРАКТЕРИСТИКИ

### Вариант 1: Минимальная конфигурация (для начала)

| Параметр | Значение | Обоснование |
|----------|----------|-------------|
| **CPU** | **2 ядра (2 vCPU)** | Достаточно для базового мониторинга 5 VM |
| **ОЗУ** | **4 GB** | Для Loki + Prometheus + Grafana |
| **HDD** | **50 GB SSD** | Для хранения логов и метрик (7-14 дней) |
| **Сеть** | **1 Gbps** | Для сбора данных с других VM |

**Стоимость (примерно):**
- Hetzner: ~€5/месяц
- DigitalOcean: ~$24/месяц
- AWS EC2 t3.medium: ~$30/месяц

---

### Вариант 2: Рекомендуемая конфигурация (production) ⭐

| Параметр | Значение | Обоснование |
|----------|----------|-------------|
| **CPU** | **4 ядра (4 vCPU)** | Для обработки логов 5 VM + CI/CD |
| **ОЗУ** | **8 GB** | Для Loki + Prometheus + Grafana + GitLab Runner |
| **HDD** | **100 GB SSD** | Для хранения логов (30 дней) и Docker образов |
| **Сеть** | **1 Gbps** | Для стабильного сбора данных |

**Стоимость (примерно):**
- Hetzner: ~€10/месяц
- DigitalOcean: ~$48/месяц
- AWS EC2 t3.large: ~$60/месяц

---

### Вариант 3: Оптимальная конфигурация (масштабирование)

| Параметр | Значение | Обоснование |
|----------|----------|-------------|
| **CPU** | **8 ядер (8 vCPU)** | Для больших объемов данных и параллельных задач |
| **ОЗУ** | **16 GB** | Для расширенного мониторинга и множественных сервисов |
| **HDD** | **200 GB SSD + 500 GB HDD** | SSD для индексов, HDD для архивных логов (90+ дней) |
| **Сеть** | **10 Gbps** | Для высоконагруженных систем |

**Стоимость (примерно):**
- Hetzner: ~€20/месяц
- DigitalOcean: ~$96/месяц
- AWS EC2 t3.xlarge: ~$120/месяц

---

## 🐧 ОПЕРАЦИОННАЯ СИСТЕМА

### Рекомендация: **Ubuntu Server 22.04 LTS** (БЕЗ GUI)

**Почему:**
- ✅ Совместимость с существующими VM (все используют Ubuntu/Linux)
- ✅ Долгосрочная поддержка до 2027
- ✅ Отличная поддержка Docker (как на других VM)
- ✅ Стабильность и надежность
- ✅ Большое сообщество

**⚠️ GUI НЕ НУЖЕН!**

**Причины:**
- ✅ **Все управление через SSH** - как на других VM проекта
- ✅ **Grafana доступна через браузер** - веб-интерфейс на порту 3000, доступен с любого компьютера
- ✅ **Экономия ресурсов** - GUI потребляет ~1-2 GB RAM и CPU
- ✅ **Безопасность** - меньше уязвимостей без GUI компонентов
- ✅ **Стандарт для серверов** - все ваши VM используют Ubuntu Server без GUI

**Установка:**
```bash
# При установке Ubuntu Server 22.04 LTS выбрать:
# - Минимальная установка
# - OpenSSH server
# - Standard system utilities
# - БЕЗ GUI (серверная версия)
```

**Альтернативы:**
- Debian 12 - более легковесная
- Ubuntu Server 20.04 LTS - если нужна совместимость со старыми версиями

---

## 📦 РЕКОМЕНДУЕМЫЙ СТЕК ПО (с учетом существующего стека)

### 1. Система сбора и хранения логов

#### ⭐ Рекомендация: **Loki + Promtail** (легковесный, совместим с Grafana)

**Почему Loki вместо ELK:**
- ✅ Меньше ресурсов (4 GB RAM достаточно)
- ✅ Интеграция с Grafana (уже используется)
- ✅ Простая настройка
- ✅ Эффективное хранение
- ✅ Совместим с Prometheus (метрики)

**Установка через Docker (как на других VM):**
```bash
# Структура как на других VM
~/monitoring/
├── docker-compose.yml
├── loki/
│   └── config.yaml
└── promtail/
    └── config.yml
```

**Требования:**
- CPU: 2 ядра
- RAM: 2 GB
- HDD: 30 GB

---

### 2. Система мониторинга метрик

#### ⭐ Рекомендация: **Prometheus + Node Exporter**

**Почему:**
- ✅ Стандарт индустрии
- ✅ Интеграция с Grafana
- ✅ Легковесный
- ✅ Pull-based модель (как на других VM)

**Установка через Docker:**
```bash
# Структура
~/monitoring/
├── prometheus/
│   ├── docker-compose.yml
│   └── prometheus.yml
```

**Требования:**
- CPU: 1 ядро
- RAM: 1 GB
- HDD: 10 GB

---

### 3. Визуализация и дашборды

#### ⭐ Рекомендация: **Grafana**

**Почему:**
- ✅ Единый интерфейс для логов и метрик
- ✅ Мощная визуализация
- ✅ Готовые дашборды
- ✅ Алертинг встроен

**Установка через Docker:**
```bash
# В том же docker-compose.yml что и Loki
```

**Требования:**
- CPU: 1 ядро
- RAM: 1 GB
- HDD: 5 GB

---

### 4. Система управления развертыванием

#### ⭐ Рекомендация: **GitLab Runner** (если используете GitLab)

**Альтернатива: GitHub Actions Runner** (если используете GitHub)

**Почему GitLab Runner:**
- ✅ Работает как сервис (systemd, как на других VM)
- ✅ Поддержка Docker executor (как на других VM)
- ✅ Интеграция с существующим стеком

**Установка:**
```bash
# Через apt (как на других VM)
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
sudo apt-get install gitlab-runner
```

**Требования:**
- CPU: 2 ядра (для сборки Docker образов)
- RAM: 2 GB
- HDD: 50 GB (для Docker образов и кэша)

---

### 5. Дополнительные инструменты

#### Docker & Docker Compose (обязательно)
```bash
# Как на других VM
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo apt-get install docker-compose-plugin
```

#### Nginx (для reverse proxy)
```bash
sudo apt-get install nginx
# Для доступа к Grafana через домен
```

#### Ansible (для автоматизации развертывания)
```bash
sudo apt-get install ansible
# Для автоматического деплоя на другие VM
```

#### Fail2ban (безопасность)
```bash
sudo apt-get install fail2ban
# Как на других VM
```

---

## 🏗️ АРХИТЕКТУРА 6-Й VM

```
┌─────────────────────────────────────────────────────────┐
│         MONITORING VM (10.0.88.30)                      │
│         4 CPU, 8 GB RAM, 100 GB SSD                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Loki Stack (Docker Compose)                     │  │
│  │  - Loki (логи)                                   │  │
│  │  - Promtail (сбор логов)                         │  │
│  │  - Grafana (визуализация)                        │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Prometheus Stack (Docker Compose)               │  │
│  │  - Prometheus (метрики)                          │  │
│  │  - Node Exporter (системные метрики)             │  │
│  │  - Alertmanager (алерты)                         │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  CI/CD (systemd)                                  │  │
│  │  - GitLab Runner                                 │  │
│  │  - Ansible                                       │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Reverse Proxy (systemd)                         │  │
│  │  - Nginx (для доступа к Grafana)                 │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
└─────────────────────────────────────────────────────────┘
         │
         │ Сбор данных
         │
    ┌────┴────┬──────────┬──────────┬──────────┐
    │         │          │          │          │
    ▼         ▼          ▼          ▼          ▼
Frontend  Backend   Database   Parsers   ML Platform
10.0.88.10 10.0.88.20 10.0.88.11 10.0.88.23 10.0.88.25
```

---

## 📋 ПОШАГОВАЯ УСТАНОВКА

### Шаг 1: Установка базовой системы

```bash
# Ubuntu Server 22.04 LTS
# Минимальная установка с SSH сервером

# Обновление системы
sudo apt-get update && sudo apt-get upgrade -y

# Базовые утилиты (как на других VM)
sudo apt-get install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    ufw \
    fail2ban \
    sshpass
```

### Шаг 2: Установка Docker (как на других VM)

```bash
# Установка Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Добавление пользователя в группу docker
sudo usermod -aG docker $USER

# Установка Docker Compose
sudo apt-get install -y docker-compose-plugin

# Проверка
docker --version
docker compose version
```

### Шаг 3: Развертывание Loki Stack

```bash
# Создание структуры (как на других VM)
mkdir -p ~/monitoring/loki
cd ~/monitoring/loki

# Создание docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  loki:
    image: grafana/loki:latest
    container_name: loki
    ports:
      - "3100:3100"
    command: -config.file=/etc/loki/local-config.yaml
    volumes:
      - ./loki-data:/loki
    networks:
      - monitoring
    restart: unless-stopped

  promtail:
    image: grafana/promtail:latest
    container_name: promtail
    volumes:
      - /var/log:/var/log:ro
      - ./promtail-config.yml:/etc/promtail/config.yml
    command: -config.file=/etc/promtail/config.yml
    networks:
      - monitoring
    depends_on:
      - loki
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
    volumes:
      - ./grafana-data:/var/lib/grafana
      - ./grafana-provisioning:/etc/grafana/provisioning
    networks:
      - monitoring
    depends_on:
      - loki
    restart: unless-stopped

networks:
  monitoring:
    driver: bridge
EOF

# Создание конфигурации Promtail
cat > promtail-config.yml << 'EOF'
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          __path__: /var/log/*.log
EOF

# Запуск
docker compose up -d
```

### Шаг 4: Развертывание Prometheus

```bash
# Создание директории
mkdir -p ~/monitoring/prometheus
cd ~/monitoring/prometheus

# Создание docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
    networks:
      - monitoring
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      - monitoring
    restart: unless-stopped

networks:
  monitoring:
    driver: bridge
EOF

# Создание конфигурации Prometheus
cat > prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
  
  # Мониторинг других VM
  - job_name: 'backend'
    static_configs:
      - targets: ['10.0.88.20:5000']
  
  - job_name: 'frontend'
    static_configs:
      - targets: ['10.0.88.10:80']
  
  - job_name: 'ml-platform'
    static_configs:
      - targets: ['10.0.88.25:8000']
EOF

# Запуск
docker compose up -d
```

### Шаг 5: Установка GitLab Runner

```bash
# Установка GitLab Runner
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
sudo apt-get install gitlab-runner

# Регистрация runner (нужен токен из GitLab)
sudo gitlab-runner register

# Настройка для Docker executor
sudo gitlab-runner install --user=gitlab-runner --working-directory=/home/gitlab-runner
sudo gitlab-runner start
```

### Шаг 6: Настройка файрвола

```bash
# Разрешить SSH
sudo ufw allow 22/tcp

# Разрешить Grafana
sudo ufw allow 3000/tcp

# Разрешить Prometheus
sudo ufw allow 9090/tcp

# Разрешить Loki
sudo ufw allow 3100/tcp

# Разрешить Node Exporter
sudo ufw allow 9100/tcp

# Включить файрвол
sudo ufw enable
```

---

## 🔧 КОНФИГУРАЦИЯ ДЛЯ СБОРА ЛОГОВ С ДРУГИХ VM

### Настройка Promtail на других VM

**На каждой VM (10.0.88.10, 10.0.88.20, 10.0.88.23, 10.0.88.25):**

```bash
# Установка Promtail через Docker
docker run -d \
  --name promtail \
  -v /var/log:/var/log:ro \
  -v /path/to/promtail-config.yml:/etc/promtail/config.yml \
  -p 9080:9080 \
  grafana/promtail:latest \
  -config.file=/etc/promtail/config.yml
```

**Конфигурация promtail-config.yml на других VM:**
```yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://10.0.88.30:3100/loki/api/v1/push  # Monitoring VM

scrape_configs:
  - job_name: backend-logs  # или frontend-logs, parsers-logs, ml-logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: backend
          vm: 10.0.88.20
          __path__: /var/log/backend/*.log
```

---

## 📊 МОНИТОРИНГ РЕСУРСОВ

### Рекомендуемые метрики:

1. **CPU использование** - не более 70%
2. **RAM использование** - не более 80%
3. **Дисковое пространство** - не более 85%
4. **Сетевая активность** - мониторинг трафика
5. **Доступность сервисов** - uptime мониторинг всех 5 VM

---

## 🔐 БЕЗОПАСНОСТЬ

### Настройка (как на других VM):

1. **Fail2ban** - защита от брутфорса
2. **SSH ключи** - вместо паролей
3. **UFW** - файрвол
4. **Регулярные обновления** - `unattended-upgrades`
5. **Ограничение доступа** - только с внутренней сети

---

## 💰 ОЦЕНКА СТОИМОСТИ

### Рекомендуемая конфигурация (4 CPU, 8 GB, 100 GB SSD):

| Провайдер | Стоимость/месяц |
|-----------|-----------------|
| **Hetzner** | ~€10 |
| **DigitalOcean** | ~$48 |
| **AWS EC2 t3.large** | ~$60 |
| **Azure Standard_B4ms** | ~$70 |
| **GCP e2-standard-4** | ~$65 |

---

## ✅ ИТОГОВЫЕ РЕКОМЕНДАЦИИ

### Для вашего проекта рекомендуется:

**Конфигурация:**
- **CPU:** 4 ядра
- **ОЗУ:** 8 GB
- **HDD:** 100 GB SSD
- **ОС:** Ubuntu Server 22.04 LTS
- **IP:** 10.0.88.30

**Стек ПО:**
- ✅ **Loki + Promtail** - сбор логов (легковесный)
- ✅ **Prometheus** - метрики
- ✅ **Grafana** - визуализация (единый интерфейс)
- ✅ **GitLab Runner** - CI/CD
- ✅ **Docker** - контейнеризация (как на других VM)
- ✅ **Nginx** - reverse proxy
- ✅ **Ansible** - автоматизация

**Преимущества:**
- ✅ Совместимость с существующим стеком (Docker, systemd)
- ✅ Легковесное решение (не требует много ресурсов)
- ✅ Единый интерфейс (Grafana для всего)
- ✅ Простая интеграция с существующими VM

---

**Последнее обновление:** 2025-01-20  
**Версия:** 1.0

