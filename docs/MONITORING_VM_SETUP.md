# 🖥️ НАСТРОЙКА VM ДЛЯ МОНИТОРИНГА ЛОГОВ И РАЗВЕРТЫВАНИЯ

## 📋 Обзор

Документ содержит рекомендации по созданию отдельной виртуальной машины для централизованного мониторинга логов и управления развертыванием проекта Vulnerability Manager.

## 🎯 Назначение VM

- **Централизованный сбор логов** со всех VM проекта
- **Мониторинг состояния** сервисов и приложений
- **Управление развертыванием** через CI/CD
- **Визуализация метрик** и дашборды
- **Алертинг** при проблемах

## 💻 Рекомендуемые технические характеристики

### Минимальная конфигурация (для начала)

| Параметр | Значение | Обоснование |
|----------|----------|-------------|
| **CPU** | 2 ядра (2 vCPU) | Достаточно для сбора логов и базового мониторинга |
| **ОЗУ** | 4 GB | Для работы системы мониторинга и хранения индексов |
| **HDD** | 50 GB SSD | Для хранения логов и метрик (можно расширить) |
| **Сеть** | 1 Gbps | Для сбора данных с других VM |

### Рекомендуемая конфигурация (production)

| Параметр | Значение | Обоснование |
|----------|----------|-------------|
| **CPU** | 4 ядра (4 vCPU) | Для обработки большого объема логов |
| **ОЗУ** | 8 GB | Для Elasticsearch/Loki и Grafana |
| **HDD** | 100 GB SSD + 200 GB HDD | SSD для индексов, HDD для архивных логов |
| **Сеть** | 1 Gbps | Для стабильного сбора данных |

### Оптимальная конфигурация (масштабирование)

| Параметр | Значение | Обоснование |
|----------|----------|-------------|
| **CPU** | 8 ядер (8 vCPU) | Для обработки больших объемов данных |
| **ОЗУ** | 16 GB | Для работы нескольких сервисов мониторинга |
| **HDD** | 200 GB SSD + 500 GB HDD | Для длительного хранения логов |
| **Сеть** | 10 Gbps | Для высоконагруженных систем |

## 🐧 Операционная система

### Рекомендация: **Ubuntu Server 22.04 LTS**

**Преимущества:**
- ✅ Долгосрочная поддержка (LTS до 2027)
- ✅ Стабильность и надежность
- ✅ Хорошая поддержка Docker и контейнеризации
- ✅ Большое сообщество и документация
- ✅ Совместимость с существующими VM проекта

**Альтернативы:**
- **Debian 12** - более легковесная, но требует больше ручной настройки
- **CentOS Stream 9** - для enterprise окружений
- **Rocky Linux 9** - альтернатива CentOS

### Установка Ubuntu Server 22.04 LTS

```bash
# Минимальная установка с SSH сервером
# Выбрать опции:
# - OpenSSH server
# - Standard system utilities
# - Без GUI (серверная версия)
```

## 📦 Рекомендуемый стек ПО

### 1. Система сбора и хранения логов

#### Вариант A: ELK Stack (Elasticsearch + Logstash + Kibana)

**Состав:**
- **Elasticsearch** - хранение и индексация логов
- **Logstash** - сбор и обработка логов
- **Kibana** - визуализация и поиск

**Требования:**
- CPU: 4+ ядер
- RAM: 8+ GB
- HDD: 100+ GB SSD

**Установка:**
```bash
# Docker Compose установка
docker-compose -f elk-stack.yml up -d
```

**Преимущества:**
- ✅ Мощный поиск по логам
- ✅ Гибкая визуализация
- ✅ Масштабируемость
- ✅ Широкое распространение

**Недостатки:**
- ❌ Высокие требования к ресурсам
- ❌ Сложность настройки

#### Вариант B: Loki + Promtail + Grafana (рекомендуется)

**Состав:**
- **Loki** - хранение логов (легковесный)
- **Promtail** - сбор логов
- **Grafana** - визуализация

**Требования:**
- CPU: 2+ ядра
- RAM: 4+ GB
- HDD: 50+ GB

**Установка:**
```bash
# Docker Compose установка
docker-compose -f loki-stack.yml up -d
```

**Преимущества:**
- ✅ Низкие требования к ресурсам
- ✅ Простая настройка
- ✅ Интеграция с Prometheus
- ✅ Эффективное хранение

**Недостатки:**
- ❌ Меньше функций поиска чем в Elasticsearch

#### Вариант C: Graylog (для средних проектов)

**Состав:**
- **Graylog** - все в одном (сбор, хранение, визуализация)
- **MongoDB** - метаданные
- **Elasticsearch** - хранение логов

**Требования:**
- CPU: 4+ ядра
- RAM: 8+ GB
- HDD: 100+ GB

**Преимущества:**
- ✅ Все в одном решении
- ✅ Хорошая документация
- ✅ Встроенный алертинг

### 2. Система мониторинга метрик

#### Prometheus + Grafana (рекомендуется)

**Состав:**
- **Prometheus** - сбор метрик
- **Grafana** - визуализация метрик
- **Node Exporter** - метрики системы
- **cAdvisor** - метрики контейнеров

**Требования:**
- CPU: 2+ ядра
- RAM: 4+ GB
- HDD: 20+ GB

**Установка:**
```bash
# Docker Compose установка
docker-compose -f prometheus-grafana.yml up -d
```

**Преимущества:**
- ✅ Стандарт индустрии
- ✅ Мощная визуализация
- ✅ Интеграция с Loki
- ✅ Гибкие алерты

### 3. Система управления развертыванием

#### GitLab Runner / GitHub Actions Runner

**Для GitLab:**
```bash
# Установка GitLab Runner
curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
sudo apt-get install gitlab-runner
```

**Для GitHub Actions:**
```bash
# Установка GitHub Actions Runner
mkdir actions-runner && cd actions-runner
curl -o actions-runner-linux-x64-2.311.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.311.0/actions-runner-linux-x64-2.311.0.tar.gz
tar xzf ./actions-runner-linux-x64-2.311.0.tar.gz
```

**Требования:**
- CPU: 2+ ядра
- RAM: 4+ GB
- HDD: 50+ GB (для Docker образов)

### 4. Дополнительные инструменты

#### Ansible (для автоматизации развертывания)

```bash
sudo apt-get update
sudo apt-get install ansible
```

#### Docker & Docker Compose

```bash
# Установка Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Установка Docker Compose
sudo apt-get install docker-compose-plugin
```

#### Nginx (для reverse proxy)

```bash
sudo apt-get install nginx
```

## 🏗️ Рекомендуемая архитектура

### Вариант 1: Легковесный (для начала)

```
┌─────────────────────────────────────┐
│     Monitoring VM (4 GB RAM)        │
├─────────────────────────────────────┤
│  - Loki (логи)                      │
│  - Prometheus (метрики)             │
│  - Grafana (визуализация)           │
│  - GitLab Runner (CI/CD)            │
│  - Nginx (reverse proxy)            │
└─────────────────────────────────────┘
```

**Требования:**
- CPU: 2 ядра
- RAM: 4 GB
- HDD: 50 GB SSD

### Вариант 2: Стандартный (рекомендуется)

```
┌─────────────────────────────────────┐
│   Monitoring VM (8 GB RAM)          │
├─────────────────────────────────────┤
│  - Loki + Promtail (логи)           │
│  - Prometheus (метрики)             │
│  - Grafana (визуализация)           │
│  - Alertmanager (алерты)            │
│  - GitLab Runner (CI/CD)            │
│  - Ansible (автоматизация)          │
│  - Nginx (reverse proxy)            │
└─────────────────────────────────────┘
```

**Требования:**
- CPU: 4 ядра
- RAM: 8 GB
- HDD: 100 GB SSD

### Вариант 3: Полнофункциональный

```
┌─────────────────────────────────────┐
│  Monitoring VM (16 GB RAM)          │
├─────────────────────────────────────┤
│  - Elasticsearch + Logstash + Kibana│
│  - Prometheus + Grafana             │
│  - Alertmanager                     │
│  - GitLab Runner                    │
│  - Ansible Tower                    │
│  - Nginx                            │
│  - Redis (кэширование)              │
└─────────────────────────────────────┘
```

**Требования:**
- CPU: 8 ядер
- RAM: 16 GB
- HDD: 200 GB SSD + 500 GB HDD

## 📝 Пошаговая установка (рекомендуемый вариант)

### Шаг 1: Установка базовой системы

```bash
# Обновление системы
sudo apt-get update && sudo apt-get upgrade -y

# Установка базовых утилит
sudo apt-get install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    ufw \
    fail2ban
```

### Шаг 2: Установка Docker и Docker Compose

```bash
# Установка Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Добавление пользователя в группу docker
sudo usermod -aG docker $USER

# Установка Docker Compose
sudo apt-get install -y docker-compose-plugin

# Проверка установки
docker --version
docker compose version
```

### Шаг 3: Установка Loki Stack

```bash
# Создание директории для конфигурации
mkdir -p ~/monitoring/loki
cd ~/monitoring/loki

# Создание docker-compose.yml для Loki
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  loki:
    image: grafana/loki:latest
    ports:
      - "3100:3100"
    command: -config.file=/etc/loki/local-config.yaml
    volumes:
      - ./loki-data:/loki
    networks:
      - monitoring

  promtail:
    image: grafana/promtail:latest
    volumes:
      - /var/log:/var/log:ro
      - ./promtail-config.yml:/etc/promtail/config.yml
    command: -config.file=/etc/promtail/config.yml
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./grafana-data:/var/lib/grafana
    networks:
      - monitoring
    depends_on:
      - loki

networks:
  monitoring:
    driver: bridge
EOF

# Запуск
docker compose up -d
```

### Шаг 4: Установка Prometheus + Grafana

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
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./grafana-data:/var/lib/grafana
    networks:
      - monitoring
    depends_on:
      - prometheus

networks:
      monitoring:
        driver: bridge
EOF

# Создание конфигурации Prometheus
cat > prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
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
```

### Шаг 6: Настройка файрвола

```bash
# Разрешить SSH
sudo ufw allow 22/tcp

# Разрешить Grafana
sudo ufw allow 3000/tcp
sudo ufw allow 3001/tcp

# Разрешить Prometheus
sudo ufw allow 9090/tcp

# Разрешить Loki
sudo ufw allow 3100/tcp

# Включить файрвол
sudo ufw enable
```

## 🔧 Конфигурация для проекта Vulnerability Manager

### Настройка сбора логов с других VM

**IP адреса VM проекта:**
- Frontend: 10.0.88.10
- Backend: 10.0.88.20
- Database: 10.0.88.11
- Parsers: 10.0.88.23
- ML Platform: 10.0.88.25

### Promtail конфигурация для сбора логов

```yaml
# promtail-config.yml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: backend
    static_configs:
      - targets:
          - localhost
        labels:
          job: backend
          vm: monitoring
          __path__: /var/log/backend/*.log

  - job_name: frontend
    static_configs:
      - targets:
          - localhost
        labels:
          job: frontend
          vm: monitoring
          __path__: /var/log/frontend/*.log

  - job_name: parsers
    static_configs:
      - targets:
          - localhost
        labels:
          job: parsers
          vm: monitoring
          __path__: /var/log/parsers/*.log
```

## 📊 Мониторинг ресурсов

### Рекомендуемые метрики для отслеживания:

1. **CPU использование** - не более 70%
2. **RAM использование** - не более 80%
3. **Дисковое пространство** - не более 85%
4. **Сетевая активность** - мониторинг трафика
5. **Доступность сервисов** - uptime мониторинг

## 🔐 Безопасность

### Рекомендации:

1. **Настроить fail2ban** для защиты от брутфорса
2. **Использовать SSH ключи** вместо паролей
3. **Регулярно обновлять систему**
4. **Настроить бэкапы** конфигураций
5. **Ограничить доступ** к портам мониторинга

## 💰 Оценка стоимости (для облачных провайдеров)

### Минимальная конфигурация:
- **AWS EC2**: t3.medium (2 vCPU, 4 GB) - ~$30/месяц
- **DigitalOcean**: Droplet 4GB - ~$24/месяц
- **Hetzner**: CX21 (2 vCPU, 4 GB) - ~$5/месяц

### Рекомендуемая конфигурация:
- **AWS EC2**: t3.large (2 vCPU, 8 GB) - ~$60/месяц
- **DigitalOcean**: Droplet 8GB - ~$48/месяц
- **Hetzner**: CPX21 (3 vCPU, 8 GB) - ~$10/месяц

## 📚 Дополнительные ресурсы

- [Loki Documentation](https://grafana.com/docs/loki/latest/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/grafana/latest/)
- [GitLab Runner Documentation](https://docs.gitlab.com/runner/)

## ✅ Чеклист настройки

- [ ] Установлена Ubuntu Server 22.04 LTS
- [ ] Настроен SSH доступ
- [ ] Установлен Docker и Docker Compose
- [ ] Развернут Loki Stack
- [ ] Развернут Prometheus + Grafana
- [ ] Настроен GitLab Runner
- [ ] Настроен файрвол
- [ ] Настроен сбор логов с других VM
- [ ] Настроены дашборды в Grafana
- [ ] Настроены алерты
- [ ] Настроены бэкапы

---

**Последнее обновление:** 2025-01-20  
**Версия:** 1.0

