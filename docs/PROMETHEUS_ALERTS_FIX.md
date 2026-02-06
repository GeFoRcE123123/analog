# 🔧 Исправление алертов Prometheus: Все сервисы DOWN

**Проблема:** Все targets показывают статус DOWN в Prometheus  
**Дата:** 2025-01-18

---

## 🎯 Проблема

Prometheus показывает, что все сервисы недоступны:
- ❌ Backend (10.0.88.20:5000)
- ❌ Frontend (10.0.88.10:80)
- ❌ Database (10.0.88.11:9187)
- ❌ Parsers (10.0.88.23:9090)
- ❌ ML Platform (10.0.88.25:8000)

**Статус алертов:** FIRING (критический)

---

## 🔍 Диагностика

### Шаг 1: Проверка доступности сервисов

```bash
# С Monitoring VM (10.0.88.41)
ssh test@10.0.88.41
# Password: 123

# Проверить доступность каждого сервиса
curl http://10.0.88.10:80/metrics          # Frontend
curl http://10.0.88.20:5000/api/metrics    # Backend
curl http://10.0.88.11:9187/metrics        # Database (postgres-exporter)
curl http://10.0.88.23:9090/metrics        # Parsers
curl http://10.0.88.25:8000/metrics         # ML Platform
```

### Шаг 2: Проверка конфигурации Prometheus

```bash
# На Monitoring VM
cat ~/monitoring/monitoring-stack/prometheus/prometheus.yml
```

Проверьте, что конфигурация содержит правильные targets.

### Шаг 3: Проверка статуса targets в Prometheus

1. Откройте: http://10.0.88.41:9090
2. Перейдите: **Status** → **Target health**
3. Проверьте статус каждого target

---

## 🔧 Решение

### Вариант 1: Сервисы не запущены на других VM

**Проверьте и запустите сервисы на каждой VM:**

#### Backend VM (10.0.88.20):
```bash
ssh user@10.0.88.20
# Password: 123

# Проверить статус
docker ps
sudo systemctl status vulnerability-manager-backend

# Запустить если не работает
cd ~/vulnerability_manager/services/backend
docker compose up -d
```

#### Frontend VM (10.0.88.10):
```bash
ssh user@10.0.88.10
# Password: 123

# Проверить статус
docker ps
sudo systemctl status nginx

# Запустить если не работает
sudo systemctl start nginx
```

#### Database VM (10.0.88.11):
```bash
ssh user@10.0.88.11
# Password: 123

# Проверить postgres-exporter
docker ps | grep postgres-exporter

# Запустить если не работает
# (зависит от конфигурации)
```

#### Parsers VM (10.0.88.23):
```bash
ssh user@10.0.88.23
# Password: 123

# Проверить статус
docker ps
# Запустить парсеры
```

#### ML Platform VM (10.0.88.25):
```bash
ssh k8s-worker@10.0.88.25
# Password: k8s-worker

# Проверить статус
kubectl get pods
# или
docker ps
```

### Вариант 2: Экспортеры метрик не запущены

**Убедитесь, что на каждой VM запущены экспортеры метрик:**

#### Backend должен экспортировать метрики:
- Endpoint: `/api/metrics`
- Проверка: `curl http://10.0.88.20:5000/api/metrics`

#### Frontend должен экспортировать метрики:
- Endpoint: `/metrics` (обычно через nginx)
- Проверка: `curl http://10.0.88.10:80/metrics`

#### Database должен иметь postgres-exporter:
- Endpoint: `/metrics` на порту 9187
- Проверка: `curl http://10.0.88.11:9187/metrics`

### Вариант 3: Проблемы с сетью

**Проверьте сетевую связность:**

```bash
# С Monitoring VM
ping 10.0.88.10  # Frontend
ping 10.0.88.20  # Backend
ping 10.0.88.11  # Database
ping 10.0.88.23  # Parsers
ping 10.0.88.25  # ML Platform
```

### Вариант 4: Неправильная конфигурация Prometheus

**Проверьте и исправьте конфигурацию:**

```bash
# На Monitoring VM
cd ~/monitoring/monitoring-stack/prometheus
cat prometheus.yml
```

**Пример правильной конфигурации:**

```yaml
scrape_configs:
  - job_name: 'backend'
    static_configs:
      - targets: ['10.0.88.20:5000']
        labels:
          instance: 'backend-vm'
          role: 'backend'
          vm_ip: '10.0.88.20'
    metrics_path: '/api/metrics'
    
  - job_name: 'frontend'
    static_configs:
      - targets: ['10.0.88.10:80']
        labels:
          instance: 'frontend-vm'
          role: 'frontend'
          vm_ip: '10.0.88.10'
    metrics_path: '/metrics'
    
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['10.0.88.11:9187']
        labels:
          instance: 'database-vm'
          role: 'database'
          vm_ip: '10.0.88.11'
    metrics_path: '/metrics'
    
  - job_name: 'parsers'
    static_configs:
      - targets: ['10.0.88.23:9090']
        labels:
          instance: 'parsers-vm'
          role: 'parsers'
          vm_ip: '10.0.88.23'
    metrics_path: '/metrics'
    
  - job_name: 'ml-platform'
    static_configs:
      - targets: ['10.0.88.25:8000']
        labels:
          instance: 'ml-platform-vm'
          role: 'ml-platform'
          vm_ip: '10.0.88.25'
    metrics_path: '/metrics'
```

**После изменения конфигурации:**
```bash
cd ~/monitoring/monitoring-stack/prometheus
docker compose restart prometheus
```

---

## 🔍 Детальная диагностика

### Проверка через Prometheus API:

```bash
# На Monitoring VM
curl http://localhost:9090/api/v1/targets | python3 -m json.tool
```

Ищите поля:
- `health: "up"` - сервис доступен
- `health: "down"` - сервис недоступен
- `lastError` - описание ошибки

### Проверка логов Prometheus:

```bash
# На Monitoring VM
docker logs prometheus --tail 50
```

Ищите ошибки подключения к targets.

---

## ✅ Чеклист исправления

- [ ] Проверена доступность всех VM (ping)
- [ ] Проверена доступность метрик каждого сервиса (curl)
- [ ] Проверена конфигурация Prometheus
- [ ] Запущены все сервисы на соответствующих VM
- [ ] Запущены экспортеры метрик
- [ ] Перезапущен Prometheus после изменения конфигурации
- [ ] Проверен статус targets в Prometheus UI
- [ ] Алерты перешли в состояние Inactive

---

## 🚀 Быстрое исправление

### Если сервисы не запущены:

```bash
# Запустить все сервисы на всех VM
# Используйте скрипты deploy или команды вручную

# Backend
ssh user@10.0.88.20 "cd ~/vulnerability_manager && docker compose up -d"

# Frontend  
ssh user@10.0.88.10 "sudo systemctl start nginx"

# Database
ssh user@10.0.88.11 "docker ps" # Проверить postgres-exporter

# Parsers
ssh user@10.0.88.23 "cd ~/vulnerability_manager && docker compose up -d"

# ML Platform
ssh k8s-worker@10.0.88.25 "kubectl get pods" # или docker compose
```

### Если проблема в конфигурации:

```bash
# На Monitoring VM
cd ~/monitoring/monitoring-stack/prometheus
# Отредактировать prometheus.yml
nano prometheus.yml
# Перезапустить
docker compose restart prometheus
```

---

## 📊 Ожидаемый результат

После исправления:
- ✅ Все targets показывают статус **UP**
- ✅ Алерты переходят в состояние **Inactive**
- ✅ Метрики собираются со всех сервисов
- ✅ Графики в Prometheus показывают данные

---

## 🔗 Связанные документы

- [PROMETHEUS_USER_GUIDE.md](./PROMETHEUS_USER_GUIDE.md) - Руководство по Prometheus
- [VM_CREDENTIALS.md](./VM_CREDENTIALS.md) - Учетные данные для VM
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Инструкции по развертыванию

---

**После исправления все сервисы должны показывать статус UP в Prometheus!**

