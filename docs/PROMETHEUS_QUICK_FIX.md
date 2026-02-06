# ⚡ Быстрое исправление: Все сервисы DOWN в Prometheus

## 🎯 Проблема

Все targets показывают статус **DOWN** в Prometheus:
- Backend (10.0.88.20:5000) - 404 NOT FOUND
- Frontend (10.0.88.10:80) - 404 NOT FOUND
- Database (10.0.88.11:9187) - недоступен
- Parsers (10.0.88.23:9090) - недоступен
- ML Platform (10.0.88.25:8000) - недоступен

## 🔧 Решение

### 1. Проверить доступность сервисов

```bash
# С Monitoring VM
ssh test@10.0.88.41
# Password: 123

# Проверить каждый сервис
curl http://10.0.88.10:80/metrics          # Frontend
curl http://10.0.88.20:5000/api/metrics    # Backend
curl http://10.0.88.11:9187/metrics        # Database
curl http://10.0.88.23:9090/metrics        # Parsers
curl http://10.0.88.25:8000/metrics        # ML Platform
```

### 2. Запустить сервисы на каждой VM

**Backend (10.0.88.20):**
```bash
ssh user@10.0.88.20
cd ~/vulnerability_manager/services/backend
docker compose up -d
```

**Frontend (10.0.88.10):**
```bash
ssh user@10.0.88.10
sudo systemctl start nginx
```

**Database (10.0.88.11):**
```bash
ssh user@10.0.88.11
# Проверить postgres-exporter
docker ps | grep postgres-exporter
```

**Parsers (10.0.88.23):**
```bash
ssh user@10.0.88.23
cd ~/vulnerability_manager
docker compose up -d
```

**ML Platform (10.0.88.25):**
```bash
ssh k8s-worker@10.0.88.25
kubectl get pods
# или
docker compose up -d
```

### 3. Проверить endpoints метрик

Убедитесь, что метрики доступны по правильным путям:
- Backend: `/api/metrics` (не `/metrics`)
- Frontend: `/metrics`
- Database: `/metrics` (postgres-exporter)
- Parsers: `/metrics`
- ML Platform: `/metrics`

### 4. Перезапустить Prometheus

```bash
# На Monitoring VM
cd ~/monitoring/monitoring-stack/prometheus
docker compose restart prometheus
```

## ✅ Проверка

1. Откройте Prometheus: http://10.0.88.41:9090
2. Перейдите: **Status** → **Target health**
3. Все targets должны показывать **UP**

## 📚 Подробнее

См. [PROMETHEUS_ALERTS_FIX.md](./PROMETHEUS_ALERTS_FIX.md) для детальной диагностики.

