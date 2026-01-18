# 🚨 Критическое исправление: Prometheus недоступен

**Дата:** 2025-01-18  
**Проблема:** Prometheus стал недоступен после изменений конфигурации

---

## 🔴 Проблема

- ❌ Prometheus недоступен: http://10.0.88.41:9090
- ❌ Ошибка Docker сети: `iptables: No chain/target/match by that name`
- ❌ Порт 9090 не слушается

---

## ✅ Решение

### Причина

Проблема с iptables и Docker сетью после изменений. Docker не может создать правила iptables для проброса портов.

### Исправление

**Использован host network mode** для обхода проблемы с Docker сетью:

```bash
# На Monitoring VM
ssh test@10.0.88.41
cd ~/monitoring/monitoring-stack/prometheus

# Остановить Prometheus
docker compose down

# Обновить docker-compose.yml для использования host network
cat > docker-compose.yml << 'EOF'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    network_mode: host
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    restart: unless-stopped
EOF

# Запустить Prometheus
docker compose up -d
```

---

## ✅ Результат

После исправления:
- ✅ Prometheus доступен: http://10.0.88.41:9090
- ✅ Контейнер запущен
- ✅ Порт 9090 слушается

---

## 🔍 Проверка

```bash
# Проверить статус
curl http://10.0.88.41:9090

# Проверить контейнер
ssh test@10.0.88.41
docker ps | grep prometheus
```

---

## ⚠️ Примечание

Использование `network_mode: host` означает, что Prometheus использует сеть хоста напрямую, что обходит проблемы с Docker сетью и iptables.

---

**Статус:** ✅ Исправлено - Prometheus должен быть доступен

