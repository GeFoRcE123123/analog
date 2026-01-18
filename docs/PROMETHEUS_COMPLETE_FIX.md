# ✅ Полное исправление Prometheus Targets

**Дата:** 2025-01-18

---

## 🎯 Выполненные действия

### 1. ✅ Запущен postgres-exporter на Database VM

**Команды:**
```bash
ssh user@10.0.88.11
docker run -d --name postgres-exporter \
  --restart unless-stopped \
  -p 9187:9187 \
  -e DATA_SOURCE_NAME='postgresql://admin:123@localhost:5432/vuln_db?sslmode=disable' \
  prometheuscommunity/postgres-exporter:latest
```

**Результат:**
- ✅ Контейнер запущен
- ✅ Метрики доступны: http://10.0.88.11:9187/metrics
- ✅ Target в Prometheus должен показывать UP

### 2. ✅ Исправлена конфигурация Prometheus для Parsers

**Проблема:** Prometheus был настроен на порт 9090, но парсеры работают на порту 8000

**Решение:**
```bash
# На Monitoring VM
ssh test@10.0.88.41
cd ~/monitoring/monitoring-stack/prometheus

# Изменить порт с 9090 на 8000
sed -i 's/10.0.88.23:9090/10.0.88.23:8000/g' prometheus.yml

# Перезапустить Prometheus
docker compose restart prometheus
```

**Результат:**
- ✅ Конфигурация обновлена
- ✅ Prometheus перезапущен
- ⚠️ Требуется проверка, что парсеры экспортируют метрики на порту 8000

### 3. ✅ Проверка статуса в Prometheus

**URL:** http://10.0.88.41:9090  
**Путь:** Status → Target health

---

## 📊 Ожидаемый статус targets

| Target | Ожидаемый статус | URL метрик |
|--------|------------------|------------|
| **backend** | ✅ UP | http://10.0.88.20:5000/api/metrics |
| **frontend** | ✅ UP | http://10.0.88.10:80/metrics |
| **postgres-exporter** | ✅ UP | http://10.0.88.11:9187/metrics |
| **ml-platform** | ✅ UP | http://10.0.88.25:8000/metrics |
| **parsers** | ⚠️ Зависит от экспорта | http://10.0.88.23:8000/metrics |

---

## 🔍 Проверка результатов

### Через Prometheus UI:

1. Откройте: http://10.0.88.41:9090
2. Перейдите: **Status** → **Target health**
3. Проверьте статус каждого target:
   - ✅ **UP** - сервис работает
   - ❌ **DOWN** - сервис недоступен

### Через API:

```bash
curl http://10.0.88.41:9090/api/v1/targets | python3 -m json.tool
```

Ищите поле `"health": "up"` для каждого target.

---

## ⚠️ Если Parsers все еще DOWN

### Проверка экспорта метрик:

```bash
# На Parsers VM
ssh user@10.0.88.23
curl http://localhost:8000/metrics
```

### Если метрики не экспортируются:

1. **Добавить экспорт метрик в код парсеров:**
   - Использовать библиотеку `prometheus_client`
   - Экспортировать метрики на порту 8000 или 9090

2. **Или использовать node-exporter:**
   - Установить node-exporter на Parsers VM
   - Экспортировать системные метрики

---

## ✅ Итоги

1. ✅ **postgres-exporter запущен** - Database метрики работают
2. ✅ **Конфигурация Prometheus обновлена** - Parsers настроены на порт 8000
3. ✅ **Prometheus перезапущен** - изменения применены
4. ⚠️ **Требуется проверка** - что парсеры экспортируют метрики

---

## 🔗 Связанные документы

- [PROMETHEUS_USER_GUIDE.md](./PROMETHEUS_USER_GUIDE.md) - Руководство по Prometheus
- [PROMETHEUS_ALERTS_FIX.md](./PROMETHEUS_ALERTS_FIX.md) - Исправление алертов
- [scripts/setup_postgres_exporter.sh](../scripts/setup_postgres_exporter.sh) - Скрипт установки

---

**После проверки все targets должны показывать статус UP!**

