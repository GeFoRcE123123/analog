# 📊 Руководство по использованию Prometheus

**URL:** http://10.0.88.41:9090  
**Назначение:** Мониторинг метрик всех VM и сервисов

---

## 🚀 Быстрый старт

### 1. Открыть Prometheus

Откройте в браузере: **http://10.0.88.41:9090**

Вы увидите интерфейс с вкладками:
- **Query** - выполнение запросов
- **Alerts** - управление алертами
- **Status** - статус и конфигурация

---

## 📝 Основные функции

### 1. Выполнение запросов (Query)

#### Базовые запросы:

**Проверить доступность метрик:**
```
up
```
Показывает все доступные targets (1 = работает, 0 = недоступен)

**CPU использование:**
```
100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
```

**Использование памяти:**
```
node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes
```

**Использование диска:**
```
100 - ((node_filesystem_avail_bytes{mountpoint="/"} * 100) / node_filesystem_size_bytes{mountpoint="/"})
```

**Количество HTTP запросов (Backend):**
```
rate(http_requests_total[5m])
```

#### Полезные запросы для вашей системы:

**Статус всех VM:**
```
up{job=~"backend|frontend|database|parsers|ml-platform"}
```

**CPU по всем VM:**
```
100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
```

**Память по всем VM:**
```
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
```

**Метрики Backend API:**
```
rate(http_requests_total{job="backend"}[5m])
```

**Метрики Database:**
```
pg_stat_database_numbackends{job="postgres-exporter"}
```

---

## 🔍 Навигация по интерфейсу

### Вкладка Query

1. **Поле ввода запроса:**
   - Введите PromQL запрос
   - Нажмите `Execute` или `Enter`
   - Используйте `Shift+Enter` для многострочных запросов

2. **Режимы отображения:**
   - **Table** - таблица значений
   - **Graph** - график во времени
   - **Explain** - объяснение запроса

3. **Время выполнения:**
   - Кнопка `< Evaluation time >` - выбор времени для запроса
   - Можно выбрать конкретное время или диапазон

### Вкладка Status

#### Monitoring status:
- **Target health** - статус всех targets (VM и сервисов)
- **Rule health** - статус правил алертинга
- **Service discovery** - обнаруженные сервисы

#### Server status:
- **Runtime & build information** - информация о версии
- **TSDB status** - статус базы данных временных рядов
- **Configuration** - текущая конфигурация
- **Command-line flags** - флаги запуска

---

## 📊 Мониторинг ваших сервисов

### Доступные targets (цели мониторинга)

Prometheus собирает метрики с:

1. **Backend VM (10.0.88.20)**
   - Метрики: `http_requests_total`, `http_request_duration_seconds`
   - Job: `backend`

2. **Frontend VM (10.0.88.10)**
   - Метрики: `nginx_*`
   - Job: `frontend`

3. **Database VM (10.0.88.11)**
   - Метрики: `pg_stat_*`
   - Job: `postgres-exporter`

4. **Parsers VM (10.0.88.23)**
   - Метрики: парсеров
   - Job: `parsers`

5. **ML Platform VM (10.0.88.25)**
   - Метрики: ML сервисов
   - Job: `ml-platform`

6. **Monitoring VM (10.0.88.41)**
   - Метрики: `node_*` (системные)
   - Job: `node-exporter`, `prometheus`

---

## 🔎 Полезные запросы

### Системные метрики

**Доступность всех сервисов:**
```promql
up
```

**CPU использование по VM:**
```promql
100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
```

**Использование памяти (процент):**
```promql
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100
```

**Свободное место на диске:**
```promql
(node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100
```

**Сетевая активность (входящий трафик):**
```promql
rate(node_network_receive_bytes_total[5m])
```

**Сетевая активность (исходящий трафик):**
```promql
rate(node_network_transmit_bytes_total[5m])
```

### Метрики приложения

**HTTP запросы Backend (в секунду):**
```promql
rate(http_requests_total{job="backend"}[5m])
```

**Время ответа Backend:**
```promql
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job="backend"}[5m]))
```

**Активные подключения к БД:**
```promql
pg_stat_database_numbackends{job="postgres-exporter"}
```

**Размер БД:**
```promql
pg_database_size_bytes{job="postgres-exporter"}
```

---

## 📈 Создание графиков

### Шаг 1: Введите запрос
В поле ввода введите PromQL запрос, например:
```
up
```

### Шаг 2: Выберите режим Graph
Нажмите кнопку **"Graph"** для отображения графика

### Шаг 3: Настройте время
Используйте кнопку `< Evaluation time >` для выбора:
- **Last 15 minutes** - последние 15 минут
- **Last 1 hour** - последний час
- **Last 6 hours** - последние 6 часов
- **Last 1 day** - последний день
- **Custom range** - свой диапазон

### Шаг 4: Выполните запрос
Нажмите **"Execute"** или `Enter`

---

## 🎯 Проверка статуса targets

### Через интерфейс:

1. Нажмите **"Status"** в верхнем меню
2. Выберите **"Target health"**
3. Увидите список всех targets с их статусом:
   - ✅ **UP** - target доступен
   - ❌ **DOWN** - target недоступен

### Через запрос:

```promql
up
```

Результат:
- `up{instance="10.0.88.20:5000", job="backend"}` = 1 (работает)
- `up{instance="10.0.88.20:5000", job="backend"}` = 0 (не работает)

---

## 🔔 Алерты (Alerts)

### Просмотр активных алертов:

1. Нажмите вкладку **"Alerts"**
2. Увидите список всех настроенных алертов
3. Статусы:
   - **Firing** - алерт активен (требует внимания)
   - **Pending** - алерт ожидает подтверждения
   - **Inactive** - алерт неактивен

---

## 💡 Советы по использованию

### 1. Используйте автодополнение
При вводе запроса Prometheus предлагает доступные метрики

### 2. Изучите доступные метрики
```promql
{__name__=~".+"}
```
Покажет все доступные метрики (осторожно - может быть много)

### 3. Фильтрация по labels
```promql
up{job="backend"}
```
Показывает только метрики Backend

### 4. Агрегация данных
```promql
sum(rate(http_requests_total[5m])) by (job)
```
Суммирует запросы по job

### 5. Использование функций
- `rate()` - скорость изменения
- `increase()` - увеличение за период
- `avg()`, `sum()`, `max()`, `min()` - агрегация
- `histogram_quantile()` - процентили

---

## 🔗 Интеграция с Grafana

Prometheus используется как источник данных для Grafana:

1. Откройте Grafana: http://10.0.88.41:3000
2. Добавьте Prometheus как Data Source:
   - URL: `http://10.0.88.41:9090`
   - Access: Server (default)
3. Создавайте дашборды с визуализацией метрик

---

## 📚 Полезные ресурсы

### PromQL функции:
- `rate()` - скорость изменения метрики
- `irate()` - мгновенная скорость
- `increase()` - увеличение за период
- `avg_over_time()` - среднее за период
- `sum_over_time()` - сумма за период

### Операторы:
- `+`, `-`, `*`, `/` - арифметические
- `==`, `!=`, `>`, `<` - сравнение
- `and`, `or`, `unless` - логические

### Примеры сложных запросов:

**Средний CPU за последний час:**
```promql
avg_over_time((100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100))[1h])
```

**Топ 5 VM по использованию памяти:**
```promql
topk(5, (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100)
```

---

## 🆘 Решение проблем

### Проблема: "No data queried yet"

**Решение:**
1. Проверьте, что target доступен (Status → Target health)
2. Убедитесь, что метрика существует
3. Проверьте правильность синтаксиса запроса

### Проблема: Target показывает DOWN

**Решение:**
1. Проверьте доступность сервиса
2. Проверьте конфигурацию Prometheus
3. Проверьте сетевую связность

### Проблема: Запрос не возвращает данные

**Решение:**
1. Используйте `up` для проверки доступности
2. Проверьте labels метрики
3. Используйте `{__name__=~".+"}` для поиска метрик

---

## ✅ Чеклист для начала работы

- [ ] Открыт Prometheus: http://10.0.88.41:9090
- [ ] Проверен статус targets (Status → Target health)
- [ ] Выполнен базовый запрос `up`
- [ ] Создан первый график
- [ ] Изучены доступные метрики
- [ ] Настроена интеграция с Grafana (опционально)

---

**🎉 Теперь вы можете использовать Prometheus для мониторинга всей системы!**

