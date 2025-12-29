# 🚀 Синхронизация CVE с прогрессом и пакетной обработкой

## Обзор

Система синхронизации CVE была обновлена для:
- **Пакетной обработки**: Загрузка и сохранение по 1000 CVE за раз
- **Обновления статуса**: Реальное время прогресса синхронизации
- **API для фронтенда**: Endpoints для получения статуса синхронизации

## Изменения

### 1. Пакетная обработка по 1000 CVE

В `services/cve_org_integration_service.py`:
- Размер пакета фиксирован: **1000 CVE** за итерацию
- После каждого пакета данные сохраняются в БД
- Прогресс логируется после каждого пакета

### 2. Статус синхронизации

Создан модуль `services/backend/cve_sync_status.py`:
- Хранит текущий статус синхронизации
- Thread-safe обновления
- Поддержка прогресса в реальном времени

### 3. API Endpoints

Добавлены новые endpoints в `services/backend/app.py`:

#### GET `/api/cve-sync/status`
Получить текущий статус синхронизации CVE

**Response:**
```json
{
  "success": true,
  "status": {
    "status": "running",
    "start_time": "2025-12-28T10:00:00",
    "total_cves": 380000,
    "processed_cves": 5000,
    "saved_cves": 5000,
    "current_batch": 5,
    "total_batches": 380,
    "progress_percent": 1.32,
    "last_update": "2025-12-28T10:05:00"
  }
}
```

#### POST `/api/cve-sync/reset`
Сбросить статус синхронизации

**Response:**
```json
{
  "success": true,
  "message": "Статус синхронизации сброшен"
}
```

## Использование

### Запуск синхронизации

```bash
# На Backend VM
ssh user@10.0.88.20
echo '123' | sudo -S docker exec -d vulnerability-backend python3 /app/services/full_cve_sync.py
```

### Мониторинг через API

```javascript
// JavaScript пример для фронтенда
async function checkSyncStatus() {
  const response = await fetch('/api/cve-sync/status', {
    credentials: 'include'
  });
  const data = await response.json();
  
  if (data.success) {
    const status = data.status;
    console.log(`Прогресс: ${status.progress_percent.toFixed(1)}%`);
    console.log(`Пакет: ${status.current_batch}/${status.total_batches}`);
    console.log(`Сохранено: ${status.saved_cves}/${status.total_cves}`);
  }
}

// Проверка каждые 5 секунд
setInterval(checkSyncStatus, 5000);
```

### Мониторинг через логи

```bash
# Логи синхронизации
echo '123' | sudo -S docker exec vulnerability-backend tail -f /app/logs/full_cve_sync.log

# Статус процесса
echo '123' | sudo -S docker exec vulnerability-backend ps aux | grep full_cve
```

## Процесс синхронизации

1. **Загрузка репозитория**: Клонирование/обновление `cvelistV5`
2. **Итерация по файлам**: Загрузка всех CVE JSON файлов
3. **Пакетная обработка**:
   - Пакет 1: CVE 1-1000 → Парсинг → Сохранение в БД → Обновление статуса
   - Пакет 2: CVE 1001-2000 → Парсинг → Сохранение в БД → Обновление статуса
   - ...
   - Пакет N: CVE (N-1)*1000+1 - N*1000 → Парсинг → Сохранение в БД → Обновление статуса
4. **Завершение**: Обновление финального статуса

## Преимущества

✅ **Прогресс в реальном времени**: Фронтенд может отслеживать прогресс синхронизации

✅ **Эффективное использование памяти**: Обработка по 1000 записей вместо загрузки всех в память

✅ **Надежность**: После каждого пакета данные сохраняются, минимизируя потери при сбоях

✅ **Мониторинг**: API позволяет отслеживать статус без прямого доступа к логам

## Деплой

1. Скопировать обновленные файлы на VM
2. Скопировать в Docker контейнер
3. Перезапустить backend (если нужно)
4. Запустить синхронизацию

```bash
# Копирование файлов
sshpass -p "123" scp services/cve_org_integration_service.py services/backend/cve_sync_status.py services/backend/app.py services/full_cve_sync.py user@10.0.88.20:/tmp/

# В контейнер
echo '123' | sudo -S docker cp /tmp/cve_org_integration_service.py vulnerability-backend:/app/services/
echo '123' | sudo -S docker cp /tmp/cve_sync_status.py vulnerability-backend:/app/services/backend/
echo '123' | sudo -S docker cp /tmp/app.py vulnerability-backend:/app/services/backend/
echo '123' | sudo -S docker cp /tmp/full_cve_sync.py vulnerability-backend:/app/services/

# Перезапуск (опционально)
echo '123' | sudo -S docker restart vulnerability-backend
```

## Пример интеграции с фронтендом

```html
<div id="sync-progress">
  <h3>Синхронизация CVE</h3>
  <div id="sync-status">Ожидание...</div>
  <div id="sync-progress-bar">
    <div id="sync-progress-fill" style="width: 0%"></div>
  </div>
  <div id="sync-details"></div>
</div>

<script>
async function updateSyncStatus() {
  try {
    const response = await fetch('/api/cve-sync/status');
    const data = await response.json();
    
    if (data.success && data.status) {
      const status = data.status;
      
      // Обновление статуса
      document.getElementById('sync-status').textContent = 
        `Статус: ${status.status} | ${status.progress_percent.toFixed(1)}%`;
      
      // Обновление прогресс-бара
      document.getElementById('sync-progress-fill').style.width = 
        `${status.progress_percent}%`;
      
      // Детали
      document.getElementById('sync-details').innerHTML = `
        Пакет: ${status.current_batch}/${status.total_batches}<br>
        Сохранено: ${status.saved_cves}/${status.total_cves}<br>
        Последнее обновление: ${new Date(status.last_update).toLocaleString()}
      `;
      
      // Автоматическое обновление если синхронизация в процессе
      if (status.status === 'running') {
        setTimeout(updateSyncStatus, 5000); // Проверка каждые 5 секунд
      }
    }
  } catch (error) {
    console.error('Ошибка получения статуса:', error);
  }
}

// Запуск обновления
updateSyncStatus();
</script>
```

