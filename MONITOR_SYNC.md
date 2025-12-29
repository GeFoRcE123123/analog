# 📊 Мониторинг синхронизации CVE

## Команды для мониторинга

### 1. Статус синхронизации через API

```bash
# После авторизации через браузер, получите cookies или используйте токен
curl -b cookies.txt http://10.0.88.20/api/cve-sync/status | python3 -m json.tool
```

Ответ:
```json
{
  "success": true,
  "status": {
    "status": "running",
    "start_time": "2025-12-28T11:00:00",
    "total_cves": 243203,
    "processed_cves": 5000,
    "saved_cves": 5000,
    "current_batch": 5,
    "total_batches": 244,
    "progress_percent": 2.05,
    "last_update": "2025-12-28T11:05:00"
  }
}
```

### 2. Логи синхронизации в реальном времени

```bash
ssh user@10.0.88.20
echo '123' | sudo -S docker exec vulnerability-backend tail -f /app/logs/full_cve_sync.log
```

### 3. Проверка процесса синхронизации

```bash
ssh user@10.0.88.20
echo '123' | sudo -S docker exec vulnerability-backend ps aux | grep full_cve
```

### 4. Количество сохраненных уязвимостей в БД

```bash
ssh user@10.0.88.20
echo '123' | sudo -S docker exec -i vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) FROM turn;"
```

### 5. Статистика по источникам

```bash
ssh user@10.0.88.20
echo '123' | sudo -S docker exec -i vulnerability_db psql -U admin -d vuln_db -c "SELECT source_identifier, COUNT(*) FROM turn GROUP BY source_identifier;"
```

### 6. Последние сохраненные уязвимости

```bash
ssh user@10.0.88.20
echo '123' | sudo -S docker exec -i vulnerability_db psql -U admin -d vuln_db -c "SELECT cve_id, title, created_date FROM turn ORDER BY created_date DESC LIMIT 10;"
```

## Интеграция с фронтендом

После авторизации на фронтенде можно периодически запрашивать статус:

```javascript
// JavaScript для фронтенда
async function checkSyncStatus() {
  const response = await fetch('/api/cve-sync/status');
  const data = await response.json();
  
  if (data.success && data.status) {
    const status = data.status;
    console.log(`Статус: ${status.status}`);
    console.log(`Прогресс: ${status.progress_percent.toFixed(1)}%`);
    console.log(`Пакет: ${status.current_batch}/${status.total_batches}`);
    console.log(`Сохранено: ${status.saved_cves}/${status.total_cves}`);
    
    // Обновление UI
    updateProgressBar(status.progress_percent);
  }
}

// Проверка каждые 5 секунд
setInterval(checkSyncStatus, 5000);
```

## Ожидаемое время

- **Полная синхронизация**: 2-4 часа для ~380,000 CVE
- **Пакет**: ~1000 CVE за 2-5 минут (зависит от сложности данных)

