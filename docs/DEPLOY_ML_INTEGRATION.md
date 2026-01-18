# 🚀 Деплой интеграции ML платформы

## ✅ Проверка перед деплоем

### 1. Изменения только в разделе ИИ-анализа
- ✅ `templates/ai/dashboard.html` - обновлен
- ✅ `templates/ai/statistics.html` - обновлен
- ✅ `templates/ai/training.html` - обновлен
- ✅ `templates/ai/monitoring.html` - обновлен
- ✅ `templates/ai/passports.html` - обновлен
- ✅ `templates/dashboard.html` - **НЕ ИЗМЕНЕН** (основной дашборд)

### 2. Новые файлы
- ✅ `services/ml_platform_client.py` - клиент для ML платформы
- ✅ `docs/ML_PLATFORM_INTEGRATION.md` - документация

### 3. Обновленные файлы
- ✅ `services/backend/app.py` - добавлены API endpoints
- ✅ `requirements.txt` - добавлен `paramiko>=3.0.0`

## 📋 Шаги деплоя

### 1. На Backend VM (10.0.88.20)

```bash
# 1. Остановить сервис
sudo systemctl stop vulnerability-manager-backend

# 2. Обновить код
cd /path/to/vulnerability_manager
git pull  # или скопировать файлы

# 3. Установить зависимости
pip3 install -r requirements.txt --break-system-packages

# 4. Проверить подключение к ML платформе
python3 -c "
from services.ml_platform_client import ml_platform_client
status = ml_platform_client.check_connection()
print('ML Platform Status:', status)
"

# 5. Запустить сервис
sudo systemctl start vulnerability-manager-backend
sudo systemctl status vulnerability-manager-backend
```

### 2. Проверка после деплоя

```bash
# Проверить API endpoints
curl http://10.0.88.20:5000/api/ml-platform/connection

# Проверить логи
sudo journalctl -u vulnerability-manager-backend -f
```

### 3. На Frontend (если нужно)

Обычно фронтенд не требует изменений, так как все изменения в шаблонах на бэкенде.

## 🔍 Проверка работы

1. Открыть сайт: `http://10.0.88.10`
2. Перейти в раздел **"ИИ-Анализ"** (в навигации)
3. Проверить:
   - ✅ Статус подключения к ML платформе отображается
   - ✅ Кнопки управления работают
   - ✅ Статистика загружается

## ⚠️ Устранение неполадок

### Изменения не видны на сайте

1. **Очистить кэш браузера**: Ctrl+Shift+R (или Cmd+Shift+R на Mac)
2. **Проверить, что сервер перезапущен**:
   ```bash
   sudo systemctl restart vulnerability-manager-backend
   ```
3. **Проверить логи**:
   ```bash
   sudo journalctl -u vulnerability-manager-backend -n 50
   ```

### ML платформа недоступна

1. Проверить SSH подключение:
   ```bash
   ssh k8s-worker@10.0.88.25
   ```

2. Проверить HTTP API:
   ```bash
   curl http://10.0.88.25:8000/health
   ```

3. Проверить, что FastAPI сервер запущен на k8s-worker

## 📝 Чеклист деплоя

- [ ] Код обновлен на Backend VM
- [ ] Зависимости установлены (`paramiko`)
- [ ] Backend сервис перезапущен
- [ ] Проверено подключение к ML платформе
- [ ] Проверена работа через веб-интерфейс
- [ ] Логи проверены на ошибки

## ✅ Готово к деплою

Все изменения только в разделе ИИ-анализа, основной дашборд не затронут.

