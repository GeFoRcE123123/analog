# 🚀 Быстрый деплой интеграции ML платформы

## Команды для выполнения на Backend VM (10.0.88.20)

```bash
# 1. Подключиться к VM
ssh user@10.0.88.20

# 2. Остановить сервис
sudo systemctl stop vulnerability-manager-backend

# 3. Перейти в директорию проекта
cd /path/to/vulnerability_manager  # Укажите правильный путь

# 4. Обновить код (скопировать файлы вручную или через git)
# Скопируйте следующие файлы:
# - services/ml_platform_client.py
# - services/backend/app.py
# - requirements.txt
# - templates/ai/*.html

# 5. Установить зависимости
pip3 install paramiko --break-system-packages

# 6. Запустить сервис
sudo systemctl start vulnerability-manager-backend

# 7. Проверить статус
sudo systemctl status vulnerability-manager-backend

# 8. Проверить логи
sudo journalctl -u vulnerability-manager-backend -n 50 -f
```

## Проверка после деплоя

1. Откройте браузер: `http://10.0.88.10`
2. Войдите в систему
3. Перейдите в раздел **"ИИ-Анализ"** (в навигации)
4. Очистите кэш браузера: `Ctrl+Shift+R` (или `Cmd+Shift+R` на Mac)
5. Проверьте:
   - ✅ Статус подключения к ML платформе отображается
   - ✅ Кнопки управления работают
   - ✅ Статистика загружается

## Устранение неполадок

### Изменения не видны
- Очистите кэш браузера
- Убедитесь, что сервис перезапущен
- Проверьте логи на ошибки

### ML платформа недоступна
- Проверьте SSH: `ssh k8s-worker@10.0.88.25`
- Проверьте API: `curl http://10.0.88.25:8000/health`
