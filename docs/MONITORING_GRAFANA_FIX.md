# 🔧 Исправление проблемы с Grafana

## Проблема
Grafana недоступна на http://10.0.88.41:3000 из-за проблем с правами доступа к директории данных.

## ✅ Решение (применено)

### Шаги исправления:

1. **Остановка Grafana:**
   ```bash
   cd ~/monitoring/monitoring-stack/loki
   docker compose down grafana
   ```

2. **Пересоздание директории:**
   ```bash
   cd ~/monitoring/monitoring-stack
   sudo rm -rf grafana/grafana-data
   sudo mkdir -p grafana/grafana-data
   sudo chmod 777 grafana/grafana-data
   ```

3. **Обновление docker-compose.yml:**
   - Добавлен `tmpfs` для `/var/lib/grafana/plugins`
   - Убрана строка `user: "472:472"` (временно, для создания БД)

4. **Запуск Grafana:**
   ```bash
   cd loki
   docker compose up -d grafana
   ```

5. **Проверка:**
   ```bash
   docker ps --filter "name=grafana"
   curl http://localhost:3000/api/health
   ```

## ✅ Результат

Grafana успешно запущена и доступна на http://10.0.88.41:3000

- Логин: `admin`
- Пароль: `admin123`

## 🔒 После первого запуска (рекомендуется)

Вернуть правильные права доступа:

```bash
cd ~/monitoring/monitoring-stack
sudo chown -R 472:472 grafana/grafana-data
sudo chmod -R 755 grafana/grafana-data

# Добавить обратно в docker-compose.yml:
# user: "472:472"
```

## 📝 Примечания

- Проблема была связана с тем, что Grafana не могла создать SQLite базу данных
- Использование tmpfs для плагинов решает проблему с правами на директорию plugins
- После создания БД можно вернуть правильные права доступа

---

**Дата исправления:** 2025-01-20  
**Статус:** ✅ Решено
