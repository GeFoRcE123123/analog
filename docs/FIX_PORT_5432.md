# Решение проблемы "port 5432 already in use"

## Проблема
Порт 5432 уже занят на VM 10.0.88.11 (Database)

## Решения

### Вариант 1: Остановить существующий PostgreSQL (рекомендуется)

```bash
# Подключиться к VM Database
ssh user@10.0.88.11

# Проверить, что использует порт 5432
sudo netstat -tulpn | grep 5432
# или
sudo ss -tulpn | grep 5432

# Если это системный PostgreSQL, остановить:
sudo systemctl stop postgresql
sudo systemctl disable postgresql  # Чтобы не запускался автоматически

# Если это Docker контейнер, остановить:
docker ps | grep postgres
docker stop <container_id>
docker rm <container_id>
```

### Вариант 2: Изменить порт в docker-compose.yml

Если нужно оставить существующий PostgreSQL, можно изменить порт:

В `services/database/docker-compose.yml` изменить:
```yaml
ports:
  - "5433:5432"  # Внешний порт 5433, внутренний 5432
```

И обновить `config.py`:
```python
port: int = 5433  # Изменить с 5432 на 5433
```

### Вариант 3: Использовать сеть Docker вместо проброса портов

Если все сервисы в одной Docker сети, можно убрать ports и использовать внутреннюю сеть Docker.

---

## Рекомендуемое решение

Остановить системный PostgreSQL (если он есть) и использовать только контейнер Docker.

