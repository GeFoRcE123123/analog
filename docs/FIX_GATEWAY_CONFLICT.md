# 🔧 Исправление конфликта IP адресов (шлюз 10.0.88.1)

## ❌ Проблема:

Docker создал bridge сеть с IP `10.0.88.1`, который конфликтует с реальным шлюзом подсети `10.0.88.1`.

## ✅ Решение:

Изменена подсеть Docker сети с `10.0.88.0/24` на `172.20.0.0/16` в файле `services/database/docker-compose.yml`.

### Изменения:

**Было:**
```yaml
networks:
  vuln_network:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.88.0/24  # ❌ Конфликт с шлюзом 10.0.88.1
```

**Стало:**
```yaml
networks:
  vuln_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16  # ✅ Нет конфликта
          gateway: 172.20.0.1
```

---

## 🚀 Что нужно сделать:

### 1. Удалить старую сеть (на VM 10.0.88.11):

```bash
ssh user@10.0.88.11

# Остановить контейнер
cd ~/vulnerability_manager/database
echo "123" | sudo -S docker compose down

# Удалить старую сеть
echo "123" | sudo -S docker network rm vuln_network 2>/dev/null || true
```

### 2. Переразвернуть базу данных:

На локальной машине:
```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
./deploy.sh database
```

Или вручную на VM:
```bash
ssh user@10.0.88.11
cd ~/vulnerability_manager/database
echo "123" | sudo -S docker compose up -d --force-recreate
```

### 3. Проверить, что конфликта нет:

```bash
# Проверить IP адрес bridge интерфейса (не должен быть 10.0.88.1)
ip addr show | grep "inet 10.0.88.1"

# Проверить новую сеть
docker network inspect vuln_network | grep -A 5 "IPAM"
```

---

## ✅ Результат:

- ✅ Docker bridge будет использовать подсеть `172.20.0.0/16`
- ✅ Шлюз Docker: `172.20.0.1` (не конфликтует с `10.0.88.1`)
- ✅ Контейнер PostgreSQL будет доступен на порту `5432` через IP `10.0.88.11:5432`
- ✅ Внутренняя Docker сеть не будет мешать реальной сети `10.0.88.0/24`

---

## 📝 Важно:

Это изменение **не влияет** на доступ к базе данных из других VM:
- Backend (10.0.88.20) все еще подключается к `10.0.88.11:5432`
- Parsers (10.0.88.23) все еще подключаются к `10.0.88.11:5432`

Docker сеть `172.20.0.0/16` используется только **внутри** контейнера PostgreSQL для его внутренней работы. Порт `5432` пробрасывается на хост `10.0.88.11`, поэтому доступ остается прежним.

---

## 🔍 Проверка:

После перезапуска проверьте:

```bash
# На VM 10.0.88.11
ip addr show | grep -E "br-|172.20"

# Должно быть что-то вроде:
# inet 172.20.0.1/16 scope global br-xxxxx

# НЕ должно быть:
# inet 10.0.88.1/24 (это было проблемой)
```

