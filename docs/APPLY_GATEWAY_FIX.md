# ✅ Применить исправление конфликта шлюза

## 📝 Что изменено:

**Файл:** `services/database/docker-compose.yml`

Подсеть Docker сети изменена с `10.0.88.0/24` на `172.20.0.0/16` для избежания конфликта с шлюзом `10.0.88.1`.

---

## 🚀 Инструкция по применению:

### Шаг 1: Скопировать исправленный файл на VM 10.0.88.11

**На локальной машине:**
```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
sshpass -p "123" scp services/database/docker-compose.yml user@10.0.88.11:~/vulnerability_manager/database/
```

Или автоматически через deploy.sh:
```bash
./deploy.sh database
```

---

### Шаг 2: Удалить старую сеть и пересоздать

**На VM 10.0.88.11:**

```bash
ssh user@10.0.88.11
cd ~/vulnerability_manager/database

# 1. Остановить контейнер
echo "123" | sudo -S docker compose down

# 2. Удалить старую сеть (которая конфликтует с шлюзом)
echo "123" | sudo -S docker network rm vuln_network 2>/dev/null || true

# 3. Удалить старый bridge интерфейс (если он остался)
# Найти имя интерфейса:
ip addr show | grep "10.0.88.1"

# Если есть br-xxx с 10.0.88.1, удалить:
sudo ip link set br-cbf6c28bf00f down 2>/dev/null || true
sudo ip link delete br-cbf6c28bf00f 2>/dev/null || true

# 4. Запустить с новой конфигурацией
echo "123" | sudo -S docker compose up -d --force-recreate

# 5. Проверить результат
echo "123" | sudo -S docker ps | grep vulnerability_db
ip addr show | grep "172.20"  # Должна быть новая сеть
ip addr show | grep "10.0.88.1" | grep -v "10.0.88.11"  # Не должно быть конфликтующего bridge
```

---

### Шаг 3: Проверка

**Проверить что:**
1. ✅ Контейнер запущен: `docker ps | grep vulnerability_db`
2. ✅ Новая сеть создана: `ip addr show | grep "172.20"`
3. ✅ Нет конфликта: `ip addr show | grep "10.0.88.1"` не должно показывать bridge
4. ✅ База доступна: `docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT 1;"`

---

## 🔍 Что должно быть после исправления:

```bash
# Должна быть новая сеть с 172.20.0.0/16
ip addr show | grep "172.20"
# Пример вывода:
# inet 172.20.0.1/16 scope global br-xxxxx

# НЕ должно быть bridge с 10.0.88.1
ip addr show | grep "10.0.88.1" | grep br-
# (ничего не должно вывестись)
```

---

## ✅ Быстрая команда (все в одной строке):

```bash
ssh user@10.0.88.11 "cd ~/vulnerability_manager/database && echo '123' | sudo -S docker compose down && echo '123' | sudo -S docker network rm vuln_network 2>/dev/null || true && echo '123' | sudo -S docker compose up -d --force-recreate"
```

---

## 📋 Резюме изменений:

- ❌ **Было:** Docker сеть `10.0.88.0/24` с шлюзом `10.0.88.1` (конфликт!)
- ✅ **Стало:** Docker сеть `172.20.0.0/16` с шлюзом `172.20.0.1` (нет конфликта)
- ✅ **Результат:** Подключение к БД не изменилось - все так же `10.0.88.11:5432`

