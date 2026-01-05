# 🔧 Исправление конфликта шлюза и маршрутизации

## ❌ Проблема:

Docker создал bridge сеть с IP `10.0.88.1`, который конфликтует с реальным шлюзом подсети `10.0.88.1`. Это **ломает маршрутизацию** и VM теряет доступ в интернет.

## ✅ Решение:

**Убрана кастомная Docker сеть** - теперь используется стандартная Docker bridge сеть (обычно `172.17.0.0/16`), которая **не конфликтует** с реальной сетью `10.0.88.0/24`.

### Изменения в `services/database/docker-compose.yml`:

**Было (конфликт):**
```yaml
networks:
  vuln_network:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.88.0/24  # ❌ Конфликт с шлюзом 10.0.88.1
```

**Стало (без конфликта):**
```yaml
# Убрана секция networks - используется стандартная Docker bridge
# PostgreSQL все равно доступен на 10.0.88.11:5432 через проброс портов
```

---

## 🚀 Как применить исправление:

### 1. Удалить старую конфликтующую сеть (на VM 10.0.88.11):

```bash
ssh user@10.0.88.11

# Остановить контейнер
cd ~/vulnerability_manager/database
echo "123" | sudo -S docker compose down

# Удалить старую сеть
echo "123" | sudo -S docker network rm vuln_network 2>/dev/null || true

# Удалить конфликтующий bridge интерфейс
sudo ip link set br-cbf6c28bf00f down 2>/dev/null || true
sudo ip link delete br-cbf6c28bf00f 2>/dev/null || true

# Проверить, что маршрутизация восстановлена
ip route | grep default
# Должно быть: default via 10.0.88.1 dev ens18 (или подобное)

# Проверить интернет
ping -c 2 8.8.8.8
```

### 2. Скопировать исправленный docker-compose.yml:

**На локальной машине:**
```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
sshpass -p "123" scp services/database/docker-compose.yml user@10.0.88.11:~/vulnerability_manager/database/
```

### 3. Запустить контейнер с новой конфигурацией:

```bash
ssh user@10.0.88.11
cd ~/vulnerability_manager/database

# Запустить (без кастомной сети)
echo "123" | sudo -S docker compose up -d --force-recreate

# Проверить что интернет работает
ping -c 2 8.8.8.8

# Проверить что нет конфликта
ip addr show | grep "10.0.88.1" | grep -v "10.0.88.11"
# Не должно ничего показать (кроме реального шлюза через основной интерфейс)
```

### 4. Проверить работу базы данных:

```bash
# Контейнер должен быть запущен
docker ps | grep vulnerability_db

# База должна быть доступна
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT 1;"

# Проверка из другой VM (например Backend)
ssh user@10.0.88.20
psql -h 10.0.88.11 -U admin -d vuln_db -c "SELECT 1;"
```

---

## 🔍 Проверка результата:

### Должно быть:

```bash
# 1. Интернет работает
ping -c 2 8.8.8.8
# ✅ Должен быть ответ

# 2. Нет конфликтующего bridge с 10.0.88.1
ip addr show | grep "br-" | grep "10.0.88.1"
# ✅ Не должно ничего показать

# 3. Реальный шлюз доступен
ip route | grep default
# ✅ default via 10.0.88.1 dev ens18 (или ваш интерфейс)

# 4. Docker использует стандартную сеть 172.17.x.x
docker network inspect bridge | grep Subnet
# ✅ Должно быть что-то вроде: "Subnet": "172.17.0.0/16"

# 5. Контейнер запущен и доступен
docker ps | grep vulnerability_db
# ✅ Контейнер должен быть в статусе Up

# 6. База данных доступна на порту 5432
netstat -tuln | grep :5432
# ✅ Должен быть слушатель на 0.0.0.0:5432
```

---

## 📝 Важно:

### Почему это работает:

1. **Убрана кастомная сеть** - Docker использует стандартную bridge сеть (172.17.0.0/16)
2. **Нет конфликта IP** - стандартная Docker сеть не пересекается с 10.0.88.0/24
3. **Проброс портов работает** - PostgreSQL доступен через `10.0.88.11:5432`
4. **Маршрутизация восстановлена** - реальный шлюз 10.0.88.1 работает корректно

### Доступ к базе данных:

- **Внутри контейнера:** PostgreSQL работает на порту 5432
- **С хоста VM:** Доступен через `localhost:5432` или `10.0.88.11:5432`
- **С других VM:** Доступен через `10.0.88.11:5432`

**Ничего не меняется** для Backend и Parsers - они по-прежнему подключаются к `10.0.88.11:5432`.

---

## 🆘 Если проблема остается:

### 1. Проверить маршруты:

```bash
ip route show
# Должен быть: default via 10.0.88.1

# Если нет - добавить:
sudo ip route add default via 10.0.88.1
```

### 2. Проверить DNS:

```bash
cat /etc/resolv.conf
# Должны быть DNS серверы

# Если нет - добавить:
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
```

### 3. Перезапустить сеть:

```bash
sudo systemctl restart networking  # Ubuntu/Debian
sudo systemctl restart NetworkManager  # CentOS/RHEL
```

---

## ✅ Резюме:

- ✅ **Убрана кастомная Docker сеть** - используется стандартная bridge
- ✅ **Нет конфликта** с реальным шлюзом 10.0.88.1
- ✅ **Маршрутизация восстановлена** - интернет должен работать
- ✅ **База данных доступна** - порт 5432 пробрасывается корректно
- ✅ **Ничего не сломалось** - Backend и Parsers работают как прежде

