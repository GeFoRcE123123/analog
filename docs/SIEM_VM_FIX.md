# 🔧 Исправление проблем с SIEM/Monitoring VM (10.0.88.41)

## 📋 Диагностика проблемы

### Текущий статус:
- ✅ VM доступна по ping (10.0.88.41)
- ❌ SSH недоступен (порт 22 закрыт)
- ❌ Все SIEM сервисы недоступны (порты 3000, 9090, 3100 закрыты)

### Возможные причины:
1. **Файрвол блокирует все порты** (наиболее вероятно)
2. SSH сервис не запущен
3. Неправильная конфигурация сети

---

## 🚀 Решение: Отключение файрвола и запуск сервисов

### Вариант 1: Через консоль VM (если есть доступ)

Если у вас есть доступ к консоли VM (через провайдера или физический доступ):

```bash
# 1. Войти в систему
# (используйте учетные данные VM)

# 2. Отключить файрвол UFW
sudo ufw disable
sudo ufw --force reset

# 3. Очистить iptables (если используется)
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# 4. Проверить статус SSH
sudo systemctl status ssh
# Если не запущен:
sudo systemctl start ssh
sudo systemctl enable ssh

# 5. Проверить Docker
docker --version
sudo systemctl status docker
# Если не запущен:
sudo systemctl start docker
sudo systemctl enable docker

# 6. Перейти в директорию мониторинга
cd ~/monitoring/monitoring-stack

# 7. Запустить сервисы
# Loki
cd loki
docker compose up -d
cd ..

# Prometheus
cd prometheus
docker compose up -d
cd ..

# Grafana (если есть отдельный compose)
if [ -d "grafana" ]; then
    cd grafana
    docker compose up -d
    cd ..
fi

# 8. Проверить статус контейнеров
docker ps

# 9. Проверить доступность сервисов
curl http://localhost:3000  # Grafana
curl http://localhost:9090   # Prometheus
curl http://localhost:3100/ready  # Loki
```

### Вариант 2: Автоматический скрипт

Создайте файл `fix_siem.sh` на VM:

```bash
#!/bin/bash
# Скрипт для исправления SIEM VM

set -e

echo "🔧 Исправление SIEM VM..."

# Отключение файрвола
echo "Отключение файрвола..."
sudo ufw --force disable
sudo ufw --force reset

# Очистка iptables
echo "Очистка iptables..."
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Запуск SSH
echo "Проверка SSH..."
sudo systemctl start ssh
sudo systemctl enable ssh

# Запуск Docker
echo "Проверка Docker..."
sudo systemctl start docker
sudo systemctl enable docker

# Запуск SIEM сервисов
echo "Запуск SIEM сервисов..."
cd ~/monitoring/monitoring-stack

if [ -d "loki" ]; then
    cd loki
    docker compose up -d
    cd ..
fi

if [ -d "prometheus" ]; then
    cd prometheus
    docker compose up -d
    cd ..
fi

if [ -d "grafana" ]; then
    cd grafana
    docker compose up -d
    cd ..
fi

# Проверка
echo "Проверка контейнеров..."
docker ps

echo "✅ Исправление завершено!"
```

Запустите скрипт:
```bash
chmod +x fix_siem.sh
./fix_siem.sh
```

---

## 🔍 Проверка после исправления

### 1. Проверка портов

```bash
# На VM
sudo netstat -tlnp | grep -E '3000|9090|3100|22'
```

### 2. Проверка контейнеров

```bash
docker ps
docker ps -a  # Все контейнеры, включая остановленные
```

### 3. Проверка логов

```bash
# Loki
docker logs loki --tail 50

# Prometheus
docker logs prometheus --tail 50

# Grafana
docker logs grafana --tail 50
```

### 4. Проверка HTTP сервисов

```bash
# С локальной машины
curl http://10.0.88.41:3000   # Grafana
curl http://10.0.88.41:9090   # Prometheus
curl http://10.0.88.41:3100/ready  # Loki
```

---

## 🐛 Устранение проблем

### Проблема: Контейнеры не запускаются

**Решение:**
```bash
# Проверить логи
docker logs <container_name>

# Пересоздать контейнеры
cd ~/monitoring/monitoring-stack/loki
docker compose down
docker compose up -d --build
```

### Проблема: Порты все еще закрыты

**Решение:**
```bash
# Проверить, что файрвол действительно отключен
sudo ufw status

# Проверить iptables
sudo iptables -L -n

# Проверить, что контейнеры слушают правильные порты
docker ps
docker port <container_name>
```

### Проблема: Docker не запускается

**Решение:**
```bash
# Проверить статус
sudo systemctl status docker

# Перезапустить
sudo systemctl restart docker

# Проверить логи
sudo journalctl -u docker -n 50
```

---

## 📊 Ожидаемый результат

После исправления должны быть доступны:

| Сервис | URL | Статус |
|--------|-----|--------|
| Grafana | http://10.0.88.41:3000 | ✅ Доступен |
| Prometheus | http://10.0.88.41:9090 | ✅ Доступен |
| Loki | http://10.0.88.41:3100 | ✅ Доступен |
| SSH | ssh user@10.0.88.41 | ✅ Доступен |

---

## 🔐 Безопасность (после исправления)

После того как все заработает, можно настроить файрвол более безопасно:

```bash
# Разрешить только нужные порты
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 3000/tcp  # Grafana
sudo ufw allow 9090/tcp  # Prometheus
sudo ufw allow 3100/tcp  # Loki
sudo ufw allow from 10.0.88.0/24  # Только внутренняя сеть

# Включить файрвол
sudo ufw enable
```

---

## 📝 Чеклист исправления

- [ ] Доступ к консоли VM получен
- [ ] Файрвол отключен (UFW и iptables)
- [ ] SSH сервис запущен и работает
- [ ] Docker запущен
- [ ] Контейнеры SIEM запущены
- [ ] Порты открыты (3000, 9090, 3100)
- [ ] HTTP сервисы доступны
- [ ] Логи без критических ошибок

---

**После выполнения этих шагов SIEM система должна заработать!**

