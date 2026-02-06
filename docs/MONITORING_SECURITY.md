# 🔒 Безопасность и изоляция Monitoring Stack

## 🎯 Принципы безопасности

### 1. **Изоляция сети**
- Loki доступен только с разрешенных IP адресов
- Promtail отправляет логи только на Monitoring VM
- Использование внутренней сети (10.0.88.0/24)

### 2. **Аутентификация и авторизация**
- SSH ключи вместо паролей
- Аутентификация в Loki (опционально)
- Ограничение прав Promtail на удаленных VM

### 3. **Шифрование трафика**
- TLS для передачи логов (рекомендуется)
- SSH туннелирование (альтернатива)
- Изоляция в приватной сети

---

## 🔐 Шаг 1: Настройка SSH ключей

### На Monitoring VM (10.0.88.41):

```bash
# Генерация SSH ключа для мониторинга
ssh-keygen -t ed25519 -C "monitoring@10.0.88.41" -f ~/.ssh/monitoring_key -N ""

# Копирование публичного ключа на другие VM
ssh-copy-id -i ~/.ssh/monitoring_key.pub user@10.0.88.20
ssh-copy-id -i ~/.ssh/monitoring_key.pub user@10.0.88.10
ssh-copy-id -i ~/.ssh/monitoring_key.pub user@10.0.88.23
ssh-copy-id -i ~/.ssh/monitoring_key.pub k8s-worker@10.0.88.25

# Настройка SSH config для удобства
cat >> ~/.ssh/config << EOF
Host backend-vm
    HostName 10.0.88.20
    User user
    IdentityFile ~/.ssh/monitoring_key
    StrictHostKeyChecking yes

Host frontend-vm
    HostName 10.0.88.10
    User user
    IdentityFile ~/.ssh/monitoring_key
    StrictHostKeyChecking yes

Host parsers-vm
    HostName 10.0.88.23
    User user
    IdentityFile ~/.ssh/monitoring_key
    StrictHostKeyChecking yes

Host ml-platform-vm
    HostName 10.0.88.25
    User k8s-worker
    IdentityFile ~/.ssh/monitoring_key
    StrictHostKeyChecking yes
EOF

chmod 600 ~/.ssh/config
```

---

## 🛡️ Шаг 2: Настройка файрвола на Monitoring VM

### Ограничение доступа к Loki:

```bash
# На VM 10.0.88.41 (Monitoring)
sudo ufw allow from 10.0.88.20 to any port 3100 proto tcp comment "Loki from Backend"
sudo ufw allow from 10.0.88.10 to any port 3100 proto tcp comment "Loki from Frontend"
sudo ufw allow from 10.0.88.23 to any port 3100 proto tcp comment "Loki from Parsers"
sudo ufw allow from 10.0.88.25 to any port 3100 proto tcp comment "Loki from ML Platform"

# Ограничение доступа к Prometheus (только локально или через VPN)
sudo ufw allow from 10.0.88.0/24 to any port 9090 proto tcp comment "Prometheus internal"

# Ограничение доступа к Grafana (только для администраторов)
sudo ufw allow from 10.0.88.0/24 to any port 3000 proto tcp comment "Grafana internal"
# Или только с определенного IP:
# sudo ufw allow from YOUR_ADMIN_IP to any port 3000 proto tcp

# Блокировка всех остальных подключений к Loki
sudo ufw deny 3100/tcp

sudo ufw reload
sudo ufw status numbered
```

---

## 🔒 Шаг 3: Настройка аутентификации в Loki (опционально)

### Включение базовой аутентификации:

```yaml
# loki/loki-config.yaml
auth_enabled: true

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

auth:
  type: basic_auth
  basic_auth:
    users:
      - username: promtail
        password: <GENERATE_SECURE_PASSWORD>
```

### Обновление Promtail конфигурации:

```yaml
# promtail-config.yml
clients:
  - url: http://10.0.88.41:3100/loki/api/v1/push
    basic_auth:
      username: promtail
      password: <SECURE_PASSWORD>
```

---

## 🚀 Шаг 4: Безопасная установка Promtail

### Создание безопасного скрипта установки:

```bash
# На Monitoring VM: ~/monitoring/monitoring-stack/setup-remote-promtail-secure.sh
#!/bin/bash
# Безопасная установка Promtail на удаленные VM

VM_IP=$1
VM_ROLE=$2
SSH_HOST=${3:-$VM_ROLE-vm}  # Использует SSH config

if [ -z "$VM_IP" ] || [ -z "$VM_ROLE" ]; then
    echo "Использование: $0 <VM_IP> <VM_ROLE> [SSH_HOST]"
    echo "Пример: $0 10.0.88.20 backend backend-vm"
    exit 1
fi

echo "🔒 Безопасная установка Promtail на $VM_IP ($VM_ROLE)..."

# Проверка SSH подключения
if ! ssh -o ConnectTimeout=5 -o BatchMode=yes $SSH_HOST "echo 'SSH OK'" 2>/dev/null; then
    echo "❌ Ошибка: Не удается подключиться через SSH ключ"
    echo "   Убедитесь, что SSH ключ настроен: ssh-copy-id $SSH_HOST"
    exit 1
fi

# Копирование конфигурации через SSH
scp promtail-remote-config.yml $SSH_HOST:/tmp/promtail-config.yml

# Создание конфигурации с правильными значениями
ssh $SSH_HOST "sed -i 's/CHANGE_ME/$VM_IP/g' /tmp/promtail-config.yml && \
               sed -i 's/vm_role: \"CHANGE_ME\"/vm_role: \"$VM_ROLE\"/g' /tmp/promtail-config.yml"

# Создание изолированной сети для Promtail
ssh $SSH_HOST "docker network create promtail-net 2>/dev/null || true"

# Запуск Promtail в изолированном контейнере с ограниченными правами
ssh $SSH_HOST "docker run -d \
  --name promtail \
  --restart unless-stopped \
  --network promtail-net \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  -v /tmp/promtail-config.yml:/etc/promtail/config.yml:ro \
  -v /var/log:/var/log:ro \
  -v /var/lib/docker/containers:/var/lib/docker/containers:ro \
  --security-opt no-new-privileges:true \
  --user 1000:1000 \
  grafana/promtail:latest \
  -config.file=/etc/promtail/config.yml"

echo "✅ Promtail безопасно установлен на $VM_IP"
echo "   Проверка: ssh $SSH_HOST 'docker logs promtail'"
```

---

## 🔐 Шаг 5: Настройка файрвола на удаленных VM

### На каждой удаленной VM:

```bash
# Разрешить исходящие подключения к Monitoring VM
sudo ufw allow out to 10.0.88.41 port 3100 proto tcp comment "Loki push"

# Заблокировать входящие подключения к Promtail (только исходящие)
sudo ufw deny 9080/tcp comment "Promtail local only"

# Разрешить SSH только с Monitoring VM (опционально)
sudo ufw allow from 10.0.88.41 to any port 22 proto tcp comment "SSH from Monitoring"

sudo ufw reload
```

---

## 🛡️ Шаг 6: Дополнительные меры безопасности

### 1. Ограничение прав Promtail:

```bash
# Создание отдельного пользователя для Promtail
sudo useradd -r -s /bin/false promtail
sudo chown -R promtail:promtail /var/log/promtail
```

### 2. Использование TLS (рекомендуется для production):

```yaml
# Loki с TLS
server:
  http_tls_config:
    cert_file: /etc/loki/tls/loki.crt
    key_file: /etc/loki/tls/loki.key

# Promtail с TLS
clients:
  - url: https://10.0.88.41:3100/loki/api/v1/push
    tls_config:
      ca_file: /etc/promtail/tls/ca.crt
```

### 3. Мониторинг безопасности:

```bash
# Логирование всех подключений к Loki
# Добавить в loki-config.yaml:
server:
  log_level: info
  log_format: json

# Мониторинг через Prometheus
# Алерт на подозрительную активность
```

---

## ✅ Чеклист безопасности

- [ ] SSH ключи настроены и пароли отключены
- [ ] Файрвол настроен на Monitoring VM (только разрешенные IP)
- [ ] Файрвол настроен на удаленных VM (только исходящие подключения)
- [ ] Promtail запущен с ограниченными правами (--read-only, --cap-drop)
- [ ] Аутентификация в Loki включена (опционально)
- [ ] TLS настроен для передачи логов (production)
- [ ] Мониторинг подключений активен
- [ ] Регулярные проверки безопасности

---

## 🔍 Проверка безопасности

### Проверка SSH подключений:

```bash
# На Monitoring VM
ssh backend-vm "echo 'Backend OK'"
ssh frontend-vm "echo 'Frontend OK'"
ssh parsers-vm "echo 'Parsers OK'"
ssh ml-platform-vm "echo 'ML Platform OK'"
```

### Проверка файрвола:

```bash
# На Monitoring VM
sudo ufw status | grep 3100
sudo ufw status | grep 9090
sudo ufw status | grep 3000

# На удаленных VM
sudo ufw status | grep 3100
```

### Проверка Promtail:

```bash
# На удаленных VM
docker ps | grep promtail
docker inspect promtail | grep -i security
docker logs promtail --tail=20
```

### Тест подключения:

```bash
# С удаленной VM к Loki
curl -v http://10.0.88.41:3100/ready

# Должно работать только с разрешенных IP
```

---

## 📊 Мониторинг безопасности

### Алерты в Prometheus:

```yaml
# alert-rules.yml
groups:
  - name: security_alerts
    rules:
      - alert: UnauthorizedLokiAccess
        expr: rate(loki_request_duration_seconds_count{status_code=~"4..|5.."}[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Подозрительная активность в Loki"
```

---

## 🚨 Инциденты безопасности

### При обнаружении подозрительной активности:

1. **Немедленно заблокировать IP:**
   ```bash
   sudo ufw deny from SUSPICIOUS_IP
   ```

2. **Проверить логи:**
   ```bash
   docker logs loki --tail=100 | grep SUSPICIOUS_IP
   journalctl -u docker | grep promtail
   ```

3. **Перезапустить Promtail на затронутых VM:**
   ```bash
   ssh affected-vm "docker restart promtail"
   ```

4. **Обновить пароли/ключи:**
   ```bash
   # Сгенерировать новые SSH ключи
   # Обновить пароли в Loki
   ```

---

## 📝 Рекомендации

1. **Регулярные обновления:**
   - Обновлять Docker образы Loki/Promtail
   - Применять патчи безопасности

2. **Аудит:**
   - Регулярно проверять логи доступа
   - Мониторить необычную активность

3. **Резервное копирование:**
   - Сохранять конфигурации безопасности
   - Документировать изменения

4. **Документация:**
   - Вести журнал изменений безопасности
   - Обновлять процедуры при инцидентах

---

**Последнее обновление:** 2025-01-20  
**Версия:** 1.0

