# 🔧 Исправление SSH и Grafana на SIEM VM

**VM:** 10.0.88.41 (Monitoring/SIEM)  
**Пользователь:** test  
**Пароль:** 123

---

## 📋 Текущий статус

- ✅ **Prometheus** (9090) - работает
- ✅ **Loki** (3100) - работает
- ❌ **SSH** (22) - недоступен
- ❌ **Grafana** (3000) - недоступна

---

## 🚀 Быстрое исправление

### Вариант 1: Использовать готовый скрипт (рекомендуется)

1. **Получите доступ к консоли VM** через провайдера

2. **Скопируйте скрипт на VM** (через другой способ или создайте вручную):

```bash
# На VM создайте файл
cat > /tmp/fix_ssh_grafana.sh << 'EOF'
# [содержимое scripts/fix_ssh_and_grafana.sh]
EOF

chmod +x /tmp/fix_ssh_grafana.sh
sudo /tmp/fix_ssh_grafana.sh
```

3. **Или выполните команды вручную** (см. Вариант 2)

### Вариант 2: Выполнить команды вручную

**На консоли VM выполните:**

```bash
# 1. Войти в систему
login: test
Password: 123

# 2. Отключить файрвол
sudo ufw --force disable
sudo ufw --force reset
sudo iptables -F && sudo iptables -X
sudo iptables -P INPUT ACCEPT

# 3. Запустить SSH
sudo systemctl start ssh
sudo systemctl enable ssh

# 4. Проверить Docker
sudo systemctl start docker
sudo systemctl enable docker

# 5. Запустить Grafana
cd ~/monitoring/monitoring-stack

# Если есть отдельная директория grafana
if [ -d grafana ]; then
    cd grafana
    docker compose up -d
    cd ..
fi

# Или если Grafana в общем compose
docker compose up -d grafana

# 6. Проверить статус
sudo systemctl status ssh
docker ps | grep grafana
```

**Пароль для sudo:** 123

---

## 🔍 Проверка после исправления

### С локальной машины:

```bash
# 1. Проверить SSH
ssh test@10.0.88.41
# Password: 123

# 2. Проверить Grafana
curl http://10.0.88.41:3000

# 3. Открыть в браузере
open http://10.0.88.41:3000
# или
xdg-open http://10.0.88.41:3000
```

### Учетные данные Grafana:

- **URL:** http://10.0.88.41:3000
- **Username:** admin
- **Password:** admin123

---

## 🐛 Устранение проблем

### Проблема: SSH все еще не работает

**Решение:**
```bash
# На VM
sudo systemctl status ssh
sudo journalctl -u ssh -n 50

# Проверить конфигурацию
sudo cat /etc/ssh/sshd_config | grep -E '^Port|^PermitRootLogin|^PasswordAuthentication'

# Перезапустить SSH
sudo systemctl restart ssh
```

### Проблема: Grafana не запускается

**Решение:**
```bash
# На VM
cd ~/monitoring/monitoring-stack

# Проверить логи
docker logs grafana --tail 50

# Пересоздать контейнер
docker compose down grafana
docker compose up -d grafana

# Или пересоздать с нуля
docker compose down
docker compose up -d
```

### Проблема: Порт 3000 все еще закрыт

**Решение:**
```bash
# На VM проверить
sudo netstat -tlnp | grep 3000
sudo ss -tlnp | grep 3000

# Проверить контейнер
docker ps | grep grafana
docker port grafana
```

---

## 📊 Ожидаемый результат

После исправления:

| Сервис | URL | Статус |
|--------|-----|--------|
| SSH | ssh test@10.0.88.41 | ✅ Доступен |
| Grafana | http://10.0.88.41:3000 | ✅ Доступна |
| Prometheus | http://10.0.88.41:9090 | ✅ Доступен |
| Loki | http://10.0.88.41:3100 | ✅ Доступен |

---

## 📝 Чеклист

- [ ] Получен доступ к консоли VM
- [ ] Файрвол отключен
- [ ] SSH запущен и работает
- [ ] Docker запущен
- [ ] Grafana контейнер запущен
- [ ] Порт 3000 открыт
- [ ] SSH доступен с локальной машины
- [ ] Grafana доступна в браузере

---

## 🔗 Связанные документы

- [HOW_TO_FIX_SIEM_VM.md](./HOW_TO_FIX_SIEM_VM.md) - Общая инструкция
- [VM_CREDENTIALS.md](./VM_CREDENTIALS.md) - Учетные данные
- [SIEM_VM_STATUS.md](./SIEM_VM_STATUS.md) - Текущий статус

---

**После исправления SSH и Grafana будут доступны!**

