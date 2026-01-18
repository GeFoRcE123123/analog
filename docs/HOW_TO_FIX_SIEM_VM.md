# ✅ ПРАВИЛЬНАЯ ИНСТРУКЦИЯ: Как исправить SIEM VM

## ⚠️ ВАЖНО: Где выполнять команды

**Вы сейчас на:** `Kirills-MacBook-Pro` (ваш Mac)  
**Нужно выполнять на:** VM `10.0.88.41` (Monitoring/SIEM сервер)

---

## 🎯 Правильный способ

### Шаг 1: Получить доступ к консоли VM 10.0.88.41

**Варианты:**

1. **Через панель провайдера** (Hetzner, DigitalOcean, AWS и т.д.)
   - Войдите в панель управления
   - Найдите VM с IP 10.0.88.41
   - Откройте "Console" или "VNC Console"

2. **Через другой сервер** (если есть доступ к другой VM в сети)
   ```bash
   # Сначала подключитесь к другой VM
   ssh user@10.0.88.20  # Например, Backend VM
   # Затем с той VM попробуйте подключиться к Monitoring
   ```

### Шаг 2: На консоли VM войдите в систему

Когда откроется консоль VM, вы увидите приглашение входа:

```
Ubuntu 22.04 LTS monitoring-vm tty1

monitoring-vm login: _
```

**Введите:**
```
user
```

**Пароль:**
```
123
```

### Шаг 3: Выполните команды исправления

**Теперь вы на VM!** Выполните:

```bash
# Отключить файрвол
sudo ufw --force disable
sudo ufw --force reset

# Очистить iptables
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT ACCEPT

# Запустить SSH
sudo systemctl start ssh
sudo systemctl enable ssh

# Проверить
sudo systemctl status ssh
```

**Пароль для sudo:** `123`

---

## 🔍 Как понять, что вы на VM?

### ✅ На VM вы увидите:
```bash
user@monitoring-vm:~$ 
# или
user@ubuntu:~$
# или похожее
```

### ❌ На вашем Mac вы видите:
```bash
kirillstepanov@Kirills-MacBook-Pro vulnerability_manager % 
# Это ваш Mac! Команды здесь не помогут!
```

---

## 📋 Полная последовательность действий

### 1. Откройте консоль VM через провайдера

**Пример для Hetzner:**
1. Войдите в Hetzner Cloud Console
2. Найдите сервер с IP 10.0.88.41
3. Нажмите "Console" или "VNC"

**Пример для DigitalOcean:**
1. Войдите в DigitalOcean
2. Найдите Droplet с IP 10.0.88.41
3. Нажмите "Access" → "Launch Droplet Console"

### 2. Войдите в систему

```
login: user
Password: 123
```

### 3. Выполните команды

```bash
# Создайте и выполните скрипт
cat > /tmp/fix.sh << 'EOF'
#!/bin/bash
sudo ufw --force disable
sudo ufw --force reset
sudo iptables -F && sudo iptables -X
sudo iptables -P INPUT ACCEPT
sudo systemctl start ssh
sudo systemctl enable ssh
echo "✅ Готово!"
EOF

chmod +x /tmp/fix.sh
sudo /tmp/fix.sh
```

### 4. Проверьте SSH

```bash
# На VM проверьте
sudo netstat -tlnp | grep 22

# С вашего Mac проверьте
ssh user@10.0.88.41
# Password: 123
```

---

## 🆘 Если пароль sudo не подходит

### Попробуйте:

1. **Другой пароль:**
   ```bash
   # Попробуйте:
   - 123
   - admin
   - password
   - (пустой пароль - просто Enter)
   ```

2. **Другой пользователь:**
   ```bash
   # Выйдите и войдите как:
   test
   # Password: 123
   ```

3. **Войти как root:**
   ```bash
   su -
   # Password: 123 или root
   ```

---

## ✅ После исправления

Когда SSH заработает, с вашего Mac выполните:

```bash
# Подключиться к VM
ssh user@10.0.88.41
# Password: 123

# Запустить SIEM сервисы
cd ~/monitoring/monitoring-stack
cd loki && docker compose up -d && cd ..
cd prometheus && docker compose up -d && cd ..
```

---

## 📞 Если не можете получить доступ к консоли

1. **Свяжитесь с провайдером** - попросите помочь с доступом к консоли
2. **Проверьте документацию провайдера** - как получить доступ к консоли VM
3. **Используйте другой сервер** - если есть доступ к другой VM в сети

---

**Помните: Все команды `sudo ufw disable` и т.д. выполняются НА VM, не на вашем Mac!**

