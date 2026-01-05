# 🔒 Инфраструктура безопасности для Vulnerability Manager

## 📋 Компоненты безопасности

### 1. **Firewall (UFW)**

**Настройка правил для всех VM:**

```bash
# SSH доступ
ufw allow 22/tcp

# Backend API (только с Frontend и Parsers)
ufw allow from 10.0.88.10 to any port 5000
ufw allow from 10.0.88.23 to any port 5000

# Frontend (HTTP/HTTPS)
ufw allow 80/tcp
ufw allow 443/tcp

# Database PostgreSQL (только с Backend, Parsers, AI)
ufw allow from 10.0.88.20 to any port 5432
ufw allow from 10.0.88.23 to any port 5432
ufw allow from 10.0.88.25 to any port 5432

# ИИ-система API (только с Backend)
ufw allow from 10.0.88.20 to any port 8000
```

**Применение:**
```bash
sudo ufw enable
sudo ufw status
```

---

### 2. **SSL/TLS сертификаты**

**Использование Let's Encrypt:**

```bash
# Установка certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Получение сертификата для Frontend
sudo certbot --nginx -d vulnerability-manager.local

# Автоматическое обновление
sudo certbot renew --dry-run
```

**Настройка Nginx:**
- Используйте конфигурацию из `security_configs/nginx_ssl.conf`
- Включите HSTS (HTTP Strict Transport Security)
- Настройте security headers

---

### 3. **Fail2ban (Защита от брутфорса)**

**Установка:**
```bash
sudo apt-get install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

**Конфигурация:**
- Используйте `security_configs/jail.local`
- Настройте правила для SSH и Nginx

**Проверка:**
```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

---

### 4. **Мониторинг безопасности**

**Настройка логирования:**
- Все логи в `/var/log/vulnerability-manager/`
- Логи безопасности в `/var/log/security-monitor.log`
- Ротация логов через logrotate

**Скрипт мониторинга:**
```bash
# Добавить в crontab (каждые 5 минут)
*/5 * * * * /opt/vulnerability-manager/security_configs/monitoring.sh
```

---

### 5. **Резервное копирование**

**Автоматические бэкапы БД:**
```bash
# Скрипт backup_db.sh
#!/bin/bash
BACKUP_DIR="/var/backups/vulnerability-manager"
DATE=$(date +%Y%m%d_%H%M%S)

docker exec vulnerability_db pg_dump -U admin vuln_db > "$BACKUP_DIR/db_$DATE.sql"

# Хранение последних 30 дней
find "$BACKUP_DIR" -name "db_*.sql" -mtime +30 -delete
```

**Расписание (каждый день в 2:00):**
```bash
0 2 * * * /opt/vulnerability-manager/scripts/backup_db.sh
```

---

### 6. **Обновления системы**

**Автоматические обновления безопасности:**
```bash
# Установка unattended-upgrades
sudo apt-get install unattended-upgrades

# Конфигурация
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

### 7. **Аудит безопасности**

**Использование auditd:**
```bash
# Установка
sudo apt-get install auditd

# Мониторинг важных файлов
sudo auditctl -w /etc/passwd -p wa
sudo auditctl -w /etc/shadow -p wa
sudo auditctl -w /etc/sudoers -p wa
```

---

## 🚀 Быстрая настройка

1. **Запустите скрипт развертывания:**
```bash
./deploy_ai_system.sh
```

2. **Примените правила firewall на всех VM:**
```bash
# На каждой VM
sudo bash security_configs/firewall_rules.sh
```

3. **Настройте SSL (только на Frontend):**
```bash
sudo certbot --nginx -d your-domain.com
```

4. **Установите fail2ban:**
```bash
sudo apt-get install fail2ban
sudo cp security_configs/jail.local /etc/fail2ban/jail.local
sudo systemctl restart fail2ban
```

5. **Настройте мониторинг:**
```bash
sudo cp security_configs/monitoring.sh /opt/vulnerability-manager/
sudo chmod +x /opt/vulnerability-manager/monitoring.sh
sudo crontab -e
# Добавьте: */5 * * * * /opt/vulnerability-manager/monitoring.sh
```

---

## ✅ Чеклист безопасности

- [ ] Firewall настроен на всех VM
- [ ] SSL сертификаты установлены (Frontend)
- [ ] Fail2ban активен
- [ ] Автоматические обновления включены
- [ ] Резервное копирование настроено
- [ ] Мониторинг логирования работает
- [ ] SSH доступ защищен (ключи вместо паролей)
- [ ] Логи защищены и ротируются
- [ ] Доступ к БД ограничен только необходимыми VM
- [ ] ИИ-система доступна только из Backend

---

## 📊 Мониторинг

**Проверка статуса:**
```bash
# Firewall
sudo ufw status

# Fail2ban
sudo fail2ban-client status

# SSL сертификаты
sudo certbot certificates

# Логи безопасности
tail -f /var/log/security-monitor.log
```

