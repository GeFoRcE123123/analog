# 🚀 Руководство по развертыванию ИИ-системы

## 📋 Что нужно для доступа к VM 10.0.88.25

### Данные для подключения:
- **IP:** 10.0.88.25
- **Пользователь:** `k8s-worker` (из ваших данных: "10.0.88.25 k8s-worker k8s-worker")
- **Пароль:** `k8s-worker` (предположительно, или уточните у вас)

### Проверка доступа:

```bash
# Вариант 1: С паролем
sshpass -p 'k8s-worker' ssh k8s-worker@10.0.88.25 "whoami && hostname"

# Вариант 2: Интерактивный ввод пароля
ssh k8s-worker@10.0.88.25

# Вариант 3: Если используется kubectl (для k8s-worker)
kubectl get nodes | grep 10.0.88.25
kubectl get pods -A
```

---

## 🔧 Настройка учетных данных

Перед развертыванием установите переменные окружения:

```bash
# Для VM 10.0.88.25 (ИИ-система)
export AI_VM_USER="k8s-worker"
export AI_VM_PASS="k8s-worker"  # или ваш реальный пароль

# Для остальных VM (используются стандартные)
export USER="user"
export PASSWORD="123"
```

---

## 📦 Развертывание на существующую архитектуру

### Вариант 1: Автоматическое развертывание (рекомендуется)

```bash
# Развертывание ИИ-системы на все VM
./deploy.sh all

# Или только на определенные компоненты
./deploy.sh backend   # Только Backend
./deploy.sh frontend  # Только Frontend
```

**Что делает скрипт:**
1. ✅ Копирует `services/ai_integration_service.py` на Backend
2. ✅ Копирует `services/adaptive_html_parser.py` на Backend
3. ✅ Копирует `templates/ai/*.html` на Frontend
4. ✅ Обновляет `services/backend/app.py` на Backend
5. ✅ Обновляет `services/database/init.sql` на Database
6. ✅ Перезапускает сервисы для применения изменений

### Вариант 2: Развертывание только ИИ-системы

```bash
# Специализированный скрипт для ИИ-системы
./deploy_ai_system.sh
```

**Что делает скрипт:**
1. ✅ Проверяет доступ к VM 10.0.88.25
2. ✅ Анализирует структуру ИИ-системы
3. ✅ Настраивает безопасность
4. ✅ Развертывает на Backend и Frontend
5. ✅ Обновляет базу данных

---

## 🔒 Настройка инфраструктуры безопасности

### 1. Firewall правила

На каждой VM выполните:

```bash
# Скопируйте скрипт на VM
scp security_configs/firewall_rules.sh user@10.0.88.10:~/

# На VM выполните
ssh user@10.0.88.10
chmod +x firewall_rules.sh
sudo bash firewall_rules.sh
```

### 2. SSL сертификаты (только на Frontend)

```bash
# На Frontend VM (10.0.88.10)
ssh user@10.0.88.10
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### 3. Fail2ban (защита от брутфорса)

```bash
# На всех VM
for vm in 10.0.88.10 10.0.88.20 10.0.88.11 10.0.88.23; do
    ssh user@$vm "sudo apt-get install -y fail2ban && sudo systemctl enable fail2ban && sudo systemctl start fail2ban"
done
```

### 4. Автоматические обновления безопасности

```bash
# На всех VM
for vm in 10.0.88.10 10.0.88.20 10.0.88.11 10.0.88.23; do
    ssh user@$vm "sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
done
```

---

## ✅ Чеклист развертывания

### Перед развертыванием:
- [ ] Все VM доступны по сети (`ping 10.0.88.10`, etc.)
- [ ] SSH доступ работает (`ssh user@10.0.88.10`)
- [ ] Docker установлен на всех VM
- [ ] База данных запущена (`docker ps | grep vulnerability-db`)

### Развертывание:
- [ ] Запущен `./deploy.sh all`
- [ ] Или запущен `./deploy_ai_system.sh`
- [ ] Проверены логи на ошибки

### После развертывания:
- [ ] Проверен доступ к веб-интерфейсу: `http://10.0.88.10`
- [ ] Проверен доступ к ИИ-интерфейсу: `http://10.0.88.10/ai/dashboard`
- [ ] Проверена работа API: `curl http://10.0.88.20:5000/api/ai/statistics`
- [ ] Настроены правила firewall
- [ ] Настроены SSL сертификаты (если требуется)
- [ ] Настроен fail2ban

---

## 🔍 Проверка работы ИИ-системы

### 1. Проверка API endpoints:

```bash
# Статистика
curl http://10.0.88.20:5000/api/ai/statistics

# Ключевые слова
curl http://10.0.88.20:5000/api/ai/keywords

# Health check
curl http://10.0.88.20:5000/api/health
```

### 2. Проверка Frontend:

```bash
# Откройте в браузере
http://10.0.88.10/ai/dashboard
http://10.0.88.10/ai/statistics
http://10.0.88.10/ai/training  # только для админов
```

### 3. Проверка логов:

```bash
# Backend
ssh user@10.0.88.20 "docker logs vulnerability-backend --tail 100 | grep -i ai"

# Frontend
ssh user@10.0.88.10 "docker logs vulnerability-frontend --tail 100"

# Database (проверка новых таблиц)
ssh user@10.0.88.11 "docker exec vulnerability-db psql -U admin -d vuln_db -c '\dt ai_*'"
```

---

## 🆘 Устранение проблем

### Проблема: VM 10.0.88.25 недоступна

**Решения:**
1. Проверьте, запущена ли VM в гипервизоре
2. Проверьте сетевые настройки VM
3. Проверьте firewall на хосте
4. Попробуйте подключиться из другой сети

### Проблема: SSH доступ не работает

**Решения:**
1. Проверьте правильность пользователя и пароля
2. Настройте SSH ключи: `ssh-copy-id k8s-worker@10.0.88.25`
3. Проверьте настройки SSH на VM: `sudo nano /etc/ssh/sshd_config`

### Проблема: ИИ-интерфейс не отображается

**Решения:**
1. Проверьте, скопированы ли шаблоны: `ssh user@10.0.88.10 "ls -la ~/vulnerability_manager/templates/ai/"`
2. Проверьте логи Frontend: `docker logs vulnerability-frontend`
3. Перезапустите Frontend: `docker compose restart frontend`

### Проблема: API возвращает ошибки

**Решения:**
1. Проверьте логи Backend: `docker logs vulnerability-backend`
2. Проверьте подключение к БД: `docker exec vulnerability-db pg_isready`
3. Проверьте, созданы ли таблицы ИИ: `docker exec vulnerability-db psql -U admin -d vuln_db -c '\dt ai_*'`

---

## 📞 Поддержка

Если возникли проблемы:
1. Проверьте логи всех сервисов
2. Убедитесь, что все VM доступны
3. Проверьте права доступа на файлы
4. Проверьте конфигурацию firewall

