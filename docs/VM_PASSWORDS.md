# 🔐 Пароли для доступа к VM

Справочник паролей для всех виртуальных машин проекта.

---

## 📋 Пароли для VM

### Основные VM проекта

| VM | IP | Пользователь | Пароль | Назначение |
|---|---|-------------|---------|------------|
| **Database** | 10.0.88.11 | `user` | `123` | База данных PostgreSQL |
| **Frontend** | 10.0.88.10 | `user` | `123` | Веб-интерфейс (Nginx) |
| **Backend** | 10.0.88.20 | `user` | `123` | Backend API (Flask) |
| **Parsers** | 10.0.88.23 | `user` | `123` | Парсеры уязвимостей |
| **ML Platform** | 10.0.88.25 | `k8s-worker` | `k8s-worker` | ML платформа |

### SIEM/Monitoring VM

| VM | IP | Пользователь | Пароль | Назначение |
|---|---|-------------|---------|------------|
| **Monitoring/SIEM** | 10.0.88.41 | `user` | `123` | SIEM система (Loki, Prometheus, Grafana) |
| **Monitoring/SIEM** | 10.0.88.41 | `test` | `123` | Альтернативный пользователь |

**Примечание:** Для Monitoring VM могут использоваться оба пользователя: `user` или `test`. Пароль одинаковый: `123`

---

## 🔑 Дополнительные пароли

### База данных PostgreSQL

| Параметр | Значение |
|----------|----------|
| **Host** | 10.0.88.11 |
| **Port** | 5432 |
| **Database** | vuln_db |
| **Username** | admin |
| **Password** | 123 |

### Grafana (на Monitoring VM)

| Параметр | Значение |
|----------|----------|
| **URL** | http://10.0.88.41:3000 |
| **Username** | admin |
| **Password** | admin123 |

---

## 🔐 Использование паролей

### SSH подключение

```bash
# С использованием sshpass
sshpass -p "123" ssh user@10.0.88.41

# Или интерактивно (введет пароль при запросе)
ssh user@10.0.88.41
# Password: 123
```

### Для Monitoring VM

```bash
# Вариант 1: пользователь user
sshpass -p "123" ssh user@10.0.88.41

# Вариант 2: пользователь test
sshpass -p "123" ssh test@10.0.88.41
```

---

## ⚠️ Безопасность

**Важно:**
- ⚠️ Эти пароли используются для разработки
- ⚠️ В production окружении необходимо изменить все пароли
- ⚠️ Используйте SSH ключи вместо паролей
- ⚠️ Не коммитьте пароли в Git

### Рекомендации:

1. **Использовать SSH ключи:**
   ```bash
   ./scripts/setup_ssh.sh --with-keys
   ```

2. **Изменить пароли в production:**
   ```bash
   # На каждой VM
   passwd
   ```

3. **Отключить вход по паролю (после настройки ключей):**
   ```bash
   sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
   sudo systemctl restart ssh
   ```

---

## 📝 Быстрая справка

### Подключение к Monitoring VM (10.0.88.41)

```bash
# Если SSH работает
ssh user@10.0.88.41
# Password: 123

# Или с sshpass
sshpass -p "123" ssh user@10.0.88.41
```

### Если SSH не работает

См. инструкции в:
- [SIEM_SSH_EXPERT_REPORT.md](./SIEM_SSH_EXPERT_REPORT.md)
- [SIEM_VM_FIX.md](./SIEM_VM_FIX.md)

---

**Последнее обновление:** 2025-01-20

