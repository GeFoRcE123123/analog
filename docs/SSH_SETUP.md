# 🔐 Настройка SSH подключений к VM проекта

Это руководство поможет настроить удобные SSH подключения ко всем виртуальным машинам проекта Vulnerability Manager.

## 📋 Обзор VM

Проект использует следующие виртуальные машины:

| VM | IP адрес | Пользователь | Назначение |
|---|---|---|---|
| **Database** | 10.0.88.11 | `user` | База данных PostgreSQL |
| **Frontend** | 10.0.88.10 | `user` | Веб-интерфейс |
| **Backend** | 10.0.88.20 | `user` | Backend API |
| **Parsers** | 10.0.88.23 | `user` | Парсеры уязвимостей |
| **ML Platform** | 10.0.88.25 | `k8s-worker` | ML платформа (k8s-worker) |

---

## 🚀 Быстрая настройка

### Вариант 1: Автоматическая настройка (рекомендуется)

Запустите скрипт настройки:

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
chmod +x scripts/setup_ssh.sh
./scripts/setup_ssh.sh --with-keys
```

Скрипт автоматически:
1. ✅ Создаст SSH ключ (если его нет)
2. ✅ Скопирует ключ на все VM
3. ✅ Настроит SSH config для удобного доступа
4. ✅ Протестирует подключения

### Вариант 2: Ручная настройка SSH ключей

#### Шаг 1: Генерация SSH ключа

```bash
ssh-keygen -t ed25519 -C "vulnerability_manager@$(hostname)" -f ~/.ssh/vulnerability_manager_key -N ""
```

#### Шаг 2: Копирование ключа на VM

**С использованием sshpass (если установлен):**

```bash
# Установка sshpass на macOS
brew install hudochenkov/sshpass/sshpass

# Копирование ключей
export SSHPASS="123"
sshpass -e ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.11
sshpass -e ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.10
sshpass -e ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.20
sshpass -e ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.23
sshpass -e ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub k8s-worker@10.0.88.25
```

**Без sshpass (вручную):**

```bash
ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.11
ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.10
ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.20
ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.23
ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub k8s-worker@10.0.88.25
```

#### Шаг 3: Настройка SSH config

Создайте или отредактируйте файл `~/.ssh/config`:

```bash
cat >> ~/.ssh/config << 'EOF'

# Vulnerability Manager VM Config
Host database-vm
    HostName 10.0.88.11
    User user
    IdentityFile ~/.ssh/vulnerability_manager_key
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

Host frontend-vm
    HostName 10.0.88.10
    User user
    IdentityFile ~/.ssh/vulnerability_manager_key
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

Host backend-vm
    HostName 10.0.88.20
    User user
    IdentityFile ~/.ssh/vulnerability_manager_key
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

Host parsers-vm
    HostName 10.0.88.23
    User user
    IdentityFile ~/.ssh/vulnerability_manager_key
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

Host ml-platform-vm
    HostName 10.0.88.25
    User k8s-worker
    IdentityFile ~/.ssh/vulnerability_manager_key
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts
EOF

chmod 600 ~/.ssh/config
```

---

## ✅ Использование

После настройки вы можете подключаться к VM используя короткие имена:

```bash
# Подключение к VM
ssh database-vm
ssh frontend-vm
ssh backend-vm
ssh parsers-vm
ssh ml-platform-vm

# Выполнение команд без интерактивного входа
ssh backend-vm "docker ps"
ssh database-vm "docker logs vulnerability-db --tail 50"

# Копирование файлов
scp file.txt backend-vm:~/
scp -r ./directory backend-vm:~/vulnerability_manager/

# Синхронизация директорий
rsync -avz ./ backend-vm:~/vulnerability_manager/
```

---

## 🔧 Проверка подключений

Проверьте доступность всех VM:

```bash
# Проверка ping
ping -c 1 10.0.88.11
ping -c 1 10.0.88.10
ping -c 1 10.0.88.20
ping -c 1 10.0.88.23
ping -c 1 10.0.88.25

# Проверка SSH подключений
ssh database-vm "echo 'Database VM OK'"
ssh frontend-vm "echo 'Frontend VM OK'"
ssh backend-vm "echo 'Backend VM OK'"
ssh parsers-vm "echo 'Parsers VM OK'"
ssh ml-platform-vm "echo 'ML Platform VM OK'"
```

---

## 🛠️ Устранение проблем

### Проблема: "Permission denied (publickey)"

**Решение:**
1. Убедитесь, что ключ скопирован на VM:
   ```bash
   ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.11
   ```

2. Проверьте права доступа:
   ```bash
   chmod 600 ~/.ssh/vulnerability_manager_key
   chmod 644 ~/.ssh/vulnerability_manager_key.pub
   ```

3. Проверьте, что на VM включена авторизация по ключам:
   ```bash
   ssh user@10.0.88.11 "cat ~/.ssh/authorized_keys"
   ```

### Проблема: "Host key verification failed"

**Решение:**
```bash
# Удалите старые ключи хостов
ssh-keygen -R 10.0.88.11
ssh-keygen -R 10.0.88.10
ssh-keygen -R 10.0.88.20
ssh-keygen -R 10.0.88.23
ssh-keygen -R 10.0.88.25

# Или используйте StrictHostKeyChecking=no в SSH config (уже настроено)
```

### Проблема: VM недоступна (ping failed)

**Решение:**
1. Проверьте, что VM запущены
2. Проверьте сетевую доступность
3. Проверьте настройки файрвола на VM:
   ```bash
   ssh user@10.0.88.11 "sudo ufw status"
   ```

### Проблема: Требуется пароль при подключении

**Решение:**
1. Убедитесь, что ключ скопирован:
   ```bash
   ssh-copy-id -i ~/.ssh/vulnerability_manager_key.pub user@10.0.88.11
   ```

2. Проверьте SSH config:
   ```bash
   cat ~/.ssh/config | grep -A 5 "database-vm"
   ```

3. Используйте явное указание ключа:
   ```bash
   ssh -i ~/.ssh/vulnerability_manager_key user@10.0.88.11
   ```

---

## 🔒 Безопасность

### Рекомендации:

1. **Используйте SSH ключи вместо паролей** - более безопасно
2. **Ограничьте доступ по SSH** - настройте файрвол на VM
3. **Используйте разные ключи** для разных окружений
4. **Регулярно ротируйте ключи** - меняйте их периодически
5. **Отключите вход по паролю** на VM после настройки ключей:
   ```bash
   # На VM
   sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```

---

## 📚 Дополнительные ресурсы

- [Документация по деплою](./README_DEPLOYMENT.md)
- [Требования доступа к VM](./VM_ACCESS_REQUIREMENTS.md)
- [Установка sshpass](./INSTALL_SSHPASS.md)
- [Скрипт деплоя](../scripts/deploy.sh)

---

## 🎯 Быстрые команды

```bash
# Подключение к Backend VM
ssh backend-vm

# Просмотр логов контейнера
ssh backend-vm "docker logs vulnerability-backend --tail 100"

# Перезапуск сервиса
ssh backend-vm "cd ~/vulnerability_manager/backend && docker compose restart"

# Копирование файла на Backend
scp config.py backend-vm:~/vulnerability_manager/

# Выполнение команды на всех VM
for vm in database-vm frontend-vm backend-vm parsers-vm; do
    echo "=== $vm ==="
    ssh $vm "docker ps"
done
```

