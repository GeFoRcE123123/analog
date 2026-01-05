# 🗄️ Инструкция по запуску базы данных на VM 10.0.88.11

## Проблема
VM `10.0.88.11` недоступна по сети. Нужно запустить VM и PostgreSQL на ней.

---

## ✅ Способ 1: Автоматический запуск через deploy.sh

Если VM доступна, просто выполните:

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
./deploy.sh database
```

---

## ✅ Способ 2: Ручной запуск через SSH

### Шаг 1: Проверьте доступность VM

```bash
ping -c 3 10.0.88.11
```

Если ping не проходит, **запустите VM** в вашем гипервизоре (VirtualBox, VMware, Hyper-V, Proxmox и т.д.).

### Шаг 2: Подключитесь к VM

```bash
ssh user@10.0.88.11
# Пароль: 123
```

### Шаг 3: Убедитесь, что Docker установлен

```bash
docker --version
docker compose version  # или docker-compose --version
```

Если Docker не установлен, установите его:
- Ubuntu/Debian: `sudo apt-get update && sudo apt-get install -y docker.io docker-compose`
- CentOS/RHEL: `sudo yum install -y docker docker-compose`

### Шаг 4: Скопируйте файлы на VM (если их еще нет)

На вашей локальной машине:

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
sshpass -p "123" scp -r services/database user@10.0.88.11:~/vulnerability_manager/
```

### Шаг 5: Запустите PostgreSQL контейнер

На VM 10.0.88.11:

```bash
cd ~/vulnerability_manager/database

# Остановите существующий PostgreSQL (если запущен)
sudo systemctl stop postgresql 2>/dev/null || true
sudo docker ps -q --filter 'publish=5432' | xargs -r sudo docker stop 2>/dev/null || true

# Запустите контейнер
echo "123" | sudo -S docker compose down
echo "123" | sudo -S docker compose up -d --build

# Проверьте статус
sudo docker ps | grep vulnerability_db
```

### Шаг 6: Проверьте подключение

```bash
# Проверьте, что контейнер запущен
sudo docker ps | grep postgres

# Проверьте логи
sudo docker logs vulnerability_db | tail -20

# Проверьте подключение из контейнера
sudo docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT version();"
```

---

## ✅ Способ 3: Запуск через локальный PostgreSQL (временное решение)

Если VM недоступна, можно временно запустить PostgreSQL локально:

### Вариант A: Docker локально

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager/services/database
docker compose up -d
```

Затем измените `config.py` чтобы использовать `localhost` вместо `10.0.88.11`.

### Вариант B: Установленный PostgreSQL

Если у вас установлен PostgreSQL локально:

```bash
# Создайте базу данных
createdb vuln_db

# Запустите init.sql
psql -d vuln_db -f services/database/init.sql
```

---

## 🔧 Настройка сетевой доступности VM

Если VM запущена, но недоступна по сети:

### 1. Проверьте сетевой режим VM
- **Bridge/NAT**: Убедитесь, что VM находится в той же подсети
- **Host-only**: Настройте сеть на `10.0.88.0/24`

### 2. Проверьте firewall на VM

```bash
# Ubuntu/Debian
sudo ufw status
sudo ufw allow 5432/tcp

# CentOS/RHEL
sudo firewall-cmd --list-all
sudo firewall-cmd --add-port=5432/tcp --permanent
sudo firewall-cmd --reload
```

### 3. Проверьте, что PostgreSQL слушает на всех интерфейсах

В `services/database/docker-compose.yml` уже настроено:
```yaml
command: >
  postgres
  -c listen_addresses='*'
```

---

## ✅ Проверка работоспособности

После запуска базы данных проверьте:

```bash
# 1. Проверьте доступность порта
nc -zv 10.0.88.11 5432

# 2. Проверьте подключение из backend VM
ssh user@10.0.88.20
psql -h 10.0.88.11 -U admin -d vuln_db -c "SELECT 1;"

# 3. Проверьте логи backend
ssh user@10.0.88.20
sudo docker logs vulnerability-backend | tail -20
```

---

## 📝 Структура файлов базы данных

```
services/database/
├── docker-compose.yml  # Конфигурация PostgreSQL контейнера
├── init.sql           # SQL скрипт инициализации (создание таблиц)
└── pg_hba.conf        # Конфигурация доступа (если нужна)
```

---

## 🔑 Учетные данные по умолчанию

- **Host**: 10.0.88.11
- **Port**: 5432
- **Database**: vuln_db
- **User**: admin
- **Password**: 123

---

## ❗ Важные замечания

1. **Пароль в production**: Измените пароль `123` на более безопасный в production!
2. **Сетевая безопасность**: Убедитесь, что порт 5432 не доступен из интернета
3. **Резервное копирование**: Настройте регулярные бэкапы базы данных

---

## 🆘 Если ничего не помогает

1. Проверьте логи PostgreSQL: `sudo docker logs vulnerability_db`
2. Проверьте сетевые настройки VM в гипервизоре
3. Убедитесь, что все VM находятся в одной сети (10.0.88.0/24)
4. Проверьте, что Docker запущен на VM: `sudo systemctl status docker`

