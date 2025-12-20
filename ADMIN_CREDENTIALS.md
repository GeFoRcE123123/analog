# 🔐 Данные для входа администратора

## URL сайта
**http://10.0.88.10**

## Данные администратора

### Вариант 1 (рекомендуемый):
- **Email**: `admin@example.com`
- **Пароль**: `Admin123!`

### Вариант 2 (если первый не работает):
- **Email**: `admin@example.com`  
- **Пароль**: `admin123`

---

## 📝 Как создать администратора вручную

Если администратор не существует, выполните на Backend VM (10.0.88.20):

```bash
# Подключитесь к Backend VM
ssh user@10.0.88.20
# Пароль: 123

# Зайдите в контейнер
sudo docker exec -it vulnerability-backend bash

# Запустите скрипт создания админа
python3 create_admin.py
```

Или через API (если есть endpoint):

```bash
curl -X POST http://10.0.88.20:5000/api/admin/create \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "Admin123!",
    "role": "admin"
  }'
```

---

## ✅ Быстрая проверка

Откройте в браузере: **http://10.0.88.10**

Вы должны увидеть страницу входа. Введите:
- Email: `admin@example.com`
- Пароль: `Admin123!`

