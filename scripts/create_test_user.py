#!/usr/bin/env python3
"""Скрипт для создания тестового пользователя"""
import bcrypt
import psycopg
from config import Config

# Подключение к базе данных
conn = psycopg.connect(
    host=Config.DATABASE_CONFIG.host,
    port=Config.DATABASE_CONFIG.port,
    dbname=Config.DATABASE_CONFIG.database,
    user=Config.DATABASE_CONFIG.username,
    password=Config.DATABASE_CONFIG.password
)
cur = conn.cursor()

# Данные тестового пользователя
test_username = "testuser"
test_email = "test@example.com"
test_password = "Test123!"
test_full_name = "Тестовый пользователь"

# Хешируем пароль
hashed_password = bcrypt.hashpw(test_password.encode(), bcrypt.gensalt()).decode()

try:
    # Проверяем, существует ли уже пользователь
    cur.execute("SELECT id, email FROM users WHERE email = %s", (test_email,))
    existing_user = cur.fetchone()

    if existing_user:
        # Обновляем существующего пользователя
        cur.execute("""
            UPDATE users
            SET username = %s,
                password_hash = %s,
                full_name = %s,
                role = 'user',
                is_active = TRUE,
                is_locked = FALSE,
                updated_at = CURRENT_TIMESTAMP
            WHERE email = %s
        """, (test_username, hashed_password, test_full_name, test_email))
        print(f"✅ Тестовый пользователь обновлен (ID: {existing_user[0]})")
    else:
        # Создаем нового пользователя
        cur.execute("""
            INSERT INTO users (username, email, password_hash, role, full_name, is_active, is_locked)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (test_username, test_email, hashed_password, "user", test_full_name, True, False))
        print("✅ Тестовый пользователь создан")

    conn.commit()

    print("\n" + "="*50)
    print("🔐 ДАННЫЕ ДЛЯ ВХОДА ТЕСТОВОГО ПОЛЬЗОВАТЕЛЯ")
    print("="*50)
    print(f"Email:    {test_email}")
    print(f"Пароль:   {test_password}")
    print("="*50)

    # Показываем всех пользователей
    cur.execute("SELECT id, username, email, role, is_active FROM users ORDER BY created_at DESC")
    users = cur.fetchall()

    print("\n📋 Все пользователи в системе:")
    for user in users:
        print(f"  ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Role: {user[3]}, Active: {user[4]}")

except Exception as e:
    print(f"❌ Ошибка: {e}")
    import traceback
    traceback.print_exc()
    conn.rollback()
finally:
    cur.close()
    conn.close()
