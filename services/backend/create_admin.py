#!/usr/bin/env python3
"""Скрипт для создания администратора"""
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

# Данные администратора
admin_username = "admin"
admin_email = "admin@example.com"
admin_password = "Admin123!"
admin_full_name = "Системный администратор"

# Хешируем пароль
hashed_password = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()

try:
    # Проверяем, существует ли уже админ
    cur.execute("SELECT id, email FROM users WHERE role = 'admin' LIMIT 1")
    existing_admin = cur.fetchone()
    
    if existing_admin:
        # Обновляем существующего админа
        cur.execute("""
            UPDATE users 
            SET username = %s, 
                email = %s, 
                password_hash = %s, 
                full_name = %s,
                is_active = TRUE,
                is_locked = FALSE,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (admin_username, admin_email, hashed_password, admin_full_name, existing_admin[0]))
        print(f"✅ Администратор обновлен (ID: {existing_admin[0]})")
    else:
        # Создаем нового админа
        cur.execute("""
            INSERT INTO users (username, email, password_hash, role, full_name, is_active, is_locked)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (email) DO UPDATE SET
                username = EXCLUDED.username,
                password_hash = EXCLUDED.password_hash,
                role = EXCLUDED.role,
                full_name = EXCLUDED.full_name,
                is_active = EXCLUDED.is_active,
                is_locked = EXCLUDED.is_locked,
                updated_at = CURRENT_TIMESTAMP
        """, (admin_username, admin_email, hashed_password, "admin", admin_full_name, True, False))
        print("✅ Администратор создан")
    
    conn.commit()
    
    print("\n" + "="*50)
    print("🔐 ДАННЫЕ ДЛЯ ВХОДА АДМИНИСТРАТОРА")
    print("="*50)
    print(f"Email:    {admin_email}")
    print(f"Пароль:   {admin_password}")
    print("="*50)
    
    # Показываем всех админов
    cur.execute("SELECT id, username, email, role, is_active FROM users WHERE role = 'admin'")
    admins = cur.fetchall()
    
    print("\n📋 Все администраторы в системе:")
    for admin in admins:
        print(f"  ID: {admin[0]}, Username: {admin[1]}, Email: {admin[2]}, Active: {admin[4]}")
        
except Exception as e:
    print(f"❌ Ошибка: {e}")
    import traceback
    traceback.print_exc()
    conn.rollback()
finally:
    cur.close()
    conn.close()

