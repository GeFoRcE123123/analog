import bcrypt
import psycopg
from config import Config

conn = psycopg.connect(Config.DATABASE_URI)
cur = conn.cursor()

# Пароль администратора
admin_password = "Admin123!"
hashed_password = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()

try:
    # Проверяем структуру таблицы
    cur.execute("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'users' 
        AND column_name IN ('username', 'email', 'password_hash', 'role', 'full_name', 'is_active');
    """)
    
    columns = [row[0] for row in cur.fetchall()]
    print(f"Доступные колонки: {columns}")
    
    # Создаем администратора
    cur.execute("""
        INSERT INTO users (username, email, password_hash, role, full_name, is_active)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (email) DO UPDATE SET
            password_hash = EXCLUDED.password_hash,
            role = EXCLUDED.role,
            is_active = EXCLUDED.is_active,
            updated_at = CURRENT_TIMESTAMP
    """, ("admin", "admin@example.com", hashed_password, "admin", "Системный администратор", True))
    
    conn.commit()
    print("✅ Администратор создан/обновлен")
    print(f"Логин: admin@example.com")
    print(f"Пароль: {admin_password}")
    
    # Создаем тестового пользователя
    user_password = "User123!"
    user_hashed = bcrypt.hashpw(user_password.encode(), bcrypt.gensalt()).decode()
    
    cur.execute("""
        INSERT INTO users (username, email, password_hash, role, full_name, department, is_active)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (email) DO UPDATE SET
            password_hash = EXCLUDED.password_hash,
            role = EXCLUDED.role,
            department = EXCLUDED.department,
            updated_at = CURRENT_TIMESTAMP
    """, ("ivanov", "ivanov@example.com", user_hashed, "user", "Иванов Иван", "Отдел безопасности", True))
    
    conn.commit()
    print("✅ Тестовый пользователь создан")
    print(f"Логин: ivanov@example.com")
    print(f"Пароль: {user_password}")
    print(f"Роль: user")
    
    # Показываем всех пользователей
    cur.execute("SELECT id, username, email, role, is_active, created_at FROM users ORDER BY id;")
    users = cur.fetchall()
    
    print("\nВсе пользователи в системе:")
    for user in users:
        print(f"  ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Role: {user[3]}, Active: {user[4]}, Created: {user[5]}")
        
except Exception as e:
    print(f"❌ Ошибка: {e}")
    import traceback
    traceback.print_exc()
    conn.rollback()
finally:
    cur.close()
    conn.close()
