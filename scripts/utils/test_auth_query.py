import psycopg
from config import Config

conn = psycopg.connect(Config.DATABASE_URI)
cur = conn.cursor()

try:
    # Запрос, который используется в auth_service.py
    cur.execute("""
        SELECT id, username, email, password_hash, role, is_active, is_locked, 
               locked_until, failed_login_attempts, last_login, created_at, 
               full_name, department
        FROM users 
        WHERE email = %s OR username = %s
        LIMIT 1
    """, ("admin@example.com", "admin"))
    
    user = cur.fetchone()
    if user:
        print("✅ Запрос выполнен успешно")
        print(f"Найден пользователь: {user[1]} ({user[2]})")
        print(f"Колонки в результате: {len(user)}")
        print(f"is_locked значение: {user[6]}")
    else:
        print("⚠️  Пользователь не найден")
        
except Exception as e:
    print(f"❌ Ошибка в запросе: {e}")
finally:
    cur.close()
    conn.close()
