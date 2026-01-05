import psycopg
from config import Config

conn = psycopg.connect(Config.DATABASE_URI)
cur = conn.cursor()

try:
    # Тест запроса который используется в auth_service.py
    test_query = """
        SELECT id, username, email, password_hash, role, is_active, is_locked, 
               locked_until, failed_login_attempts, last_login, created_at, 
               full_name, department, updated_at
        FROM users 
        WHERE email = %s OR username = %s
        LIMIT 1
    """
    
    cur.execute(test_query, ("admin@example.com", "admin"))
    user = cur.fetchone()
    
    if user:
        print("✅ Запрос выполнен успешно!")
        print(f"Колонок в результате: {len(user)}")
        print(f"ID: {user[0]}")
        print(f"Username: {user[1]}")
        print(f"Email: {user[2]}")
        print(f"Role: {user[4]}")
        print(f"is_locked: {user[6]}")
        print(f"updated_at: {user[13]}")
    else:
        print("⚠️  Пользователь не найден")
        
    # Тест обновления last_login и updated_at
    print("\nТест обновления last_login и updated_at...")
    update_query = """
        UPDATE users SET last_login = %s, updated_at = %s WHERE id = %s
    """
    
    import datetime
    now = datetime.datetime.now()
    
    cur.execute(update_query, (now, now, user[0] if user else 1))
    conn.commit()
    
    print("✅ UPDATE запрос выполнен успешно!")
    
except Exception as e:
    print(f"❌ Ошибка: {e}")
    import traceback
    traceback.print_exc()
finally:
    cur.close()
    conn.close()
