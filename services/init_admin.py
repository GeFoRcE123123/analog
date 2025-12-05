# init_admin.py
from models.database import DatabaseManager
from services.auth_service import AuthService
import bcrypt

db = DatabaseManager()
auth = AuthService()
auth.create_user("admin", "admin@example.com", "admin123", "admin")
# Проверяем, есть ли уже админы
result = db.execute_query("SELECT COUNT(*) FROM users WHERE role = 'admin'")
if result[0][0] == 0:
    password = "admin123"  # ← замените на надёжный!
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db.execute_query("""
        INSERT INTO users (username, email, password_hash, role)
        VALUES (%s, %s, %s, 'admin')
        """, ("admin", "admin@example.com", password_hash)
    )
    print("✅ Администратор создан: admin / admin123")
else:
    print("ℹ️ Администратор уже существует")