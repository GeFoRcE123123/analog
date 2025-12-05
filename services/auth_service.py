# services/auth_service.py
import bcrypt
from datetime import datetime, timedelta
from typing import Optional
from models.database import DatabaseManager

class AuthService:
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
    HASH_ROUNDS = 12  # bcrypt cost

    def __init__(self):
        self.db = DatabaseManager()

    def hash_password(self, password: str) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=self.HASH_ROUNDS)).decode('utf-8')

    def verify_password(self, plain: str, hashed: str) -> bool:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))

    def log_attempt(self, user_id: Optional[int], ip: str, user_agent: str, success: bool):
        query = """
            INSERT INTO login_attempts (user_id, ip_address, user_agent, success)
            VALUES (%s, %s, %s, %s)
        """
        self.db.execute_query(query, (user_id, ip, user_agent, success))

    def authenticate(self, email: str, password: str, ip: str = "127.0.0.1", user_agent: str = "") -> Optional[dict]:
        user = self._get_user_by_email(email)
        if not user:
            self.log_attempt(None, ip, user_agent, False)
            return None

        if not user['is_active'] or user['is_locked']:
            self.log_attempt(user['id'], ip, user_agent, False)
            return None

        locked_until = user['locked_until']
        if locked_until and datetime.utcnow() < locked_until:
            return None

        if self.verify_password(password, user['password_hash']):
            self._reset_failed_attempts(user['id'])
            self._update_last_login(user['id'])
            self.log_attempt(user['id'], ip, user_agent, True)
            return user
        else:
            self._increment_failed_attempts(user['id'])
            self.log_attempt(user['id'], ip, user_agent, False)
            return None

    def _get_user_by_email(self, email: str) -> Optional[dict]:
        query = """
            SELECT id, username, email, password_hash, role, is_active, is_locked,
                   locked_until, failed_login_attempts, full_name
            FROM users WHERE email = %s
        """
        result = self.db.execute_query(query, (email,))
        if result:
            row = result[0]
            return {
                'id': row[0], 'username': row[1], 'email': row[2], 'password_hash': row[3],
                'role': row[4], 'is_active': row[5], 'is_locked': row[6], 'locked_until': row[7],
                'failed_login_attempts': row[8], 'full_name': row[9]
            }
        return None

    def _increment_failed_attempts(self, user_id: int):
        query = "SELECT failed_login_attempts FROM users WHERE id = %s"
        result = self.db.execute_query(query, (user_id,))
        if not result:
            return
        attempts = result[0][0] + 1
        if attempts >= self.MAX_FAILED_ATTEMPTS:
            lock_until = datetime.utcnow() + timedelta(minutes=self.LOCKOUT_MINUTES)
            self.db.execute_query(
                "UPDATE users SET failed_login_attempts = %s, is_locked = TRUE, locked_until = %s WHERE id = %s",
                (attempts, lock_until, user_id)
            )
        else:
            self.db.execute_query(
                "UPDATE users SET failed_login_attempts = %s WHERE id = %s",
                (attempts, user_id)
            )

    def _reset_failed_attempts(self, user_id: int):
        self.db.execute_query(
            "UPDATE users SET failed_login_attempts = 0, is_locked = FALSE, locked_until = NULL WHERE id = %s",
            (user_id,)
        )

    def _update_last_login(self, user_id: int):
        self.db.execute_query(
            "UPDATE users SET last_login = %s, updated_at = %s WHERE id = %s",
            (datetime.utcnow(), datetime.utcnow(), user_id)
        )

    def create_user(self, username: str, email: str, password: str, role: str = 'user', full_name: str = None) -> bool:
        if role not in ('admin', 'user'):
            return False
        password_hash = self.hash_password(password)
        query = """
            INSERT INTO users (username, email, password_hash, role, full_name)
            VALUES (%s, %s, %s, %s, %s)
        """
        try:
            self.db.execute_query(query, (username, email, password_hash, role, full_name))
            return True
        except Exception:
            return False