-- Миграция: таблица сгенерированных паролей для раздела управления пользователями
-- Выполнить на существующей БД, если таблица ещё не создана.

CREATE TABLE IF NOT EXISTS user_generated_passwords (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    plain_password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_generated_passwords_user_id ON user_generated_passwords(user_id);
