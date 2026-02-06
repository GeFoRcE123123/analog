import psycopg
from config import Config

conn = psycopg.connect(Config.DATABASE_URI)
cur = conn.cursor()

try:
    # Проверяем есть ли колонка updated_at
    cur.execute("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'updated_at';
    """)
    
    if not cur.fetchone():
        print("Добавляем колонку updated_at...")
        cur.execute("ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;")
        conn.commit()
        print("✅ Колонка updated_at добавлена")
    else:
        print("✅ Колонка updated_at уже существует")
    
    # Проверяем другие колонки
    required_columns = ['is_locked', 'locked_until', 'full_name', 'department', 'last_login']
    for column in required_columns:
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = %s;
        """, (column,))
        
        if not cur.fetchone():
            print(f"Добавляем колонку {column}...")
            
            if column in ['is_locked']:
                sql_type = "BOOLEAN DEFAULT FALSE"
            elif column in ['locked_until', 'last_login', 'updated_at']:
                sql_type = "TIMESTAMP"
            elif column in ['full_name', 'department']:
                sql_type = "VARCHAR(100)"
            else:
                sql_type = "INTEGER DEFAULT 0"
            
            cur.execute(f"ALTER TABLE users ADD COLUMN {column} {sql_type};")
            print(f"✅ Колонка {column} добавлена")
        else:
            print(f"✅ Колонка {column} уже существует")
    
    conn.commit()
    print("\n✅ Все проверки выполнены!")
    
    # Показываем структуру таблицы
    cur.execute("""
        SELECT column_name, data_type, is_nullable 
        FROM information_schema.columns 
        WHERE table_name = 'users' 
        ORDER BY ordinal_position;
    """)
    
    print("\nСтруктура таблицы users:")
    for col in cur.fetchall():
        print(f"  {col[0]}: {col[1]} ({'NULL' if col[2] == 'YES' else 'NOT NULL'})")
    
except Exception as e:
    print(f"❌ Ошибка: {e}")
    conn.rollback()
finally:
    cur.close()
    conn.close()
