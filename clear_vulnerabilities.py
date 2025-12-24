#!/usr/bin/env python3
"""
Скрипт для очистки данных по уязвимостям из базы данных
Использование: python clear_vulnerabilities.py [--confirm]
"""
import sys
import argparse
from models.database import DatabaseManager
from config import Config

def clear_vulnerabilities(confirm: bool = False):
    """Очистка всех данных по уязвимостям из БД"""
    
    if not confirm:
        print("⚠️  ВНИМАНИЕ: Этот скрипт удалит ВСЕ данные по уязвимостям из базы данных!")
        print("   Будут очищены таблицы: turn, cvelist, cwelist, map_table, actids, parsing_history")
        response = input("   Продолжить? (yes/no): ")
        if response.lower() not in ['yes', 'y', 'да']:
            print("❌ Операция отменена")
            return False
    
    db_manager = DatabaseManager()
    
    try:
        print("🔍 Подключение к базе данных...")
        connection = db_manager.connection
        
        if not connection or connection.closed:
            print("❌ Ошибка: не удалось подключиться к базе данных")
            return False
        
        print("✅ Подключение установлено")
        
        with connection.cursor() as cursor:
            # Подсчет записей перед удалением
            print("\n📊 Подсчет записей перед удалением...")
            
            tables_to_check = ['turn', 'cvelist', 'cwelist', 'map_table', 'actids', 'parsing_history']
            counts = {}
            
            for table in tables_to_check:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    counts[table] = count
                    print(f"   {table}: {count} записей")
                except Exception as e:
                    print(f"   ⚠️  {table}: таблица не существует или недоступна ({e})")
                    counts[table] = 0
            
            total_count = sum(counts.values())
            print(f"\n📊 Всего записей для удаления: {total_count}")
            
            if total_count == 0:
                print("✅ База данных уже пуста")
                return True
            
            # Очистка таблиц в правильном порядке (с учетом внешних ключей)
            print("\n🗑️  Начало очистки...")
            
            # 1. actids (зависит от turn через CVE)
            if counts.get('actids', 0) > 0:
                print("   Очистка actids...")
                cursor.execute("DELETE FROM actids")
                print(f"   ✅ Удалено {cursor.rowcount} записей из actids")
            
            # 2. map_table (зависит от cvelist и cwelist)
            if counts.get('map_table', 0) > 0:
                print("   Очистка map_table...")
                cursor.execute("DELETE FROM map_table")
                print(f"   ✅ Удалено {cursor.rowcount} записей из map_table")
            
            # 3. cwelist (может использоваться в map_table, но уже очищен)
            if counts.get('cwelist', 0) > 0:
                print("   Очистка cwelist...")
                cursor.execute("DELETE FROM cwelist")
                print(f"   ✅ Удалено {cursor.rowcount} записей из cwelist")
            
            # 4. cvelist (используется в turn, но turn очистим после)
            if counts.get('cvelist', 0) > 0:
                print("   Очистка cvelist...")
                cursor.execute("DELETE FROM cvelist")
                print(f"   ✅ Удалено {cursor.rowcount} записей из cvelist")
            
            # 5. turn (основная таблица уязвимостей)
            if counts.get('turn', 0) > 0:
                print("   Очистка turn...")
                cursor.execute("DELETE FROM turn")
                print(f"   ✅ Удалено {cursor.rowcount} записей из turn")
            
            # 6. parsing_history (независимая таблица)
            if counts.get('parsing_history', 0) > 0:
                print("   Очистка parsing_history...")
                cursor.execute("DELETE FROM parsing_history")
                print(f"   ✅ Удалено {cursor.rowcount} записей из parsing_history")
            
            # Коммит транзакции
            connection.commit()
            print("\n✅ Все данные успешно очищены!")
            
            # Проверка после удаления
            print("\n🔍 Проверка после очистки...")
            for table in tables_to_check:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    if count > 0:
                        print(f"   ⚠️  {table}: осталось {count} записей")
                    else:
                        print(f"   ✅ {table}: пусто")
                except:
                    pass
            
            return True
            
    except Exception as e:
        print(f"\n❌ Ошибка при очистке данных: {e}")
        import traceback
        traceback.print_exc()
        if connection:
            connection.rollback()
        return False
    finally:
        if connection:
            connection.close()
            print("\n🔌 Соединение с базой данных закрыто")

def main():
    parser = argparse.ArgumentParser(description='Очистка данных по уязвимостям из БД')
    parser.add_argument('--confirm', action='store_true', 
                       help='Пропустить подтверждение (использовать с осторожностью!)')
    args = parser.parse_args()
    
    success = clear_vulnerabilities(confirm=args.confirm)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

