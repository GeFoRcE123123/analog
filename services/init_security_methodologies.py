#!/usr/bin/env python3
"""
Скрипт инициализации методологий безопасности
Применяет схему БД и загружает базовые методологии
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.database import DatabaseManager
from services.security_methodology_service import security_methodology_service
from config import Config
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def apply_schema():
    """Применить схему БД для методологий"""
    try:
        db_manager = DatabaseManager()
        schema_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'database',
            'security_methodologies_schema.sql'
        )
        
        if not os.path.exists(schema_path):
            logger.error(f"❌ Файл схемы не найден: {schema_path}")
            return False
        
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema_sql = f.read()
        
        # Разделяем на отдельные команды
        commands = [cmd.strip() for cmd in schema_sql.split(';') if cmd.strip()]
        
        cursor = db_manager.connection.cursor()
        for command in commands:
            if command:
                try:
                    cursor.execute(command)
                except Exception as e:
                    # Игнорируем ошибки если таблицы уже существуют
                    if 'already exists' not in str(e).lower() and 'duplicate' not in str(e).lower():
                        logger.warning(f"⚠️ Предупреждение при выполнении команды: {e}")
        
        db_manager.connection.commit()
        cursor.close()
        
        logger.info("✅ Схема БД применена успешно")
        return True
    except Exception as e:
        logger.error(f"❌ Ошибка применения схемы БД: {e}", exc_info=True)
        if db_manager.connection:
            db_manager.connection.rollback()
        return False


def load_base_methodologies():
    """Загрузить базовые методологии"""
    try:
        logger.info("📚 Загрузка базовых методологий...")
        
        # OWASP WSTG
        logger.info("📖 Загрузка OWASP WSTG...")
        if security_methodology_service.load_owasp_wstg():
            logger.info("✅ OWASP WSTG загружена")
        else:
            logger.warning("⚠️ Не удалось загрузить OWASP WSTG")
        
        # TODO: Добавить загрузку других методологий
        # - OSSTMM
        # - NIST SP 800-115
        # - OWASP MASTG
        # - PCI DSS
        
        logger.info("✅ Базовые методологии загружены")
        return True
    except Exception as e:
        logger.error(f"❌ Ошибка загрузки методологий: {e}", exc_info=True)
        return False


def main():
    """Основная функция"""
    logger.info("🚀 Инициализация методологий безопасности...")
    
    # Применяем схему БД
    if not apply_schema():
        logger.error("❌ Не удалось применить схему БД")
        return 1
    
    # Загружаем методологии
    if not load_base_methodologies():
        logger.error("❌ Не удалось загрузить методологии")
        return 1
    
    logger.info("✅ Инициализация завершена успешно!")
    return 0


if __name__ == '__main__':
    sys.exit(main())

