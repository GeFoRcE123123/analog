#!/usr/bin/env python3
"""
Демонстрационный скрипт для тестирования парсера Kaspersky с Selenium
Запускает парсер в режиме демонстрации с ограничением количества advisory
"""
import sys
import os
import logging
from pathlib import Path

# Добавляем корень проекта в путь
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Настройка логирования для демонстрации
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger(__name__)

def main():
    """Главная функция для демонстрации"""
    logger.info("=" * 70)
    logger.info("🚀 ДЕМОНСТРАЦИЯ ПАРСЕРА KASPERSKY С SELENIUM")
    logger.info("=" * 70)
    logger.info("")
    
    # Проверка зависимостей
    logger.info("📦 Проверка зависимостей...")
    try:
        import selenium
        logger.info(f"   ✅ Selenium {selenium.__version__} установлен")
    except ImportError:
        logger.error("   ❌ Selenium не установлен!")
        logger.error("   Установите: pip install selenium>=4.15.0")
        return 1
    
    try:
        import undetected_chromedriver as uc
        logger.info(f"   ✅ undetected-chromedriver доступен")
    except ImportError:
        logger.warning("   ⚠️  undetected-chromedriver не установлен")
        logger.warning("   Рекомендуется: pip install undetected-chromedriver>=3.5.0")
        logger.warning("   Парсер будет использовать стандартный ChromeDriver")
    
    logger.info("")
    
    # Проверка БД
    logger.info("🗄️  Проверка подключения к БД...")
    try:
        from config import Config
        from models.database import DatabaseManager
        from models.legacy_repositories import LegacyVulnerabilityRepository
        
        db_manager = DatabaseManager()
        vulnerability_repo = LegacyVulnerabilityRepository(db_manager.connection)
        logger.info("   ✅ Подключение к БД установлено")
    except Exception as e:
        logger.error(f"   ❌ Ошибка подключения к БД: {e}")
        logger.error("   Убедитесь, что БД запущена и настройки в config.py корректны")
        return 1
    
    logger.info("")
    
    # Импорт парсера
    logger.info("📥 Импорт парсера...")
    try:
        from services.legacy_parsers.kaspersky_selenium_parser import KasperskySeleniumParser
        logger.info("   ✅ Парсер импортирован успешно")
    except Exception as e:
        logger.error(f"   ❌ Ошибка импорта парсера: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    logger.info("")
    
    # Создание парсера
    logger.info("🔧 Создание экземпляра парсера...")
    try:
        # Используем headless=True для демонстрации (можно изменить на False для визуального режима)
        parser = KasperskySeleniumParser(
            vulnerability_repo,
            headless=True,  # Headless режим для демонстрации
            use_undetected=True
        )
        logger.info("   ✅ Парсер создан")
        logger.info("   Параметры:")
        logger.info(f"     - headless: True")
        logger.info(f"     - use_undetected: True")
    except Exception as e:
        logger.error(f"   ❌ Ошибка создания парсера: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    logger.info("")
    logger.info("=" * 70)
    logger.info("🌐 ЗАПУСК ПАРСИНГА")
    logger.info("=" * 70)
    logger.info("")
    logger.info("⚠️  ВНИМАНИЕ: Парсинг может занять несколько минут")
    logger.info("   Парсер будет:")
    logger.info("   1. Открывать страницу Kaspersky advisories")
    logger.info("   2. Находить список advisory")
    logger.info("   3. Кликать на каждую для раскрытия деталей")
    logger.info("   4. Извлекать информацию")
    logger.info("   5. Сохранять в БД")
    logger.info("")
    logger.info("📊 Демонстрация с ограничением: первые 3 advisory")
    logger.info("")
    
    try:
        # Запуск парсинга с ограничением для демонстрации
        results = parser.parse(limit=3)
        
        logger.info("")
        logger.info("=" * 70)
        logger.info("📊 РЕЗУЛЬТАТЫ ПАРСИНГА")
        logger.info("=" * 70)
        logger.info("")
        logger.info(f"✅ Спарсено advisory: {results['parsed']}")
        logger.info(f"✅ Сохранено уязвимостей: {results['saved']}")
        logger.info(f"❌ Ошибок: {len(results['errors'])}")
        logger.info("")
        
        if results['errors']:
            logger.warning("⚠️  Ошибки при парсинге:")
            for idx, error in enumerate(results['errors'], 1):
                logger.warning(f"   {idx}. {error}")
            logger.info("")
        
        if results['saved'] > 0:
            logger.info("🎉 Парсинг завершен успешно!")
            logger.info(f"   В БД добавлено {results['saved']} новых уязвимостей Kaspersky")
        else:
            logger.warning("⚠️  Не удалось сохранить уязвимости")
            if results['parsed'] > 0:
                logger.warning("   Возможные причины:")
                logger.warning("   - Уязвимости уже существуют в БД")
                logger.warning("   - Ошибки при сохранении (проверьте логи)")
        
        logger.info("")
        logger.info("=" * 70)
        
        return 0 if results['saved'] > 0 or results['parsed'] > 0 else 1
        
    except KeyboardInterrupt:
        logger.warning("")
        logger.warning("⚠️  Парсинг прерван пользователем (Ctrl+C)")
        return 1
    except Exception as e:
        logger.error("")
        logger.error(f"❌ Критическая ошибка при парсинге: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return 1

if __name__ == "__main__":
    exit(main())

