#!/usr/bin/env python3
"""
БДУ ФСТЭК Importer
==================

Импортер для загрузки данных БДУ ФСТЭК в базу данных PostgreSQL

Использование:
    python bdu_importer.py --xml-file path/to/vulxml.xml [--batch-size 1000] [--dry-run]

Автор: Vulnerability Manager System
Дата: 2026-01-22
"""

import sys
import os
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import psycopg2
from psycopg2.extras import execute_batch

# Добавляем корневую директорию проекта в PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.parsers.bdu_xml_parser import BDUXMLParser

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BDUImporter:
    """
    Импортер данных БДУ ФСТЭК в PostgreSQL
    
    Возможности:
    - Пакетная загрузка данных (batch insert)
    - Обработка конфликтов (upsert)
    - Dry-run режим для тестирования
    - Статистика импорта
    """
    
    # SQL запрос для вставки/обновления уязвимости
    UPSERT_QUERY = """
    INSERT INTO vulnerabilities (
        title, description, severity, status, cvss_score, risk_level, category,
        -- БДУ поля
        bdu_id, bdu_name, vendor, product_name, affected_versions, platform,
        software_types, registry_number, vulnerable_software, environment,
        cwes, vul_class, sl_oper_procs,
        identify_date, publication_date, last_upd_date,
        cvss2_vector, cvss2_score, cvss3_vector, cvss3_score, bdu_severity,
        vul_status, exploit_status, fix_status, solution, sources, other_identifiers,
        vul_incident, vul_state, vul_elimination,
        -- NVD поля (опционально)
        cve_id,
        -- Даты
        created_date
    ) VALUES (
        %(title)s, %(description)s, %(severity)s, %(status)s, %(cvss_score)s, %(risk_level)s, %(category)s,
        %(bdu_id)s, %(bdu_name)s, %(vendor)s, %(product_name)s, %(affected_versions)s, %(platform)s,
        %(software_types)s, %(registry_number)s, %(vulnerable_software)s, %(environment)s,
        %(cwes)s, %(vul_class)s, %(sl_oper_procs)s,
        %(identify_date)s, %(publication_date)s, %(last_upd_date)s,
        %(cvss2_vector)s, %(cvss2_score)s, %(cvss3_vector)s, %(cvss3_score)s, %(bdu_severity)s,
        %(vul_status)s, %(exploit_status)s, %(fix_status)s, %(solution)s, %(sources)s, %(other_identifiers)s,
        %(vul_incident)s, %(vul_state)s, %(vul_elimination)s,
        %(cve_id)s,
        %(created_date)s
    )
    ON CONFLICT (bdu_id) DO UPDATE SET
        bdu_name = EXCLUDED.bdu_name,
        description = EXCLUDED.description,
        severity = EXCLUDED.severity,
        cvss_score = EXCLUDED.cvss_score,
        vendor = EXCLUDED.vendor,
        product_name = EXCLUDED.product_name,
        affected_versions = EXCLUDED.affected_versions,
        platform = EXCLUDED.platform,
        software_types = EXCLUDED.software_types,
        vulnerable_software = EXCLUDED.vulnerable_software,
        environment = EXCLUDED.environment,
        cwes = EXCLUDED.cwes,
        vul_class = EXCLUDED.vul_class,
        sl_oper_procs = EXCLUDED.sl_oper_procs,
        last_upd_date = EXCLUDED.last_upd_date,
        cvss2_vector = EXCLUDED.cvss2_vector,
        cvss2_score = EXCLUDED.cvss2_score,
        cvss3_vector = EXCLUDED.cvss3_vector,
        cvss3_score = EXCLUDED.cvss3_score,
        bdu_severity = EXCLUDED.bdu_severity,
        vul_status = EXCLUDED.vul_status,
        exploit_status = EXCLUDED.exploit_status,
        fix_status = EXCLUDED.fix_status,
        solution = EXCLUDED.solution,
        sources = EXCLUDED.sources,
        other_identifiers = EXCLUDED.other_identifiers,
        vul_incident = EXCLUDED.vul_incident,
        vul_state = EXCLUDED.vul_state,
        vul_elimination = EXCLUDED.vul_elimination,
        cve_id = EXCLUDED.cve_id;
    """
    
    def __init__(self, db_config: Dict[str, str], batch_size: int = 1000, dry_run: bool = False):
        """
        Args:
            db_config: Конфигурация подключения к БД
            batch_size: Размер пакета для batch insert
            dry_run: Режим без записи в БД (только статистика)
        """
        self.db_config = db_config
        self.batch_size = batch_size
        self.dry_run = dry_run
        self.conn = None
        self.cursor = None
        
        self.stats = {
            'total_parsed': 0,
            'inserted': 0,
            'updated': 0,
            'errors': 0,
            'skipped': 0,
        }
    
    def connect(self):
        """Подключение к БД"""
        try:
            self.conn = psycopg2.connect(**self.db_config)
            self.cursor = self.conn.cursor()
            logger.info(f"✅ Подключение к БД успешно: {self.db_config['host']}")
        except Exception as e:
            logger.error(f"❌ Ошибка подключения к БД: {e}")
            raise
    
    def disconnect(self):
        """Отключение от БД"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
        logger.info("БД соединение закрыто")
    
    def import_from_xml(self, xml_file_path: str):
        """
        Импорт данных из XML файла БДУ
        
        Args:
            xml_file_path: Путь к vulxml.xml
        """
        logger.info(f"Начало импорта из {xml_file_path}")
        
        if not self.dry_run:
            self.connect()
        
        try:
            parser = BDUXMLParser(xml_file_path)
            batch = []
            
            for vuln_data in parser.parse_stream():
                self.stats['total_parsed'] += 1
                
                # Подготовка данных для вставки
                record = self._prepare_record(vuln_data)
                batch.append(record)
                
                # Вставка пакетом
                if len(batch) >= self.batch_size:
                    self._insert_batch(batch)
                    batch = []
                
                # Логирование прогресса
                if self.stats['total_parsed'] % 5000 == 0:
                    self._log_progress()
            
            # Вставка оставшихся записей
            if batch:
                self._insert_batch(batch)
            
            # Финальная статистика
            self._log_final_stats(parser.get_statistics())
            
        except Exception as e:
            logger.error(f"❌ Ошибка импорта: {e}")
            if self.conn:
                self.conn.rollback()
            raise
        finally:
            if not self.dry_run:
                self.disconnect()
    
    def _prepare_record(self, vuln_data: Dict) -> Dict:
        """
        Подготовка записи для вставки в БД
        
        Args:
            vuln_data: Данные уязвимости из парсера
        
        Returns:
            Dict готовый для INSERT
        """
        # Преобразование JSONB полей
        software_types_json = json.dumps(vuln_data.get('software_types', []), ensure_ascii=False)
        vulnerable_software_json = json.dumps(vuln_data.get('vulnerable_software', []), ensure_ascii=False)
        environment_json = json.dumps(vuln_data.get('environment', []), ensure_ascii=False)
        cwes_json = json.dumps(vuln_data.get('cwes', []), ensure_ascii=False)
        sl_oper_procs_json = json.dumps(vuln_data.get('sl_oper_procs', []), ensure_ascii=False)
        other_identifiers_json = json.dumps(vuln_data.get('other_identifiers', []), ensure_ascii=False)
        
        return {
            'title': vuln_data.get('title'),
            'description': vuln_data.get('description'),
            'severity': vuln_data.get('severity'),
            'status': 'new',  # Новые импортированные уязвимости
            'cvss_score': vuln_data.get('cvss_score', 0.0),
            'risk_level': vuln_data.get('severity', 'medium'),
            'category': 'bdu',
            
            # БДУ поля
            'bdu_id': vuln_data.get('bdu_id'),
            'bdu_name': vuln_data.get('bdu_name'),
            'vendor': vuln_data.get('vendor'),
            'product_name': vuln_data.get('product_name'),
            'affected_versions': vuln_data.get('affected_versions'),
            'platform': vuln_data.get('platform'),
            'software_types': software_types_json,
            'registry_number': vuln_data.get('registry_number'),
            'vulnerable_software': vulnerable_software_json,
            'environment': environment_json,
            'cwes': cwes_json,
            'vul_class': vuln_data.get('vul_class'),
            'sl_oper_procs': sl_oper_procs_json,
            'identify_date': vuln_data.get('identify_date'),
            'publication_date': vuln_data.get('publication_date'),
            'last_upd_date': vuln_data.get('last_upd_date'),
            'cvss2_vector': vuln_data.get('cvss2_vector'),
            'cvss2_score': vuln_data.get('cvss2_score'),
            'cvss3_vector': vuln_data.get('cvss3_vector'),
            'cvss3_score': vuln_data.get('cvss3_score'),
            'bdu_severity': vuln_data.get('bdu_severity'),
            'vul_status': vuln_data.get('vul_status'),
            'exploit_status': vuln_data.get('exploit_status'),
            'fix_status': vuln_data.get('fix_status'),
            'solution': vuln_data.get('solution'),
            'sources': vuln_data.get('sources'),
            'other_identifiers': other_identifiers_json,
            'vul_incident': vuln_data.get('vul_incident'),
            'vul_state': vuln_data.get('vul_state'),
            'vul_elimination': vuln_data.get('vul_elimination'),
            
            # NVD поля
            'cve_id': vuln_data.get('cve_id'),
            
            # Даты
            'created_date': datetime.now(),
        }
    
    def _insert_batch(self, batch: List[Dict]):
        """
        Вставка пакета записей в БД
        
        Args:
            batch: Список записей
        """
        if self.dry_run:
            logger.info(f"[DRY RUN] Пропуск вставки {len(batch)} записей")
            self.stats['inserted'] += len(batch)
            return
        
        try:
            execute_batch(self.cursor, self.UPSERT_QUERY, batch, page_size=100)
            self.conn.commit()
            self.stats['inserted'] += len(batch)
        except Exception as e:
            logger.error(f"❌ Ошибка вставки пакета: {e}")
            self.stats['errors'] += len(batch)
            self.conn.rollback()
    
    def _log_progress(self):
        """Логирование прогресса"""
        logger.info(
            f"📊 Прогресс: {self.stats['total_parsed']} обработано | "
            f"{self.stats['inserted']} вставлено | "
            f"{self.stats['errors']} ошибок"
        )
    
    def _log_final_stats(self, parser_stats: Dict):
        """Логирование финальной статистики"""
        logger.info("=" * 80)
        logger.info("📊 ФИНАЛЬНАЯ СТАТИСТИКА ИМПОРТА")
        logger.info("=" * 80)
        logger.info(f"Всего обработано парсером: {parser_stats['total_processed']}")
        logger.info(f"Успешно распарсено: {parser_stats['successful']}")
        logger.info(f"Ошибок парсинга: {parser_stats['errors']}")
        logger.info(f"С CVSS 3.0: {parser_stats['with_cvss3']}")
        logger.info(f"С CVSS 2.0: {parser_stats['with_cvss2']}")
        logger.info(f"С CVE ID: {parser_stats['with_cve']}")
        logger.info(f"С эксплоитами: {parser_stats['with_exploit']}")
        logger.info("-" * 80)
        logger.info(f"Записей вставлено/обновлено в БД: {self.stats['inserted']}")
        logger.info(f"Ошибок записи: {self.stats['errors']}")
        logger.info("=" * 80)


def get_db_config_from_env() -> Dict[str, str]:
    """Получить конфигурацию БД из переменных окружения"""
    return {
        'host': os.getenv('DB_HOST', '10.0.88.11'),
        'port': os.getenv('DB_PORT', '5432'),
        'database': os.getenv('DB_NAME', 'vuln_db'),
        'user': os.getenv('DB_USER', 'vuln_user'),
        'password': os.getenv('DB_PASSWORD', ''),
    }


def main():
    parser = argparse.ArgumentParser(
        description='Импортер данных БДУ ФСТЭК в PostgreSQL'
    )
    parser.add_argument(
        '--xml-file',
        required=True,
        help='Путь к файлу vulxml.xml'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='Размер пакета для batch insert (по умолчанию: 1000)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Режим тестирования без записи в БД'
    )
    parser.add_argument(
        '--db-host',
        help='Хост БД (по умолчанию: из переменной окружения DB_HOST или 10.0.88.11)'
    )
    parser.add_argument(
        '--db-port',
        help='Порт БД (по умолчанию: 5432)'
    )
    parser.add_argument(
        '--db-name',
        help='Название БД (по умолчанию: vuln_db)'
    )
    parser.add_argument(
        '--db-user',
        help='Пользователь БД'
    )
    parser.add_argument(
        '--db-password',
        help='Пароль БД'
    )
    
    args = parser.parse_args()
    
    # Конфигурация БД
    db_config = get_db_config_from_env()
    
    # Переопределение из аргументов
    if args.db_host:
        db_config['host'] = args.db_host
    if args.db_port:
        db_config['port'] = args.db_port
    if args.db_name:
        db_config['database'] = args.db_name
    if args.db_user:
        db_config['user'] = args.db_user
    if args.db_password:
        db_config['password'] = args.db_password
    
    # Создание импортера
    importer = BDUImporter(
        db_config=db_config,
        batch_size=args.batch_size,
        dry_run=args.dry_run
    )
    
    # Запуск импорта
    try:
        importer.import_from_xml(args.xml_file)
    except KeyboardInterrupt:
        logger.warning("\n⚠️ Импорт прерван пользователем")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Критическая ошибка: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

