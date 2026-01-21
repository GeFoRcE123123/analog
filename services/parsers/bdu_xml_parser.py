#!/usr/bin/env python3
"""
БДУ ФСТЭК XML Parser
====================

Парсер для обработки XML файла с данными БДУ ФСТЭК (vulxml.xml)

Источник: https://bdu.fstec.ru/files/documents/vulxml.zip

Автор: Vulnerability Manager System
Дата: 2026-01-22
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Generator
from datetime import datetime, date
from decimal import Decimal
import re
import logging
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BDUXMLParser:
    """
    Парсер XML файла БДУ ФСТЭК
    
    Поддерживает:
    - Streaming парсинг больших файлов (500+ MB)
    - Извлечение всех полей из БДУ паспорта
    - Нормализацию данных для БД
    """
    
    def __init__(self, xml_file_path: str):
        """
        Args:
            xml_file_path: Путь к файлу vulxml.xml
        """
        self.xml_file_path = Path(xml_file_path)
        if not self.xml_file_path.exists():
            raise FileNotFoundError(f"XML файл не найден: {xml_file_path}")
        
        self.stats = {
            'total_processed': 0,
            'successful': 0,
            'errors': 0,
            'with_cvss3': 0,
            'with_cvss2': 0,
            'with_cve': 0,
            'with_exploit': 0,
        }
    
    def parse_stream(self) -> Generator[Dict, None, None]:
        """
        Streaming парсинг XML файла (для больших файлов)
        
        Yields:
            Dict с данными одной уязвимости
        """
        logger.info(f"Начало парсинга: {self.xml_file_path}")
        
        context = ET.iterparse(self.xml_file_path, events=('start', 'end'))
        context = iter(context)
        event, root = next(context)
        
        for event, elem in context:
            if event == 'end' and elem.tag == 'vul':
                try:
                    vuln_data = self._parse_vulnerability_element(elem)
                    if vuln_data:
                        self.stats['successful'] += 1
                        yield vuln_data
                    
                    self.stats['total_processed'] += 1
                    
                    # Логирование прогресса
                    if self.stats['total_processed'] % 1000 == 0:
                        logger.info(f"Обработано {self.stats['total_processed']} уязвимостей")
                    
                except Exception as e:
                    self.stats['errors'] += 1
                    logger.error(f"Ошибка парсинга уязвимости: {e}")
                
                # Очистка памяти
                elem.clear()
                root.clear()
        
        logger.info(f"Парсинг завершен. Статистика: {self.stats}")
    
    def _parse_vulnerability_element(self, elem: ET.Element) -> Optional[Dict]:
        """
        Парсинг одного элемента <vul>
        
        Args:
            elem: XML элемент <vul>
        
        Returns:
            Dict с данными уязвимости
        """
        vuln = {}
        
        # 1. ИДЕНТИФИКАЦИЯ
        vuln['bdu_id'] = self._get_text(elem, 'identifier')
        vuln['bdu_name'] = self._get_text(elem, 'name')
        vuln['description'] = self._get_text(elem, 'description')
        
        if not vuln['bdu_id']:
            return None  # Пропускаем записи без ID
        
        # 2. ИНФОРМАЦИЯ О ПО (Vulnerable Software)
        vuln['vulnerable_software'] = self._parse_vulnerable_software(elem)
        
        # Извлекаем основные поля из первого ПО
        if vuln['vulnerable_software']:
            first_soft = vuln['vulnerable_software'][0]
            vuln['vendor'] = first_soft.get('vendor')
            vuln['product_name'] = first_soft.get('name')
            vuln['affected_versions'] = first_soft.get('version')
            vuln['platform'] = first_soft.get('platform')
            vuln['software_types'] = first_soft.get('types', [])
            vuln['registry_number'] = first_soft.get('registry_number')
        
        # 3. ОКРУЖЕНИЕ (Environment)
        vuln['environment'] = self._parse_environment(elem)
        
        # 4. ТЕХНИЧЕСКИЕ ДЕТАЛИ
        vuln['cwes'] = self._parse_cwes(elem)
        vuln['vul_class'] = self._get_text(elem, 'vul_class')
        vuln['sl_oper_procs'] = self._parse_sl_oper_procs(elem)
        
        # 5. ДАТЫ
        vuln['identify_date'] = self._parse_date(self._get_text(elem, 'identify_date'))
        vuln['publication_date'] = self._parse_date(self._get_text(elem, 'publication_date'))
        vuln['last_upd_date'] = self._parse_date(self._get_text(elem, 'last_upd_date'))
        
        # 6. ОЦЕНКА РИСКОВ
        cvss_elem = elem.find('cvss')
        if cvss_elem is not None:
            vuln['cvss2_score'] = self._parse_decimal(cvss_elem.get('score'))
            vuln['cvss2_vector'] = cvss_elem.text.strip() if cvss_elem.text else None
            if vuln['cvss2_score']:
                self.stats['with_cvss2'] += 1
        
        cvss3_elem = elem.find('cvss3')
        if cvss3_elem is not None:
            vuln['cvss3_score'] = self._parse_decimal(cvss3_elem.get('score'))
            vuln['cvss3_vector'] = cvss3_elem.text.strip() if cvss3_elem.text else None
            if vuln['cvss3_score']:
                self.stats['with_cvss3'] += 1
        
        vuln['bdu_severity'] = self._get_text(elem, 'severity')
        
        # 7. СТАТУСЫ И УСТРАНЕНИЕ
        vuln['vul_status'] = self._get_text(elem, 'vul_status')
        vuln['exploit_status'] = self._get_text(elem, 'exploit_status')
        vuln['fix_status'] = self._get_text(elem, 'fix_status')
        vuln['solution'] = self._get_text(elem, 'solution')
        
        # Статистика эксплоитов
        if vuln['exploit_status'] and 'Существует' in vuln['exploit_status']:
            self.stats['with_exploit'] += 1
        
        # 8. ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ
        vuln['sources'] = self._get_text(elem, 'sources')
        vuln['other_identifiers'] = self._parse_identifiers(elem)
        vuln['vul_incident'] = self._get_text(elem, 'vul_incident')
        vuln['vul_state'] = self._get_text(elem, 'vul_state')
        vuln['vul_elimination'] = self._get_text(elem, 'vul_elimination')
        
        # Извлечение CVE ID из identifiers
        vuln['cve_id'] = self._extract_cve_id(vuln['other_identifiers'])
        if vuln['cve_id']:
            self.stats['with_cve'] += 1
        
        # 9. ДОПОЛНИТЕЛЬНЫЕ ВЫЧИСЛЯЕМЫЕ ПОЛЯ
        vuln['title'] = self._generate_title(vuln)
        vuln['severity'] = self._map_severity(vuln['bdu_severity'], vuln.get('cvss2_score'), vuln.get('cvss3_score'))
        vuln['cvss_score'] = self._get_best_cvss_score(vuln.get('cvss2_score'), vuln.get('cvss3_score'))
        
        return vuln
    
    def _parse_vulnerable_software(self, elem: ET.Element) -> List[Dict]:
        """Парсинг секции vulnerable_software"""
        software_list = []
        
        vuln_soft_elem = elem.find('vulnerable_software')
        if vuln_soft_elem is None:
            return software_list
        
        for soft_elem in vuln_soft_elem.findall('soft'):
            software = {
                'name': self._get_text(soft_elem, 'name'),
                'vendor': self._get_text(soft_elem, 'vendor'),
                'version': self._get_text(soft_elem, 'version'),
                'platform': self._get_text(soft_elem, 'platform'),
                'registry_number': self._get_text(soft_elem, 'registry_number'),
                'types': []
            }
            
            # Парсинг типов ПО
            types_elem = soft_elem.find('types')
            if types_elem is not None:
                for type_elem in types_elem.findall('type'):
                    if type_elem.text:
                        software['types'].append(type_elem.text.strip())
            
            software_list.append(software)
        
        return software_list
    
    def _parse_environment(self, elem: ET.Element) -> List[Dict]:
        """Парсинг секции environment"""
        env_list = []
        
        env_elem = elem.find('environment')
        if env_elem is None:
            return env_list
        
        for os_elem in env_elem.findall('os'):
            environment = {
                'name': self._get_text(os_elem, 'name'),
                'vendor': self._get_text(os_elem, 'vendor'),
                'version': self._get_text(os_elem, 'version'),
                'platform': self._get_text(os_elem, 'platform'),
                'registry_number': self._get_text(os_elem, 'registry_number'),
            }
            env_list.append(environment)
        
        return env_list
    
    def _parse_cwes(self, elem: ET.Element) -> List[Dict]:
        """Парсинг секции cwes"""
        cwe_list = []
        
        cwes_elem = elem.find('cwes')
        if cwes_elem is None:
            return cwe_list
        
        for cwe_elem in cwes_elem.findall('cwe'):
            cwe = {
                'identifier': self._get_text(cwe_elem, 'identifier'),
                'name': self._get_text(cwe_elem, 'name'),
            }
            cwe_list.append(cwe)
        
        return cwe_list
    
    def _parse_sl_oper_procs(self, elem: ET.Element) -> List[Dict]:
        """Парсинг секции sl_oper_procs (служебные операционные процессы)"""
        proc_list = []
        
        procs_elem = elem.find('sl_oper_procs')
        if procs_elem is None:
            return proc_list
        
        for sop_elem in procs_elem.findall('sop'):
            proc = {
                'name': self._get_text(sop_elem, 'name'),
            }
            proc_list.append(proc)
        
        return proc_list
    
    def _parse_identifiers(self, elem: ET.Element) -> List[Dict]:
        """Парсинг секции identifiers"""
        id_list = []
        
        identifiers_elem = elem.find('identifiers')
        if identifiers_elem is None:
            return id_list
        
        for id_elem in identifiers_elem.findall('identifier'):
            identifier = {
                'type': id_elem.get('type'),
                'link': id_elem.get('link'),
                'value': id_elem.text.strip() if id_elem.text else None
            }
            id_list.append(identifier)
        
        return id_list
    
    def _extract_cve_id(self, identifiers: List[Dict]) -> Optional[str]:
        """Извлечение CVE ID из списка идентификаторов"""
        for identifier in identifiers:
            if identifier.get('type') == 'CVE':
                return identifier.get('value')
        return None
    
    def _get_text(self, elem: ET.Element, tag: str) -> Optional[str]:
        """Безопасное получение текста из элемента"""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return None
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[date]:
        """Парсинг даты в формате DD.MM.YYYY"""
        if not date_str:
            return None
        
        try:
            # Формат БДУ: DD.MM.YYYY
            return datetime.strptime(date_str, '%d.%m.%Y').date()
        except ValueError:
            try:
                # Попытка альтернативного формата
                return datetime.strptime(date_str, '%Y-%m-%d').date()
            except ValueError:
                logger.warning(f"Не удалось распарсить дату: {date_str}")
                return None
    
    def _parse_decimal(self, value: Optional[str]) -> Optional[Decimal]:
        """Парсинг decimal значения"""
        if not value:
            return None
        
        try:
            return Decimal(value)
        except (ValueError, TypeError):
            logger.warning(f"Не удалось распарсить decimal: {value}")
            return None
    
    def _generate_title(self, vuln: Dict) -> str:
        """Генерация заголовка уязвимости"""
        parts = []
        
        # BDU ID
        if vuln.get('bdu_id'):
            parts.append(vuln['bdu_id'])
        
        # CVE ID
        if vuln.get('cve_id'):
            parts.append(vuln['cve_id'])
        
        # Название из БДУ (обрезаем до 200 символов)
        if vuln.get('bdu_name'):
            name = vuln['bdu_name']
            if len(name) > 200:
                name = name[:197] + '...'
            parts.append(name)
        elif vuln.get('product_name'):
            # Если нет названия, используем продукт
            parts.append(f"Уязвимость в {vuln['product_name']}")
        
        title = ' - '.join(parts) if parts else 'БДУ Уязвимость'
        return title[:500]  # Лимит БД
    
    def _map_severity(self, bdu_severity: Optional[str], cvss2: Optional[Decimal], cvss3: Optional[Decimal]) -> str:
        """Маппинг уровня опасности на стандартные значения"""
        # Приоритет CVSS score
        score = cvss3 or cvss2
        if score:
            if score >= 9.0:
                return 'critical'
            elif score >= 7.0:
                return 'high'
            elif score >= 4.0:
                return 'medium'
            else:
                return 'low'
        
        # Если нет CVSS, используем текстовое описание БДУ
        if bdu_severity:
            severity_lower = bdu_severity.lower()
            if 'критический' in severity_lower or 'крит' in severity_lower:
                return 'critical'
            elif 'высокий' in severity_lower:
                return 'high'
            elif 'средний' in severity_lower:
                return 'medium'
            elif 'низкий' in severity_lower:
                return 'low'
        
        return 'medium'  # По умолчанию
    
    def _get_best_cvss_score(self, cvss2: Optional[Decimal], cvss3: Optional[Decimal]) -> float:
        """Получить лучшую CVSS оценку (приоритет CVSS 3.0)"""
        if cvss3:
            return float(cvss3)
        elif cvss2:
            return float(cvss2)
        return 0.0
    
    def get_statistics(self) -> Dict:
        """Получить статистику парсинга"""
        return self.stats.copy()


def main():
    """Пример использования парсера"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python bdu_xml_parser.py <path_to_vulxml.xml>")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    parser = BDUXMLParser(xml_file)
    
    print("=" * 80)
    print("БДУ ФСТЭК XML Parser")
    print("=" * 80)
    print(f"\nФайл: {xml_file}\n")
    
    # Пример: обработка первых 10 записей
    count = 0
    for vuln in parser.parse_stream():
        count += 1
        print(f"\n--- Уязвимость #{count} ---")
        print(f"BDU ID: {vuln.get('bdu_id')}")
        print(f"Title: {vuln.get('title')}")
        print(f"CVE: {vuln.get('cve_id')}")
        print(f"Vendor: {vuln.get('vendor')}")
        print(f"Product: {vuln.get('product_name')}")
        print(f"CVSS 3.0: {vuln.get('cvss3_score')}")
        print(f"CVSS 2.0: {vuln.get('cvss2_score')}")
        print(f"Severity: {vuln.get('severity')}")
        print(f"Exploit: {vuln.get('exploit_status')}")
        print(f"CWEs: {len(vuln.get('cwes', []))}")
        
        if count >= 10:
            break
    
    print("\n" + "=" * 80)
    print("Статистика:")
    print("=" * 80)
    stats = parser.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")


if __name__ == '__main__':
    main()

