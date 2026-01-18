"""
Валидатор для CVE JSON 5.x формата
Основан на официальном валидаторе из cve-schema репозитория
"""
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from jsonschema import Draft7Validator, ValidationError

logger = logging.getLogger(__name__)


class CVEJSON5Validator:
    """
    Валидатор для проверки соответствия CVE JSON записей
    официальной схеме CVE Record Format 5.x
    """
    
    def __init__(self, schema_path: Optional[str] = None):
        """
        Инициализация валидатора
        
        Args:
            schema_path: Путь к файлу схемы (по умолчанию использует bundled схему)
        """
        self.logger = logging.getLogger(__name__)
        
        # Определяем путь к схеме
        if not schema_path:
            # Используем bundled схему из проекта
            base_path = Path(__file__).parent.parent.parent
            schema_path = base_path / "schema" / "cve_json5" / "schemas" / "CVE_Record_Format_bundled.json"
        
        self.schema_path = Path(schema_path)
        
        # Загружаем схему
        try:
            with open(self.schema_path, 'r', encoding='utf-8') as f:
                self.schema = json.load(f)
            self.validator = Draft7Validator(self.schema)
            self.logger.info(f"✅ Схема CVE JSON 5.x загружена: {self.schema_path}")
        except Exception as e:
            self.logger.error(f"❌ Ошибка загрузки схемы: {e}", exc_info=True)
            self.schema = None
            self.validator = None
    
    def validate(self, cve_record: Dict[str, Any]) -> tuple[bool, List[str]]:
        """
        Валидация CVE записи
        
        Args:
            cve_record: CVE запись в формате JSON 5.x
            
        Returns:
            Tuple (is_valid, errors_list)
        """
        if not self.validator:
            return False, ["Валидатор не инициализирован"]
        
        errors = []
        
        try:
            # Валидация
            validation_errors = list(self.validator.iter_errors(cve_record))
            
            if validation_errors:
                for error in validation_errors:
                    error_path = '.'.join(str(p) for p in error.path)
                    error_msg = f"{error_path}: {error.message}"
                    if error.context:
                        error_msg += f" (context: {error.context})"
                    errors.append(error_msg)
                
                self.logger.warning(f"⚠️ CVE запись не прошла валидацию: {len(errors)} ошибок")
                return False, errors
            else:
                self.logger.debug("✅ CVE запись прошла валидацию")
                return True, []
                
        except Exception as e:
            error_msg = f"Ошибка валидации: {str(e)}"
            self.logger.error(f"❌ {error_msg}", exc_info=True)
            return False, [error_msg]
    
    def validate_file(self, file_path: str) -> tuple[bool, List[str]]:
        """
        Валидация CVE записи из файла
        
        Args:
            file_path: Путь к JSON файлу
            
        Returns:
            Tuple (is_valid, errors_list)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                cve_record = json.load(f)
            return self.validate(cve_record)
        except Exception as e:
            error_msg = f"Ошибка чтения файла {file_path}: {str(e)}"
            self.logger.error(f"❌ {error_msg}", exc_info=True)
            return False, [error_msg]
    
    def validate_batch(self, cve_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Валидация списка CVE записей
        
        Args:
            cve_records: Список CVE записей
            
        Returns:
            Dict с результатами валидации
        """
        results = {
            'total': len(cve_records),
            'valid': 0,
            'invalid': 0,
            'errors': []
        }
        
        for idx, cve_record in enumerate(cve_records):
            try:
                cve_id = cve_record.get('cveMetadata', {}).get('cveId', f'Record_{idx}')
                is_valid, errors = self.validate(cve_record)
                
                if is_valid:
                    results['valid'] += 1
                else:
                    results['invalid'] += 1
                    results['errors'].append({
                        'cve_id': cve_id,
                        'errors': errors
                    })
            except Exception as e:
                results['invalid'] += 1
                results['errors'].append({
                    'cve_id': f'Record_{idx}',
                    'errors': [f"Ошибка обработки: {str(e)}"]
                })
        
        self.logger.info(f"✅ Валидация завершена: {results['valid']}/{results['total']} валидных записей")
        return results


# Глобальный экземпляр
_cve_json5_validator_instance = None

def get_cve_json5_validator(schema_path: Optional[str] = None):
    """Получить экземпляр CVEJSON5Validator"""
    global _cve_json5_validator_instance
    if _cve_json5_validator_instance is None:
        _cve_json5_validator_instance = CVEJSON5Validator(schema_path)
    return _cve_json5_validator_instance

cve_json5_validator = get_cve_json5_validator()

