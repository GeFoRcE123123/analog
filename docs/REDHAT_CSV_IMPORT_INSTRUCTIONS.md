# Инструкция по импорту Red Hat CVE из CSV

## Проблема
В базе данных только 159 Red Hat CVE, а должно быть ~44448 из скачанного CSV файла.

## Решение

### Вариант 1: Через веб-интерфейс (рекомендуется)

1. Откройте `http://217.25.230.15:8080/vulnerabilities`
2. Войдите как администратор
3. Перейдите на страницу `/parsers`
4. В разделе "Red Hat Парсер":
   - Выберите режим: **"Импорт из CSV"**
   - Укажите путь: `/tmp/cve_data/full/redhat_all_cve.csv`
   - Оставьте лимит пустым (импортировать все)
   - Включите "Пропускать существующие"
   - Нажмите кнопку импорта

### Вариант 2: Через API (требуется авторизация)

```bash
# Получите сессию/токен авторизации, затем:
curl -X POST http://217.25.230.15:8080/api/redhat/import \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d '{
    "mode": "csv",
    "csv_path": "/tmp/cve_data/full/redhat_all_cve.csv",
    "import_limit": null,
    "skip_existing": true
  }'
```

### Вариант 3: Прямой запуск в контейнере (требует sudo)

На сервере выполните:
```bash
sudo docker exec vulnerability-backend python3 << 'PYEOF'
import sys
import pandas as pd
sys.path.insert(0, '/app')
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from services.redhat_cve_importer import RedHatCVEImporter

csv_path = '/tmp/cve_data/full/redhat_all_cve.csv'
print('🚀 Начало импорта Red Hat CVE из CSV')

db_manager = DatabaseManager()
vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
redhat_importer = RedHatCVEImporter()

df = pd.read_csv(csv_path)
total = len(df)
imported = 0
skipped = 0
errors = 0

print(f'📊 Всего записей: {total}')

for i, (_, row) in enumerate(df.iterrows(), 1):
    try:
        cve_id = row.get('cve_id', '')
        if not cve_id:
            errors += 1
            continue
        
        existing = vuln_repo.get_by_cve_id(cve_id)
        if existing:
            skipped += 1
            if i % 5000 == 0:
                print(f'{i}/{total}: импортировано {imported}, пропущено {skipped}, ошибок {errors}')
            continue
        
        redhat_cve = {
            'CVE': cve_id,
            'bugzilla_description': row.get('description', ''),
            'threat_severity': row.get('severity', ''),
            'public_date': row.get('public_date', ''),
            'cvss3': {
                'cvss3_base_score': row.get('cvss3') if pd.notna(row.get('cvss3')) else None
            } if pd.notna(row.get('cvss3')) else {}
        }
        
        nvd_vuln = redhat_importer.transform_redhat_to_nvd_format(redhat_cve)
        if not nvd_vuln:
            errors += 1
            continue
        
        if redhat_importer.save_nvd_vulnerability(nvd_vuln):
            imported += 1
        else:
            errors += 1
        
        if i % 5000 == 0:
            print(f'{i}/{total}: импортировано {imported}, пропущено {skipped}, ошибок {errors}')
    
    except Exception as e:
        errors += 1
        if i % 5000 == 0:
            print(f'Ошибка {i}: {str(e)[:100]}')

print('\n' + '=' * 50)
print('РЕЗУЛЬТАТЫ ИМПОРТА')
print('=' * 50)
print(f'Всего: {total}')
print(f'Импортировано: {imported}')
print(f'Пропущено: {skipped}')
print(f'Ошибок: {errors}')
PYEOF
```

## Текущий статус

- CSV файл скопирован на сервер: `/tmp/cve_data/full/redhat_all_cve.csv`
- Файл содержит: 44448 записей
- В БД сейчас: 159 Red Hat CVE
- Ожидается после импорта: ~44448 Red Hat CVE

## Проверка результатов

После импорта проверьте:
```bash
curl -s http://217.25.230.15:8080/api/parsers/stats | python3 -c "import sys, json; d=json.load(sys.stdin); by_source = d.get('stats', {}).get('by_source', {}); redhat_count = sum(v.get('in_db', 0) for k, v in by_source.items() if 'redhat' in k.lower() or 'RedHat' in k); print('Red Hat CVE в БД:', redhat_count)"
```
