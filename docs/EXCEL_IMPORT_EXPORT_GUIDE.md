# 📊 Руководство по импорту и экспорту Excel

**Для разработчиков**  
**Версия:** 1.0  
**Дата:** 2025-01-18

---

## 📋 Содержание

1. [Обзор функциональности](#обзор-функциональности)
2. [Импорт из Excel](#импорт-из-excel)
3. [Экспорт в Excel](#экспорт-в-excel)
4. [Технические детали](#технические-детали)
5. [Примеры использования](#примеры-использования)
6. [Расширение функциональности](#расширение-функциональности)

---

## 🎯 Обзор функциональности

### Импорт из Excel
- Загрузка файлов Excel (.xlsx, .xls)
- Предварительный просмотр данных перед импортом
- Валидация обязательных колонок
- Пакетный импорт уязвимостей в базу данных
- Обработка ошибок с детальными сообщениями

### Экспорт в Excel
- Экспорт уязвимостей операторов
- Экспорт отчетов по производительности
- Автоматическое форматирование (заголовки, цвета, ширина колонок)
- Генерация файлов с временными метками

---

## 📥 Импорт из Excel

### Архитектура

```
Frontend (import_excel.html)
    ↓
API Endpoint: /api/excel/import/preview (предпросмотр)
API Endpoint: /api/excel/import (импорт)
    ↓
Pandas (чтение Excel)
    ↓
VulnerabilityService (сохранение в БД)
```

### API Endpoints

#### 1. Предварительный просмотр (`/api/excel/import/preview`)

**Метод:** `POST`  
**Тип контента:** `multipart/form-data`  
**Параметры:**
- `file` - файл Excel (.xlsx, .xls)

**Ответ:**
```json
{
  "success": true,
  "columns": ["title", "description", "severity", "cvss_score"],
  "row_count": 150,
  "sample_data": [
    {
      "title": "CVE-2024-0001",
      "description": "Описание уязвимости",
      "severity": "high",
      "cvss_score": 8.5
    }
  ]
}
```

**Ошибки:**
```json
{
  "success": false,
  "error": "Файл не найден"
}
```

#### 2. Импорт данных (`/api/excel/import`)

**Метод:** `POST`  
**Тип контента:** `multipart/form-data`  
**Параметры:**
- `file` - файл Excel (.xlsx, .xls)

**Обязательные колонки:**
- `title` - название уязвимости
- `description` - описание уязвимости
- `severity` - уровень серьезности (low, medium, high, critical)

**Опциональные колонки:**
- `status` - статус (по умолчанию: "new")
- `cvss_score` - CVSS оценка (по умолчанию: 0.0)
- `risk_level` - уровень риска (по умолчанию: "medium")
- `category` - категория (по умолчанию: "web")

**Ответ при успехе:**
```json
{
  "success": true,
  "imported_count": 145,
  "errors": [],
  "total_rows": 150
}
```

**Ответ при ошибке:**
```json
{
  "success": false,
  "error": "Отсутствуют обязательные колонки: title, description",
  "missing_columns": ["title", "description"],
  "available_columns": ["id", "name", "type"]
}
```

**Ответ с частичными ошибками:**
```json
{
  "success": true,
  "imported_count": 145,
  "errors": [
    "Строка 12: Ошибка добавления уязвимости",
    "Строка 45: Invalid severity value"
  ],
  "total_rows": 150
}
```

### Реализация на Backend

**Файл:** `scripts/utils/app.py` (или `app.py`)

```python
import pandas as pd
import tempfile
import os
from werkzeug.utils import secure_filename
from flask import request, jsonify
from models.entities import Vulnerability

@app.route('/api/excel/import/preview', methods=['POST'])
def preview_excel_import():
    """Предварительный просмотр Excel файла"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Файл не найден'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Файл не выбран'})
        
        # Сохранение временного файла
        temp_dir = tempfile.mkdtemp()
        filename = file.filename or 'import.xlsx'
        filepath = os.path.join(temp_dir, secure_filename(filename))
        file.save(filepath)
        
        # Чтение Excel
        df = pd.read_excel(filepath)
        
        # Подготовка данных для ответа
        columns = list(df.columns)
        row_count = len(df)
        sample_data = df.head(5).to_dict('records')
        
        # Очистка
        os.remove(filepath)
        os.rmdir(temp_dir)
        
        return jsonify({
            'success': True,
            'columns': columns,
            'row_count': row_count,
            'sample_data': sample_data
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/excel/import', methods=['POST'])
def import_excel_vulnerabilities():
    """Импорт уязвимостей из Excel"""
    try:
        required_columns = ['title', 'description', 'severity']
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Файл не найден'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Файл не выбран'})
        
        # Сохранение временного файла
        temp_dir = tempfile.mkdtemp()
        filename = file.filename or 'import.xlsx'
        filepath = os.path.join(temp_dir, secure_filename(filename))
        file.save(filepath)
        
        # Чтение Excel
        df = pd.read_excel(filepath)
        
        # Валидация колонок
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            os.remove(filepath)
            os.rmdir(temp_dir)
            return jsonify({
                'success': False,
                'error': f'Отсутствуют обязательные колонки: {", ".join(missing_columns)}',
                'missing_columns': missing_columns,
                'available_columns': list(df.columns)
            })
        
        # Импорт данных
        imported_count = 0
        errors = []
        
        for index, row in df.iterrows():
            try:
                # Парсинг CVSS score
                cvss_score_val = row.get('cvss_score')
                cvss_score = float(str(cvss_score_val)) if cvss_score_val is not None else 0.0
                
                # Создание объекта уязвимости
                vulnerability = Vulnerability(
                    id=0,
                    title=str(row['title']),
                    description=str(row['description']) if 'description' in row else '',
                    severity=str(row['severity']) if 'severity' in row else 'medium',
                    status=str(row.get('status', 'new')),
                    cvss_score=cvss_score,
                    risk_level=str(row.get('risk_level', 'medium')),
                    category=str(row.get('category', 'web'))
                )
                
                # Сохранение в БД
                if vuln_service.add_vulnerability(vulnerability):
                    imported_count += 1
                else:
                    errors.append(f"Строка {int(index) + 1}: Ошибка добавления уязвимости")
            except Exception as e:
                errors.append(f"Строка {int(index) + 1}: {str(e)}")
        
        # Очистка
        os.remove(filepath)
        os.rmdir(temp_dir)
        
        return jsonify({
            'success': True,
            'imported_count': imported_count,
            'errors': errors,
            'total_rows': len(df)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
```

### Frontend реализация

**Файл:** `templates/import_excel.html`

```javascript
// Загрузка и предпросмотр
function uploadFile() {
    const formData = new FormData();
    formData.append('file', uploadedFile);
    
    fetch('/api/excel/import/preview', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showPreview(data);
        } else {
            showError(data.error);
        }
    });
}

// Импорт данных
function importFile() {
    const formData = new FormData();
    formData.append('file', uploadedFile);
    
    fetch('/api/excel/import', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showResult(data);
        } else {
            showError(data.error);
        }
    });
}
```

---

## 📤 Экспорт в Excel

### Архитектура

```
Backend Route (/export/operator-vulnerabilities)
    ↓
ExportService.export_operator_vulnerabilities()
    ↓
ExportService.export_to_excel()
    ↓
OpenPyXL (создание Excel файла)
    ↓
Скачивание файла пользователем
```

### API Endpoints

#### 1. Экспорт всех операторов с уязвимостями

**Маршрут:** `/export/operator-vulnerabilities`  
**Метод:** `POST`  
**Доступ:** `@admin_required`

**Реализация:**
```python
@app.route('/export/operator-vulnerabilities', methods=['POST'])
@login_required
@admin_required
def export_operator_vulnerabilities():
    """Экспорт всех операторов с уязвимостями"""
    try:
        operators = operator_service.get_all_operators()
        filename = export_service.export_operator_vulnerabilities(operators)
        flash(f'Отчет экспортирован: {filename}', 'success')
    except Exception as e:
        logger.error(f"Error exporting operator vulnerabilities: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'error')
    
    return redirect(url_for('operators_page'))
```

#### 2. Экспорт уязвимостей одного оператора

**Маршрут:** `/export/operator/<int:operator_id>`  
**Метод:** `POST`  
**Доступ:** `@admin_required`

**Реализация:**
```python
@app.route('/export/operator/<int:operator_id>', methods=['POST'])
@login_required
@admin_required
def export_single_operator(operator_id):
    """Экспорт уязвимостей одного оператора"""
    try:
        operator = operator_service.get_operator_by_id(operator_id)
        if operator:
            filename = export_service.export_single_operator_vulnerabilities(operator)
            flash(f'Уязвимости оператора {operator.name} экспортированы: {filename}', 'success')
        else:
            flash('Оператор не найден', 'error')
    except Exception as e:
        logger.error(f"Error exporting single operator: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'error')
    
    return redirect(url_for('operators_page'))
```

### Реализация ExportService

**Файл:** `services/export_service.py`

```python
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from datetime import datetime
from typing import List

class ExportService:
    @staticmethod
    def export_to_excel(data, filename_prefix="report"):
        """Базовый метод экспорта данных в Excel"""
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Отчет"

        # Заголовки
        headers = list(data[0].keys()) if data else []
        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="DDDDDD", end_color="DDDDDD", fill_type="solid")
            cell.alignment = Alignment(horizontal="center")

        # Данные
        for row, item in enumerate(data, 2):
            for col, key in enumerate(headers, 1):
                ws.cell(row=row, column=col, value=item.get(key, ''))

        # Авто-ширина колонок
        for column in ws.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = (max_length + 2)
            ws.column_dimensions[column_letter].width = adjusted_width

        # Генерация имени файла
        filename = f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        wb.save(filename)
        return filename

    def export_operator_vulnerabilities(self, operators: List[Operator]) -> str:
        """Экспорт уязвимостей по каждому оператору"""
        data = []
        
        for op in operators:
            # Заголовок оператора
            data.append({
                'Оператор': f"ОПЕРАТОР: {op.name}",
                'Email': op.email,
                'Метрика': f"{op.current_metric}%",
                'Уровень опыта': f"{op.experience_level}%",
                'Нагрузка': f"{op.calculate_workload()}%",
                'Кол-во уязвимостей': len(op.assigned_vulnerabilities),
                'Статус': '',
                'CVSS': '',
                'Категория': ''
            })
            
            # Уязвимости оператора
            for vuln in op.assigned_vulnerabilities:
                data.append({
                    'Оператор': vuln.title,
                    'Email': '',
                    'Метрика': '',
                    'Уровень опыта': '',
                    'Нагрузка': '',
                    'Кол-во уязвимостей': '',
                    'Статус': vuln.status,
                    'CVSS': vuln.cvss_score,
                    'Категория': vuln.category
                })
            
            # Пустая строка между операторами
            data.append({})
        
        return self.export_to_excel(data, "отчет_операторов_уязвимостей")

    def export_single_operator_vulnerabilities(self, operator: Operator) -> str:
        """Экспорт уязвимостей для одного оператора"""
        data = []
        
        # Заголовок оператора
        data.append({
            'Оператор': operator.name,
            'Email': operator.email,
            'Текущая метрика': f"{operator.current_metric}%",
            'Уровень опыта': f"{operator.experience_level}%",
            'Нагрузка': f"{operator.calculate_workload()}%",
            'Всего уязвимостей': len(operator.assigned_vulnerabilities)
        })
        
        # Пустая строка
        data.append({})
        
        # Заголовки уязвимостей
        data.append({
            'ID уязвимости': 'ID',
            'Название уязвимости': 'Название',
            'Описание': 'Описание',
            'Уровень риска': 'Уровень риска',
            'Статус': 'Статус',
            'CVSS Score': 'CVSS',
            'Категория': 'Категория',
            'Правки': 'Правки'
        })
        
        # Данные уязвимостей
        for vuln in operator.assigned_vulnerabilities:
            data.append({
                'ID уязвимости': vuln.id,
                'Название уязвимости': vuln.title,
                'Описание': vuln.description,
                'Уровень риска': vuln.severity.upper(),
                'Статус': vuln.status,
                'CVSS Score': vuln.cvss_score,
                'Категория': vuln.category,
                'Правки': vuln.modifications
            })
        
        # Статистика по статусам
        status_counts = {}
        for vuln in operator.assigned_vulnerabilities:
            status_counts[vuln.status] = status_counts.get(vuln.status, 0) + 1
        
        data.append({})
        data.append({'ID уязвимости': 'СТАТИСТИКА:', ...})
        for status, count in status_counts.items():
            data.append({
                'ID уязвимости': f"Статус '{status}':",
                'Название уязвимости': count,
                ...
            })
        
        filename = f"уязвимости_{operator.name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return self.export_to_excel(data, filename.replace('.xlsx', ''))
```

---

## 🔧 Технические детали

### Зависимости

**requirements.txt:**
```
openpyxl==3.1.2
pandas>=1.5.0  # Для чтения Excel (если используется)
```

### Установка

```bash
pip install openpyxl==3.1.2
# или
pip install -r requirements.txt
```

### Формат Excel файла для импорта

**Обязательные колонки:**
- `title` - название уязвимости (строка)
- `description` - описание уязвимости (строка)
- `severity` - уровень серьезности (low, medium, high, critical)

**Опциональные колонки:**
- `status` - статус (new, in_progress, completed, rejected)
- `cvss_score` - CVSS оценка (число, 0.0-10.0)
- `risk_level` - уровень риска (low, medium, high, critical)
- `category` - категория (web, network, system, etc.)

**Пример Excel файла:**

| title | description | severity | cvss_score | status | risk_level | category |
|-------|-------------|----------|------------|--------|------------|----------|
| CVE-2024-0001 | SQL Injection vulnerability | high | 8.5 | new | high | web |
| CVE-2024-0002 | XSS vulnerability | medium | 6.2 | in_progress | medium | web |

---

## 💡 Примеры использования

### Пример 1: Импорт уязвимостей через API

```python
import requests

# Предварительный просмотр
with open('vulnerabilities.xlsx', 'rb') as f:
    files = {'file': f}
    response = requests.post('http://localhost:5000/api/excel/import/preview', files=files)
    print(response.json())

# Импорт
with open('vulnerabilities.xlsx', 'rb') as f:
    files = {'file': f}
    response = requests.post('http://localhost:5000/api/excel/import', files=files)
    result = response.json()
    print(f"Импортировано: {result['imported_count']} из {result['total_rows']}")
```

### Пример 2: Программный экспорт

```python
from services.export_service import ExportService
from services.operator_service import OperatorService

export_service = ExportService()
operator_service = OperatorService()

# Экспорт всех операторов
operators = operator_service.get_all_operators()
filename = export_service.export_operator_vulnerabilities(operators)
print(f"Файл создан: {filename}")

# Экспорт одного оператора
operator = operator_service.get_operator_by_id(1)
filename = export_service.export_single_operator_vulnerabilities(operator)
print(f"Файл создан: {filename}")
```

### Пример 3: Создание кастомного экспорта

```python
from services.export_service import ExportService

export_service = ExportService()

# Подготовка данных
data = [
    {
        'ID': 1,
        'Название': 'CVE-2024-0001',
        'Описание': 'Описание уязвимости',
        'CVSS': 8.5
    },
    {
        'ID': 2,
        'Название': 'CVE-2024-0002',
        'Описание': 'Другая уязвимость',
        'CVSS': 6.2
    }
]

# Экспорт
filename = export_service.export_to_excel(data, "custom_report")
print(f"Файл создан: {filename}")
```

---

## 🚀 Расширение функциональности

### Добавление новых полей в импорт

1. **Обновите валидацию:**
```python
required_columns = ['title', 'description', 'severity', 'new_field']
```

2. **Добавьте обработку в цикле импорта:**
```python
vulnerability = Vulnerability(
    ...
    new_field=str(row.get('new_field', 'default_value'))
)
```

### Добавление нового типа экспорта

1. **Создайте метод в ExportService:**
```python
def export_custom_report(self, data: List[Dict]) -> str:
    """Кастомный экспорт"""
    # Подготовка данных
    export_data = []
    for item in data:
        export_data.append({
            'Поле 1': item.field1,
            'Поле 2': item.field2,
            ...
        })
    
    return self.export_to_excel(export_data, "custom_report")
```

2. **Добавьте маршрут:**
```python
@app.route('/export/custom', methods=['POST'])
@login_required
def export_custom():
    data = get_custom_data()
    filename = export_service.export_custom_report(data)
    return send_file(filename, as_attachment=True)
```

### Улучшение форматирования Excel

```python
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

# Цветные заголовки
header_fill = PatternFill(
    start_color="4472C4",
    end_color="4472C4",
    fill_type="solid"
)
header_font = Font(bold=True, color="FFFFFF")

# Границы
thin_border = Border(
    left=Side(style='thin'),
    right=Side(style='thin'),
    top=Side(style='thin'),
    bottom=Side(style='thin')
)

# Применение
for cell in ws[1]:
    cell.fill = header_fill
    cell.font = header_font
    cell.border = thin_border
```

---

## 📝 Чеклист для разработчика

- [ ] Установлены зависимости (`openpyxl`, `pandas`)
- [ ] API endpoints добавлены в `app.py`
- [ ] `ExportService` импортирован и инициализирован
- [ ] Frontend страница `/import-excel` доступна
- [ ] Тестирование импорта с валидным файлом
- [ ] Тестирование импорта с невалидным файлом
- [ ] Тестирование экспорта операторов
- [ ] Обработка ошибок реализована

---

## 🔗 Связанные файлы

- `services/export_service.py` - сервис экспорта
- `templates/import_excel.html` - страница импорта
- `app.py` - маршруты и API endpoints
- `requirements.txt` - зависимости

---

**Статус:** ✅ Готово к использованию  
**Последнее обновление:** 2025-01-18

