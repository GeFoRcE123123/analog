# БДУ ФСТЭК - Полное руководство по реализации

## 📋 Общий обзор

Данный документ описывает **все необходимые изменения** для полной интеграции БДУ ФСТЭК в систему Vulnerability Manager.

## ✅ Выполнено

1. ✅ **Миграция БД** - добавлено 30+ полей БДУ
2. ✅ **Модели данных** - обновлен `entities.py` с БДУ полями
3. ✅ **XML парсер** - создан `bdu_xml_parser.py`
4. ✅ **Импортер** - создан `bdu_importer.py`
5. ✅ **Документация** - создана полная документация

## 🚧 В процессе реализации

### 1. API Endpoints (app.py)

#### Новые endpoints для БДУ:

```python
# ============================================
# БДУ ФСТЭК API ENDPOINTS
# ============================================

@app.route('/api/bdu/vendors', methods=['GET'])
@login_required
def get_bdu_vendors():
    """
    Получить список всех вендоров из БДУ
    
    Query params:
        - search: строка поиска
        - limit: макс. количество (default: 100)
    
    Returns:
        JSON: [{"vendor": "Microsoft Corp", "count": 1234}, ...]
    """
    search = request.args.get('search', '')
    limit = int(request.args.get('limit', 100))
    
    query = """
    SELECT vendor, COUNT(*) as count
    FROM vulnerabilities
    WHERE vendor IS NOT NULL AND vendor != ''
    """
    
    if search:
        query += f" AND vendor ILIKE %s"
        params = (f'%{search}%',)
    else:
        params = ()
    
    query += """
    GROUP BY vendor
    ORDER BY count DESC
    LIMIT %s
    """
    params += (limit,)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        results = [{"vendor": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    return jsonify(results)


@app.route('/api/bdu/products', methods=['GET'])
@login_required
def get_bdu_products():
    """
    Получить список продуктов из БДУ
    
    Query params:
        - vendor: фильтр по вендору
        - search: строка поиска
        - limit: макс. количество (default: 100)
    """
    vendor = request.args.get('vendor')
    search = request.args.get('search', '')
    limit = int(request.args.get('limit', 100))
    
    query = """
    SELECT vendor, product_name, COUNT(*) as count
    FROM vulnerabilities
    WHERE product_name IS NOT NULL AND product_name != ''
    """
    params = []
    
    if vendor:
        query += " AND vendor = %s"
        params.append(vendor)
    
    if search:
        query += " AND product_name ILIKE %s"
        params.append(f'%{search}%')
    
    query += """
    GROUP BY vendor, product_name
    ORDER BY count DESC
    LIMIT %s
    """
    params.append(limit)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        results = [{
            "vendor": row[0],
            "product_name": row[1],
            "count": row[2]
        } for row in cursor.fetchall()]
    
    return jsonify(results)


@app.route('/api/bdu/vulnerabilities/exploits', methods=['GET'])
@login_required
def get_bdu_vulnerabilities_with_exploits():
    """
    Получить уязвимости БДУ с эксплоитами
    
    Query params:
        - vendor: фильтр по вендору
        - severity: фильтр по severity (critical, high, medium, low)
        - limit: макс. количество (default: 50)
        - offset: смещение для пагинации (default: 0)
    """
    vendor = request.args.get('vendor')
    severity = request.args.get('severity')
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))
    
    query = """
    SELECT 
        id, bdu_id, cve_id, title, vendor, product_name,
        cvss3_score, cvss2_score, severity, exploit_status,
        publication_date, last_upd_date
    FROM vulnerabilities
    WHERE exploit_status LIKE '%Существует%'
      AND bdu_id IS NOT NULL
    """
    params = []
    
    if vendor:
        query += " AND vendor = %s"
        params.append(vendor)
    
    if severity:
        query += " AND severity = %s"
        params.append(severity)
    
    query += """
    ORDER BY COALESCE(cvss3_score, cvss2_score, 0) DESC
    LIMIT %s OFFSET %s
    """
    params.extend([limit, offset])
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        results = [{
            "id": row[0],
            "bdu_id": row[1],
            "cve_id": row[2],
            "title": row[3],
            "vendor": row[4],
            "product_name": row[5],
            "cvss3_score": float(row[6]) if row[6] else None,
            "cvss2_score": float(row[7]) if row[7] else None,
            "severity": row[8],
            "exploit_status": row[9],
            "publication_date": row[10].isoformat() if row[10] else None,
            "last_upd_date": row[11].isoformat() if row[11] else None,
        } for row in cursor.fetchall()]
    
    return jsonify(results)


@app.route('/api/bdu/stats', methods=['GET'])
@login_required
def get_bdu_stats():
    """
    Получить статистику по БДУ данным
    
    Returns:
        JSON: {
            "total_bdu": 82000,
            "with_cvss3": 71000,
            "with_exploits": 15000,
            "top_vendors": [...],
            "severity_distribution": {...}
        }
    """
    query = """
    SELECT 
        COUNT(*) as total_bdu,
        COUNT(CASE WHEN cvss3_score IS NOT NULL THEN 1 END) as with_cvss3,
        COUNT(CASE WHEN cvss2_score IS NOT NULL THEN 1 END) as with_cvss2,
        COUNT(CASE WHEN exploit_status LIKE '%Существует%' THEN 1 END) as with_exploits,
        COUNT(CASE WHEN cve_id IS NOT NULL THEN 1 END) as with_cve,
        COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
        COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count,
        COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_count,
        COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_count
    FROM vulnerabilities
    WHERE bdu_id IS NOT NULL
    """
    
    # Топ вендоров
    top_vendors_query = """
    SELECT vendor, COUNT(*) as count
    FROM vulnerabilities
    WHERE vendor IS NOT NULL AND bdu_id IS NOT NULL
    GROUP BY vendor
    ORDER BY count DESC
    LIMIT 10
    """
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Общая статистика
        cursor.execute(query)
        row = cursor.fetchone()
        stats = {
            "total_bdu": row[0],
            "with_cvss3": row[1],
            "with_cvss2": row[2],
            "with_exploits": row[3],
            "with_cve": row[4],
            "severity_distribution": {
                "critical": row[5],
                "high": row[6],
                "medium": row[7],
                "low": row[8],
            }
        }
        
        # Топ вендоров
        cursor.execute(top_vendors_query)
        stats["top_vendors"] = [{"vendor": r[0], "count": r[1]} for r in cursor.fetchall()]
    
    return jsonify(stats)


# Обновление существующего endpoint для добавления БДУ фильтров
@app.route('/api/vulnerabilities', methods=['GET'])
@login_required
def get_vulnerabilities_api():
    """
    ОБНОВЛЕННЫЙ endpoint с поддержкой БДУ фильтров
    
    Новые query params:
        - vendor: фильтр по вендору
        - product: фильтр по продукту
        - exploit_status: has_exploit/no_exploit/any
        - bdu_only: true/false - только БДУ уязвимости
        - cve_id: поиск по CVE ID
        - bdu_id: поиск по BDU ID
    """
    # ... существующий код ...
    
    # Добавить БДУ фильтры
    vendor = request.args.get('vendor')
    product = request.args.get('product')
    exploit_filter = request.args.get('exploit_status')
    bdu_only = request.args.get('bdu_only', 'false').lower() == 'true'
    cve_id = request.args.get('cve_id')
    bdu_id = request.args.get('bdu_id')
    
    if bdu_only:
        query += " AND bdu_id IS NOT NULL"
    
    if vendor:
        query += " AND vendor = %s"
        params.append(vendor)
    
    if product:
        query += " AND product_name = %s"
        params.append(product)
    
    if exploit_filter == 'has_exploit':
        query += " AND exploit_status LIKE '%Существует%'"
    elif exploit_filter == 'no_exploit':
        query += " AND (exploit_status NOT LIKE '%Существует%' OR exploit_status IS NULL)"
    
    if cve_id:
        query += " AND cve_id = %s"
        params.append(cve_id)
    
    if bdu_id:
        query += " AND bdu_id = %s"
        params.append(bdu_id)
    
    # ... остальной код ...
```

#### Обновление endpoint деталей уязвимости:

```python
@app.route('/api/vulnerabilities/<int:vuln_id>', methods=['GET'])
@login_required
def get_vulnerability_details(vuln_id):
    """
    ОБНОВЛЕН: Добавить БДУ поля в ответ
    """
    query = """
    SELECT 
        id, title, description, severity, status,
        assigned_operator, created_date, completed_date,
        approved, modifications, cvss_score, risk_level, category,
        -- NVD поля
        cve_id, source_identifier, published, last_modified, vuln_status,
        -- БДУ поля
        bdu_id, bdu_name, vendor, product_name, affected_versions,
        platform, software_types, registry_number, vulnerable_software,
        environment, cwes, vul_class, sl_oper_procs,
        identify_date, publication_date, last_upd_date,
        cvss2_vector, cvss2_score, cvss3_vector, cvss3_score, bdu_severity,
        vul_status, exploit_status, fix_status, solution, sources,
        other_identifiers, vul_incident, vul_state, vul_elimination
    FROM vulnerabilities
    WHERE id = %s
    """
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (vuln_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({"error": "Vulnerability not found"}), 404
        
        # Формирование ответа с БДУ данными
        result = {
            "id": row[0],
            "title": row[1],
            "description": row[2],
            # ... базовые поля ...
            
            # БДУ данные
            "bdu": {
                "bdu_id": row[18],
                "bdu_name": row[19],
                "vendor": row[20],
                "product_name": row[21],
                "affected_versions": row[22],
                "platform": row[23],
                "software_types": json.loads(row[24]) if row[24] else [],
                "vulnerable_software": json.loads(row[26]) if row[26] else [],
                "environment": json.loads(row[27]) if row[27] else [],
                "cwes": json.loads(row[28]) if row[28] else [],
                "vul_class": row[29],
                "dates": {
                    "identify_date": row[31].isoformat() if row[31] else None,
                    "publication_date": row[32].isoformat() if row[32] else None,
                    "last_upd_date": row[33].isoformat() if row[33] else None,
                },
                "cvss": {
                    "cvss2": {
                        "vector": row[34],
                        "score": float(row[35]) if row[35] else None,
                    },
                    "cvss3": {
                        "vector": row[36],
                        "score": float(row[37]) if row[37] else None,
                    },
                    "severity_text": row[38],
                },
                "status": {
                    "vul_status": row[39],
                    "exploit_status": row[40],
                    "fix_status": row[41],
                },
                "remediation": {
                    "solution": row[42],
                    "vul_elimination": row[48],
                },
                "references": {
                    "sources": row[43],
                    "other_identifiers": json.loads(row[44]) if row[44] else [],
                },
                "incident_info": row[45],
                "state": row[47],
            }
        }
    
    return jsonify(result)
```

### 2. VulnerabilityService обновления

Создать файл `services/bdu_service.py`:

```python
class BDUService:
    """Сервис для работы с БДУ данными"""
    
    def get_vulnerabilities_by_vendor(self, vendor: str, limit: int = 50):
        """Получить уязвимости по вендору"""
        pass
    
    def get_vulnerabilities_with_exploits(self, filters: dict):
        """Получить уязвимости с эксплоитами"""
        pass
    
    def search_by_product(self, product_name: str, vendor: str = None):
        """Поиск по названию продукта"""
        pass
    
    def get_bdu_statistics(self):
        """Статистика БДУ"""
        pass
```

### 3. Frontend обновления

#### 3.1. Обновление модального окна (`vulnerabilities_list.html`)

Добавить БДУ блок после секции "Additional Info":

```html
<!-- БДУ ФСТЭК Passport (accordion) -->
<div v-if="currentVuln.bdu && currentVuln.bdu.bdu_id" 
     class="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl border border-blue-200 mt-4">
    <button @click="toggleSection('bdu')" 
            class="w-full px-6 py-4 flex items-center justify-between hover:bg-blue-100 transition-colors rounded-xl">
        <div class="flex items-center space-x-3">
            <div class="bg-blue-500 p-2 rounded-lg">
                <i class="fas fa-shield-alt text-white"></i>
            </div>
            <div class="text-left">
                <h4 class="font-semibold text-gray-900">БДУ ФСТЭК Паспорт</h4>
                <p class="text-sm text-gray-600">{{ currentVuln.bdu.bdu_id }}</p>
            </div>
        </div>
        <i class="fas" :class="expandedSections.bdu ? 'fa-chevron-up' : 'fa-chevron-down'"></i>
    </button>
    
    <div v-show="expandedSections.bdu" class="px-6 pb-6">
        <!-- Основная информация БДУ -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <!-- Вендор и продукт -->
            <div class="bg-white rounded-lg p-4 border border-gray-200">
                <h5 class="font-semibold text-gray-700 mb-2 flex items-center">
                    <i class="fas fa-building text-blue-500 mr-2"></i>
                    Информация о ПО
                </h5>
                <div class="space-y-2 text-sm">
                    <div v-if="currentVuln.bdu.vendor">
                        <span class="text-gray-600">Вендор:</span>
                        <span class="font-medium">{{ currentVuln.bdu.vendor }}</span>
                    </div>
                    <div v-if="currentVuln.bdu.product_name">
                        <span class="text-gray-600">Продукт:</span>
                        <span class="font-medium">{{ currentVuln.bdu.product_name }}</span>
                    </div>
                    <div v-if="currentVuln.bdu.affected_versions">
                        <span class="text-gray-600">Версии:</span>
                        <span class="font-medium">{{ currentVuln.bdu.affected_versions }}</span>
                    </div>
                    <div v-if="currentVuln.bdu.platform">
                        <span class="text-gray-600">Платформа:</span>
                        <span class="font-medium">{{ currentVuln.bdu.platform }}</span>
                    </div>
                </div>
            </div>
            
            <!-- Статусы -->
            <div class="bg-white rounded-lg p-4 border border-gray-200">
                <h5 class="font-semibold text-gray-700 mb-2 flex items-center">
                    <i class="fas fa-info-circle text-green-500 mr-2"></i>
                    Статусы
                </h5>
                <div class="space-y-2 text-sm">
                    <div v-if="currentVuln.bdu.status.vul_status">
                        <span class="text-gray-600">Статус уязвимости:</span>
                        <span class="font-medium">{{ currentVuln.bdu.status.vul_status }}</span>
                    </div>
                    <div v-if="currentVuln.bdu.status.exploit_status">
                        <span class="text-gray-600">Эксплоит:</span>
                        <span class="font-medium" :class="currentVuln.bdu.status.exploit_status.includes('Существует') ? 'text-red-600' : 'text-green-600'">
                            {{ currentVuln.bdu.status.exploit_status }}
                        </span>
                    </div>
                    <div v-if="currentVuln.bdu.status.fix_status">
                        <span class="text-gray-600">Устранение:</span>
                        <span class="font-medium">{{ currentVuln.bdu.status.fix_status }}</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- CVSS БДУ -->
        <div v-if="currentVuln.bdu.cvss" class="bg-white rounded-lg p-4 border border-gray-200 mb-4">
            <h5 class="font-semibold text-gray-700 mb-2">CVSS Оценки БДУ</h5>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div v-if="currentVuln.bdu.cvss.cvss3.score">
                    <span class="text-sm text-gray-600">CVSS 3.0:</span>
                    <div class="flex items-center space-x-2">
                        <span class="text-2xl font-bold" :class="getCvssColorClass(currentVuln.bdu.cvss.cvss3.score)">
                            {{ currentVuln.bdu.cvss.cvss3.score }}
                        </span>
                        <span class="text-xs text-gray-500">{{ currentVuln.bdu.cvss.cvss3.vector }}</span>
                    </div>
                </div>
                <div v-if="currentVuln.bdu.cvss.cvss2.score">
                    <span class="text-sm text-gray-600">CVSS 2.0:</span>
                    <div class="flex items-center space-x-2">
                        <span class="text-2xl font-bold" :class="getCvssColorClass(currentVuln.bdu.cvss.cvss2.score)">
                            {{ currentVuln.bdu.cvss.cvss2.score }}
                        </span>
                        <span class="text-xs text-gray-500">{{ currentVuln.bdu.cvss.cvss2.vector }}</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Решение -->
        <div v-if="currentVuln.bdu.remediation.solution" 
             class="bg-green-50 rounded-lg p-4 border border-green-200">
            <h5 class="font-semibold text-gray-700 mb-2 flex items-center">
                <i class="fas fa-wrench text-green-500 mr-2"></i>
                Способ устранения
            </h5>
            <p class="text-sm text-gray-700 whitespace-pre-wrap">{{ currentVuln.bdu.remediation.solution }}</p>
        </div>
        
        <!-- CWE -->
        <div v-if="currentVuln.bdu.cwes && currentVuln.bdu.cwes.length > 0" 
             class="mt-4">
            <h5 class="font-semibold text-gray-700 mb-2">CWE Классификация</h5>
            <div class="flex flex-wrap gap-2">
                <span v-for="cwe in currentVuln.bdu.cwes" :key="cwe.identifier"
                      class="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-xs">
                    {{ cwe.identifier }}: {{ cwe.name }}
                </span>
            </div>
        </div>
    </div>
</div>
```

#### 3.2. Добавление фильтров БДУ

```html
<!-- Фильтры -->
<div class="bg-white rounded-lg shadow-sm p-4 mb-6">
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <!-- Существующие фильтры -->
        
        <!-- БДУ Вендор -->
        <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
                Вендор
            </label>
            <select v-model="filters.vendor" 
                    @change="fetchVulnerabilities" 
                    class="w-full px-3 py-2 border border-gray-300 rounded-lg">
                <option value="">Все вендоры</option>
                <option v-for="vendor in vendors" :key="vendor.vendor" :value="vendor.vendor">
                    {{ vendor.vendor }} ({{ vendor.count }})
                </option>
            </select>
        </div>
        
        <!-- Эксплоит -->
        <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
                Наличие эксплоита
            </label>
            <select v-model="filters.exploit_status" 
                    @change="fetchVulnerabilities"
                    class="w-full px-3 py-2 border border-gray-300 rounded-lg">
                <option value="any">Любой</option>
                <option value="has_exploit">Есть эксплоит</option>
                <option value="no_exploit">Нет эксплоита</option>
            </select>
        </div>
        
        <!-- Только БДУ -->
        <div class="flex items-end">
            <label class="flex items-center">
                <input type="checkbox" 
                       v-model="filters.bdu_only" 
                       @change="fetchVulnerabilities"
                       class="mr-2">
                <span class="text-sm text-gray-700">Только БДУ ФСТЭК</span>
            </label>
        </div>
    </div>
</div>
```

#### 3.3. JavaScript обновления

```javascript
// Добавить в data()
data() {
    return {
        // ... существующие поля ...
        vendors: [],
        filters: {
            // ... существующие фильтры ...
            vendor: '',
            exploit_status: 'any',
            bdu_only: false,
        },
        expandedSections: {
            // ... существующие секции ...
            bdu: false,
        }
    }
},

// Добавить методы
methods: {
    // ... существующие методы ...
    
    async loadVendors() {
        try {
            const response = await fetch('/api/bdu/vendors?limit=100');
            this.vendors = await response.json();
        } catch (error) {
            console.error('Error loading vendors:', error);
        }
    },
    
    getCvssColorClass(score) {
        if (score >= 9.0) return 'text-red-600';
        if (score >= 7.0) return 'text-orange-600';
        if (score >= 4.0) return 'text-yellow-600';
        return 'text-green-600';
    },
    
    // Обновить fetchVulnerabilities для включения БДУ фильтров
    async fetchVulnerabilities() {
        const params = new URLSearchParams({
            page: this.currentPage,
            per_page: this.perPage,
            // ... существующие параметры ...
            vendor: this.filters.vendor,
            exploit_status: this.filters.exploit_status,
            bdu_only: this.filters.bdu_only,
        });
        
        // ... остальной код ...
    }
},

mounted() {
    // ... существующий код ...
    this.loadVendors();
}
```

## 📊 Приоритеты реализации

1. **Высокий приоритет:**
   - ✅ Миграция БД (выполнено)
   - ✅ Парсер и импортер (выполнено)
   - 🔄 API endpoints для БДУ данных
   - 🔄 Frontend отображение БДУ полей

2. **Средний приоритет:**
   - Фильтры по вендору/эксплоитам
   - BDU Service методы
   - Статистика БДУ на dashboard

3. **Низкий приоритет:**
   - Экспорт БДУ в Excel
   - Advanced поиск по БДУ полям
   - Графики и визуализация БДУ статистики

## 🚀 Запуск после реализации

```bash
# 1. Применить миграцию
psql -h 10.0.88.11 -U vuln_user -d vuln_db -f scripts/migration/add_bdu_fields_v2.sql

# 2. Импортировать БДУ данные
python services/parsers/bdu_importer.py --xml-file temp_bdu/export/vulxml.xml

# 3. Перезапустить сервер
systemctl restart vuln_manager

# 4. Проверить в браузере
open http://10.0.88.10/vulnerabilities
```

## 📝 Чеклист реализации

- [x] Миграция БД
- [x] Модели данных
- [x] XML парсер
- [x] Импортер
- [ ] API endpoints (5 новых + обновление 2 существующих)
- [ ] BDU Service
- [ ] Frontend модальное окно
- [ ] Frontend фильтры
- [ ] Тестирование
- [ ] Документация API

## 🔗 Ссылки

- Миграция: `scripts/migration/add_bdu_fields_v2.sql`
- Парсер: `services/parsers/bdu_xml_parser.py`
- Импортер: `services/parsers/bdu_importer.py`
- Модели: `models/entities.py`
- Документация: `docs/bdu/`

---

**Статус:** В процессе реализации (60% готово)  
**Дата последнего обновления:** 2026-01-22

