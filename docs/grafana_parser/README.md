# 🔧 Grafana Security Advisories Parser

**Парсер уязвимостей Grafana для Vulnerability Manager**

---

## 📚 Документация

### Быстрый старт
1. **[PARSING_PLAN.md](PARSING_PLAN.md)** ⭐ **НАЧНИТЕ ЗДЕСЬ!**
   - Поэтапный план парсинга
   - Структура данных
   - Примеры запросов

2. **[DATA_MAPPING.md](DATA_MAPPING.md)**
   - Маппинг полей Grafana → БД
   - Сравнение с БДУ ФСТЭК
   - Особенности интеграции

3. **[IMPLEMENTATION.md](IMPLEMENTATION.md)**
   - Код парсера
   - API endpoints
   - Тесты

---

## 🎯 Цель

Автоматический парсинг уязвимостей с сайта Grafana Security Advisories и интеграция в существующую систему управления уязвимостями.

**Источник:** https://grafana.com/security/security-advisories/

---

## 📊 Что парсим

### Список уязвимостей (таблица)
- CVE ID
- Severity (CVSS score)
- Product name
- Advisory title
- Update date

### Детальная страница каждой CVE
- Advisory ID (CVE)
- Published date
- Product
- CVSS Score
- CVSS Vector
- Fixed Versions
- Summary (полное описание)
- Vulnerability details
- Remediation info
- Credits (кто нашел)

---

## 🔄 Интеграция с БДУ

Система уже поддерживает БДУ ФСТЭК структуру. Grafana данные будут:
- Маппиться на существующие поля
- Заполнять vendor = "Grafana Labs"
- Дополнять NVD данные для Grafana CVE

---

## 📁 Структура папки

```
docs/grafana_parser/
├── README.md                 # Этот файл
├── PARSING_PLAN.md          # Детальный план парсинга
├── DATA_MAPPING.md          # Маппинг полей
├── IMPLEMENTATION.md        # Реализация
└── examples/
    ├── list_response.html   # Пример страницы списка
    └── detail_response.html # Пример детальной страницы
```

---

## 🚀 Следующие шаги

1. Изучить [PARSING_PLAN.md](PARSING_PLAN.md)
2. Реализовать парсер по [IMPLEMENTATION.md](IMPLEMENTATION.md)
3. Протестировать на примерах
4. Интегрировать в систему

---

**Дата создания:** 22 января 2026  
**Версия:** 1.0  
**Статус:** 📝 В разработке

