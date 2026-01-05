# 📁 СТРУКТУРА ПРОЕКТА

## 🎯 Корень проекта (главные файлы)

```
vulnerability_manager/
├── config.py              # ⚙️ Конфигурация проекта
├── requirements.txt        # 📦 Зависимости Python
├── README.md              # 📖 Главный README
├── .gitignore             # 🚫 Git ignore
└── .python-version        # 🐍 Версия Python
```

## 📁 Основные папки

### 📚 `docs/` - Документация
- `analysis/` - Анализ проекта, архитектура, редизайн
- `deployment/` - Инструкции по развертыванию
- `guides/` - Руководства и гайды
- `reports/` - Отчеты о тестировании
- `sql/` - SQL скрипты и миграции
- `configs/` - Конфигурационные файлы

### 📜 `scripts/` - Скрипты
- `migration/` - Скрипты миграции БД
- `monitoring/` - Скрипты мониторинга
- `utils/` - Вспомогательные Python скрипты
- Основные скрипты развертывания (deploy.sh и т.д.)

### 🔧 `services/` - Основной код
- `backend/` - Backend сервис (Flask API)
- `frontend/` - Frontend сервис (Nginx + статика)
- `parsers/` - Парсеры уязвимостей
- `legacy_parsers/` - Legacy парсеры
- Другие сервисы

### 📄 `templates/` - HTML шаблоны
- Jinja2 шаблоны для рендеринга страниц

### 🗄️ `models/` - Модели данных
- Репозитории, сущности, database manager

### 🧪 `tests/` - Тесты
- Unit, integration, regression тесты

### 📦 `pars/` - Исходные файлы парсеров
- Текстовые файлы с описанием парсеров
