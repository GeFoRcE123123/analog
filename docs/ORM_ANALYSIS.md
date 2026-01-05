# 🔍 Анализ ORM-прослойки в проекте Vulnerability Manager

## 📋 Итоговый вывод

**В проекте НЕ используется полноценный ORM (Object-Relational Mapping)**, но реализован **паттерн Repository** с собственными репозиториями, который выполняет роль абстракции над базой данных.

---

## 🏗️ Архитектура доступа к данным

### 1. Паттерн Repository

Проект использует паттерн Repository для абстракции доступа к данным:

```
models/
├── repositories.py              # Абстрактные интерфейсы (BaseRepository)
├── postgres_repositories.py     # Реализация для PostgreSQL (современная схема)
├── legacy_repositories.py       # Реализация для legacy схемы
├── database.py                  # DatabaseManager (менеджер соединений)
├── repository_factory.py        # Фабрика репозиториев
└── entities.py                  # Модели данных (dataclasses)
```

### 2. Структура абстракций

#### Абстрактные интерфейсы (`models/repositories.py`)

```python
class BaseRepository(ABC):
    """Абстрактный базовый класс для всех репозиториев"""
    @abstractmethod
    def get_by_id(self, id: int): pass
    @abstractmethod
    def get_all(self) -> List: pass
    @abstractmethod
    def add(self, entity) -> bool: pass
    @abstractmethod
    def update(self, entity) -> bool: pass
    @abstractmethod
    def delete(self, id: int) -> bool: pass

class VulnerabilityRepository(BaseRepository):
    """Интерфейс репозитория уязвимостей"""
    @abstractmethod
    def get_by_cve_id(self, cve_id: str): pass
    @abstractmethod
    def get_by_status(self, status: str): pass
    # ... другие методы
```

#### Реализации репозиториев

1. **PostgresVulnerabilityRepository** (`models/postgres_repositories.py`)
   - Работа с современной схемой БД
   - Использует `psycopg` для выполнения SQL запросов
   - Ручной маппинг объектов на SQL

2. **LegacyVulnerabilityRepository** (`models/legacy_repositories.py`)
   - Работа с legacy схемой БД (таблица `turn`)
   - Использует `psycopg` для выполнения SQL запросов
   - Ручной маппинг объектов на SQL

### 3. Модели данных (`models/entities.py`)

Используются Python `dataclasses`, а не ORM-модели:

```python
@dataclass
class Vulnerability:
    id: int
    cve_id: Optional[str]
    title: str
    description: str
    severity: str
    status: str
    cvss_score: float
    # ... другие поля
```

**Особенности:**
- ❌ Нет автоматического маппинга на таблицы БД
- ❌ Нет lazy loading
- ❌ Нет миграций через ORM
- ✅ Ручное преобразование между объектами и строками SQL
- ✅ Полный контроль над SQL запросами

---

## 🔧 Технические детали

### Используемые библиотеки

1. **psycopg** / **psycopg2**
   - Низкоуровневый драйвер PostgreSQL
   - Выполнение raw SQL запросов
   - Нет абстракции ORM

2. **Python dataclasses**
   - Используются для моделирования данных
   - Не связаны с БД автоматически
   - Требуется ручное преобразование

### Пример работы с данными

```python
# Пример из LegacyVulnerabilityRepository
def _save_to_turn(self, cursor, vulnerability: Vulnerability) -> Optional[int]:
    """Сохранение в таблицу turn"""
    # Ручное преобразование объекта в SQL
    cursor.execute("""
        INSERT INTO turn (cve, title, description, severity, ...)
        VALUES (%s, %s, %s, %s, ...)
        ON CONFLICT (cve) DO UPDATE SET ...
    """, (
        vulnerability.cve_id,
        vulnerability.title,
        vulnerability.description,
        vulnerability.severity,
        # ... ручное маппинг каждого поля
    ))
```

### DatabaseManager

```python
class DatabaseManager:
    """Менеджер базы данных для миграций и управления схемой"""
    def _connect(self):
        # Прямое соединение через psycopg
        self.connection = psycopg.connect(...)
        self.connection.autocommit = False
```

**Особенности:**
- ✅ Singleton pattern
- ✅ Управление соединениями
- ✅ Ручное управление транзакциями
- ❌ Нет session management как в SQLAlchemy

---

## 📊 Сравнение с ORM

### Что есть (Repository Pattern)

| Функция | Реализовано |
|---------|-------------|
| Абстракция доступа к данным | ✅ Паттерн Repository |
| Инкапсуляция SQL запросов | ✅ В методах репозиториев |
| Изоляция бизнес-логики от БД | ✅ Через интерфейсы |
| Поддержка разных схем БД | ✅ Legacy и Modern репозитории |
| Управление соединениями | ✅ DatabaseManager |

### Чего нет (ORM функционал)

| Функция | Отсутствует |
|---------|-------------|
| Автоматический маппинг объектов ↔ таблицы | ❌ Ручной маппинг |
| Lazy loading | ❌ Все данные загружаются сразу |
| Миграции через ORM | ❌ SQL миграции вручную |
| Query Builder | ❌ Raw SQL запросы |
| Связи между моделями | ❌ Ручное управление |
| Кэширование на уровне ORM | ❌ Нет (есть только Redis в OptimizedDatabaseManager) |

---

## 🎯 Преимущества текущего подхода

1. **Полный контроль над SQL**
   - Можно писать оптимизированные запросы
   - Нет overhead от ORM

2. **Гибкость**
   - Легко работать с legacy схемой
   - Можно использовать специфичные функции PostgreSQL

3. **Производительность**
   - Нет дополнительных слоев абстракции
   - Прямое выполнение SQL

4. **Простота**
   - Не нужно изучать ORM API
   - Понятный код для SQL разработчиков

---

## ⚠️ Недостатки текущего подхода

1. **Дублирование кода**
   - Много повторяющегося SQL кода
   - Ручной маппинг в каждом методе

2. **Риск SQL injection**
   - Нужно быть осторожным с параметрами (используется параметризация ✅)

3. **Сложность рефакторинга**
   - Изменение схемы требует изменений во многих местах

4. **Нет валидации на уровне моделей**
   - Валидация должна быть вручную

---

## 📝 Вывод

**Проект использует паттерн Repository, а не полноценный ORM.**

Это подход "Data Mapper" из паттернов Мартина Фаулера:
- Объекты данных (dataclasses) отделены от логики доступа к БД
- Репозитории выполняют роль маппера между объектами и БД
- Ручной маппинг через SQL запросы

**Рекомендации:**

1. **Если нужен полноценный ORM:**
   - Рассмотреть интеграцию SQLAlchemy
   - Это даст автоматический маппинг, миграции, query builder

2. **Если оставить текущий подход:**
   - Добавить больше абстракций (Query Builder)
   - Централизовать маппинг (Mapper classes)
   - Добавить валидацию на уровне моделей

3. **Гибридный подход:**
   - Использовать SQLAlchemy для новых частей
   - Оставить Repository для legacy кода

---

## 🔗 Связанные файлы

- `models/repositories.py` - Абстрактные интерфейсы
- `models/postgres_repositories.py` - Реализация для PostgreSQL
- `models/legacy_repositories.py` - Реализация для legacy схемы
- `models/database.py` - DatabaseManager
- `models/entities.py` - Модели данных (dataclasses)
- `models/repository_factory.py` - Фабрика репозиториев

