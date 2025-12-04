import psycopg2
from psycopg2 import pool
import redis
import json
import logging
from typing import Optional, List, Tuple, Any
from config import Config
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class OptimizedDatabaseManager:
    """Оптимизированный менеджер базы данных с connection pooling и кэшированием"""
    
    _instance = None
    _pool = None
    _redis_client = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OptimizedDatabaseManager, cls).__new__(cls)
            cls._instance._init_pool()
            cls._instance._init_redis()
        return cls._instance
    
    def _init_pool(self):
        """Инициализация connection pool"""
        try:
            db_config = Config.DATABASE_CONFIG
            if db_config.type == "postgresql":
                self._pool = pool.ThreadedConnectionPool(
                    minconn=5,  # Минимальное количество соединений
                    maxconn=20,  # Максимальное количество соединений
                    host=db_config.host,
                    port=db_config.port,
                    database=db_config.database,
                    user=db_config.username,
                    password=db_config.password
                )
                logger.info("Database connection pool initialized")
            else:
                raise ValueError(f"Unsupported database type: {db_config.type}")
        except Exception as e:
            logger.error(f"Error initializing database pool: {e}")
            raise
    
    def _init_redis(self):
        """Инициализация Redis для кэширования"""
        try:
            # Попробуем подключиться к Redis (если установлен)
            self._redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True,
                socket_connect_timeout=5
            )
            # Проверим соединение
            self._redis_client.ping()
            logger.info("Redis cache initialized")
        except Exception as e:
            logger.warning(f"Redis not available, caching disabled: {e}")
            self._redis_client = None
    
    @contextmanager
    def get_connection(self):
        """Получить соединение из пула"""
        conn = None
        try:
            if self._pool:
                conn = self._pool.getconn()
                yield conn
        finally:
            if conn and self._pool:
                self._pool.putconn(conn)
    
    def get_cached(self, key: str) -> Optional[Any]:
        """Получить данные из кэша"""
        if not self._redis_client:
            return None
        
        try:
            cached_data = self._redis_client.get(key)
            if cached_data:
                return json.loads(str(cached_data))
        except Exception as e:
            logger.warning(f"Cache get error: {e}")
        return None
    
    def set_cached(self, key: str, data: Any, expire: int = 300) -> bool:
        """Сохранить данные в кэш"""
        if not self._redis_client:
            return False
        
        try:
            serialized_data = json.dumps(data, default=str)
            self._redis_client.setex(key, expire, serialized_data)
            return True
        except Exception as e:
            logger.warning(f"Cache set error: {e}")
            return False
    
    def invalidate_cache(self, pattern: str) -> bool:
        """Очистить кэш по паттерну"""
        if not self._redis_client:
            return False
        
        try:
            # Получаем ключи и преобразуем их в список
            keys = self._redis_client.keys(pattern)
            if isinstance(keys, list) and keys:
                self._redis_client.delete(*keys)
            return True
        except Exception as e:
            logger.warning(f"Cache invalidation error: {e}")
            return False
    
    def execute_query(self, query: str, params: Optional[Tuple] = None, 
                     cache_key: Optional[str] = None, cache_expire: int = 300) -> List[Tuple]:
        """Выполнить SQL запрос с кэшированием"""
        # Попробуем получить из кэша
        if cache_key:
            cached_result = self.get_cached(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for key: {cache_key}")
                return cached_result
        
        # Выполняем запрос к БД
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, params)
                    result = cursor.fetchall()
                    
                    # Сохраняем в кэш
                    if cache_key:
                        self.set_cached(cache_key, result, cache_expire)
                    
                    return result
        except Exception as e:
            logger.error(f"Database query error: {e}")
            raise
    
    def execute_update(self, query: str, params: Optional[Tuple] = None) -> int:
        """Выполнить UPDATE/INSERT/DELETE запрос с инвалидацией кэша"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, params)
                    conn.commit()
                    # Инвалидируем связанные кэши
                    self.invalidate_cache("vuln:*")
                    self.invalidate_cache("stats:*")
                    return cursor.rowcount
        except Exception as e:
            logger.error(f"Database update error: {e}")
            raise

# Глобальный экземпляр
optimized_db_manager = OptimizedDatabaseManager()