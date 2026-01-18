"""
Загрузчик данных с поддержкой различных форматов
"""

import pandas as pd
import numpy as np
import torch
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, Union
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
import pickle
import h5py

from ml_platform.core.logger import PlatformLogger


class DataLoader:
    """Загрузка и подготовка данных для обучения"""
    
    def __init__(
        self,
        train_split: float = 0.7,
        val_split: float = 0.15,
        test_split: float = 0.15,
        normalize: bool = True,
        random_state: int = 42
    ):
        """
        Инициализация загрузчика данных
        
        Args:
            train_split: Доля обучающих данных
            val_split: Доля валидационных данных
            test_split: Доля тестовых данных
            normalize: Нормализовать ли данные
            random_state: Seed для воспроизводимости
        """
        assert abs(train_split + val_split + test_split - 1.0) < 1e-6, \
            "Сумма долей должна быть равна 1.0"
        
        self.train_split = train_split
        self.val_split = val_split
        self.test_split = test_split
        self.normalize = normalize
        self.random_state = random_state
        self.logger = PlatformLogger.get_logger()
        self.scaler: Optional[StandardScaler] = None
        self.imputer: Optional[SimpleImputer] = None
    
    def load_data(self, file_path: str, **kwargs) -> pd.DataFrame:
        """
        Загрузка данных из файла
        
        Args:
            file_path: Путь к файлу данных
            **kwargs: Дополнительные параметры для pandas
            
        Returns:
            DataFrame с данными
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Файл данных не найден: {file_path}")
        
        self.logger.info(f"Загрузка данных из {file_path}")
        
        # Определение формата файла
        suffix = path.suffix.lower()
        
        try:
            if suffix == '.csv':
                df = pd.read_csv(file_path, **kwargs)
            elif suffix in ['.parquet', '.pq']:
                df = pd.read_parquet(file_path, **kwargs)
            elif suffix == '.pkl' or suffix == '.pickle':
                with open(file_path, 'rb') as f:
                    df = pickle.load(f)
                if not isinstance(df, pd.DataFrame):
                    raise ValueError("Файл pickle должен содержать DataFrame")
            elif suffix in ['.h5', '.hdf5']:
                if not H5PY_AVAILABLE:
                    raise ImportError("h5py не установлен. Установите: pip install h5py")
                # Для HDF5 предполагаем, что данные в ключе 'data'
                key = kwargs.pop('key', 'data')
                df = pd.read_hdf(file_path, key=key, **kwargs)
            else:
                raise ValueError(f"Неподдерживаемый формат файла: {suffix}")
            
            self.logger.info(f"Данные загружены: {len(df)} строк, {len(df.columns)} столбцов")
            return df
            
        except Exception as e:
            self.logger.error(f"Ошибка при загрузке данных: {e}")
            raise
    
    def validate_data(self, df: pd.DataFrame) -> Tuple[bool, Optional[str]]:
        """
        Проверка целостности данных
        
        Args:
            df: DataFrame для проверки
            
        Returns:
            Tuple (валидны ли данные, сообщение об ошибке)
        """
        # Проверка на пустой DataFrame
        if df.empty:
            return False, "DataFrame пуст"
        
        # Проверка на наличие NaN
        nan_count = df.isna().sum().sum()
        if nan_count > 0:
            self.logger.warning(f"Обнаружено {nan_count} пропущенных значений")
            # Не критично, но нужно обработать
        
        # Проверка на бесконечные значения
        inf_count = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
        if inf_count > 0:
            return False, f"Обнаружено {inf_count} бесконечных значений"
        
        # Проверка на достаточное количество данных
        if len(df) < 10:
            return False, "Недостаточно данных для обучения (минимум 10 строк)"
        
        return True, None
    
    def prepare_data(
        self,
        df: pd.DataFrame,
        target_column: Optional[str] = None,
        feature_columns: Optional[list] = None,
        handle_missing: str = 'mean'
    ) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Подготовка данных для обучения
        
        Args:
            df: DataFrame с данными
            target_column: Название столбца с целевой переменной
            feature_columns: Список столбцов-признаков (если None, все кроме target)
            handle_missing: Стратегия обработки пропусков ('mean', 'median', 'drop')
            
        Returns:
            Tuple (X, y) - признаки и целевая переменная
        """
        # Валидация данных
        is_valid, error_msg = self.validate_data(df)
        if not is_valid:
            raise ValueError(f"Данные невалидны: {error_msg}")
        
        # Определение признаков
        if feature_columns is None:
            if target_column:
                feature_columns = [col for col in df.columns if col != target_column]
            else:
                feature_columns = list(df.columns)
        
        X = df[feature_columns].select_dtypes(include=[np.number]).values
        
        # Обработка пропущенных значений
        if np.isnan(X).any():
            if handle_missing == 'drop':
                mask = ~np.isnan(X).any(axis=1)
                X = X[mask]
                if target_column:
                    y = df[target_column].values[mask]
                else:
                    y = None
            else:
                self.imputer = SimpleImputer(strategy=handle_missing)
                X = self.imputer.fit_transform(X)
                if target_column:
                    y = df[target_column].values
                else:
                    y = None
        else:
            if target_column:
                y = df[target_column].values
            else:
                y = None
        
        # Нормализация
        if self.normalize:
            self.scaler = StandardScaler()
            X = self.scaler.fit_transform(X)
            self.logger.info("Данные нормализованы")
        
        return X, y
    
    def split_data(
        self,
        X: np.ndarray,
        y: Optional[np.ndarray] = None
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, Optional[np.ndarray], Optional[np.ndarray], Optional[np.ndarray]]:
        """
        Разделение данных на train/val/test
        
        Args:
            X: Признаки
            y: Целевая переменная (опционально)
            
        Returns:
            Tuple (X_train, X_val, X_test, y_train, y_val, y_test)
        """
        # Первое разделение: train и temp (val + test)
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y,
            test_size=(1 - self.train_split),
            random_state=self.random_state,
            stratify=y if y is not None else None
        )
        
        # Второе разделение: val и test
        val_ratio = self.val_split / (self.val_split + self.test_split)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp,
            test_size=(1 - val_ratio),
            random_state=self.random_state,
            stratify=y_temp if y_temp is not None else None
        )
        
        self.logger.info(
            f"Данные разделены: train={len(X_train)}, "
            f"val={len(X_val)}, test={len(X_test)}"
        )
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def create_dataloaders(
        self,
        X_train: np.ndarray,
        X_val: np.ndarray,
        X_test: np.ndarray,
        y_train: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        y_test: Optional[np.ndarray] = None,
        batch_size: int = 32,
        shuffle: bool = True
    ) -> Tuple[torch.utils.data.DataLoader, torch.utils.data.DataLoader, torch.utils.data.DataLoader]:
        """
        Создание PyTorch DataLoader'ов
        
        Args:
            X_train, X_val, X_test: Признаки
            y_train, y_val, y_test: Целевые переменные
            batch_size: Размер батча
            shuffle: Перемешивать ли данные
            
        Returns:
            Tuple (train_loader, val_loader, test_loader)
        """
        # Преобразование в тензоры
        X_train_tensor = torch.FloatTensor(X_train)
        X_val_tensor = torch.FloatTensor(X_val)
        X_test_tensor = torch.FloatTensor(X_test)
        
        # Создание датасетов
        if y_train is not None:
            y_train_tensor = torch.LongTensor(y_train) if y_train.dtype in [np.int32, np.int64] else torch.FloatTensor(y_train)
            train_dataset = torch.utils.data.TensorDataset(X_train_tensor, y_train_tensor)
        else:
            train_dataset = torch.utils.data.TensorDataset(X_train_tensor)
        
        if y_val is not None:
            y_val_tensor = torch.LongTensor(y_val) if y_val.dtype in [np.int32, np.int64] else torch.FloatTensor(y_val)
            val_dataset = torch.utils.data.TensorDataset(X_val_tensor, y_val_tensor)
        else:
            val_dataset = torch.utils.data.TensorDataset(X_val_tensor)
        
        if y_test is not None:
            y_test_tensor = torch.LongTensor(y_test) if y_test.dtype in [np.int32, np.int64] else torch.FloatTensor(y_test)
            test_dataset = torch.utils.data.TensorDataset(X_test_tensor, y_test_tensor)
        else:
            test_dataset = torch.utils.data.TensorDataset(X_test_tensor)
        
        # Создание DataLoader'ов
        train_loader = torch.utils.data.DataLoader(
            train_dataset, batch_size=batch_size, shuffle=shuffle
        )
        val_loader = torch.utils.data.DataLoader(
            val_dataset, batch_size=batch_size, shuffle=False
        )
        test_loader = torch.utils.data.DataLoader(
            test_dataset, batch_size=batch_size, shuffle=False
        )
        
        return train_loader, val_loader, test_loader
    
    def load_and_prepare(
        self,
        file_path: str,
        target_column: Optional[str] = None,
        batch_size: int = 32
    ) -> Tuple[torch.utils.data.DataLoader, torch.utils.data.DataLoader, torch.utils.data.DataLoader]:
        """
        Полный цикл загрузки и подготовки данных
        
        Args:
            file_path: Путь к файлу данных
            target_column: Название столбца с целевой переменной
            batch_size: Размер батча
            
        Returns:
            Tuple (train_loader, val_loader, test_loader)
        """
        # Загрузка
        df = self.load_data(file_path)
        
        # Подготовка
        X, y = self.prepare_data(df, target_column=target_column)
        
        # Разделение
        X_train, X_val, X_test, y_train, y_val, y_test = self.split_data(X, y)
        
        # Создание DataLoader'ов
        return self.create_dataloaders(
            X_train, X_val, X_test, y_train, y_val, y_test, batch_size=batch_size
        )
