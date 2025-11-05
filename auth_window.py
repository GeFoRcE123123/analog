import tkinter as tk
from tkinter import ttk, messagebox
from database import db_manager


class AuthWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Авторизация в Vulnerability Management System")
        self.root.geometry("400x350")
        self.root.resizable(False, False)

        self.center_window()
        self.setup_ui()

    def center_window(self):
        """Центрирование окна на экране"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def setup_ui(self):
        """Настройка интерфейса"""
        # Заголовок
        title_label = ttk.Label(
            self.root,
            text="Vulnerability Management System",
            font=('Arial', 16, 'bold')
        )
        title_label.pack(pady=20)

        # Фрейм для полей ввода
        input_frame = ttk.Frame(self.root)
        input_frame.pack(pady=20, padx=40, fill='x')

        # Поле для хоста
        ttk.Label(input_frame, text="IP адрес сервера:").grid(row=0, column=0, sticky='w', pady=5)
        self.host_entry = ttk.Entry(input_frame, width=25)
        self.host_entry.grid(row=0, column=1, sticky='ew', pady=5, padx=(10, 0))
        self.host_entry.insert(0, "localhost")

        # Поле для порта
        ttk.Label(input_frame, text="Порт:").grid(row=1, column=0, sticky='w', pady=5)
        self.port_entry = ttk.Entry(input_frame, width=25)
        self.port_entry.grid(row=1, column=1, sticky='ew', pady=5, padx=(10, 0))
        self.port_entry.insert(0, "5432")

        # Поле для базы данных
        ttk.Label(input_frame, text="База данных:").grid(row=2, column=0, sticky='w', pady=5)
        self.database_entry = ttk.Entry(input_frame, width=25)
        self.database_entry.grid(row=2, column=1, sticky='ew', pady=5, padx=(10, 0))
        self.database_entry.insert(0, "vulnerability_db")

        # Поле для пользователя
        ttk.Label(input_frame, text="Пользователь:").grid(row=3, column=0, sticky='w', pady=5)
        self.username_entry = ttk.Entry(input_frame, width=25)
        self.username_entry.grid(row=3, column=1, sticky='ew', pady=5, padx=(10, 0))
        self.username_entry.insert(0, "postgres")

        # Поле для пароля
        ttk.Label(input_frame, text="Пароль:").grid(row=4, column=0, sticky='w', pady=5)
        self.password_entry = ttk.Entry(input_frame, width=25, show="*")
        self.password_entry.grid(row=4, column=1, sticky='ew', pady=5, padx=(10, 0))

        # Настройка весов колонок
        input_frame.columnconfigure(1, weight=1)

        # Фрейм для кнопок
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=20)

        # Кнопка подключения
        self.connect_btn = ttk.Button(
            button_frame,
            text="Подключиться",
            command=self.connect_to_database
        )
        self.connect_btn.pack(side='left', padx=10)

        # Кнопка выхода
        ttk.Button(
            button_frame,
            text="Выход",
            command=self.root.quit
        ).pack(side='left', padx=10)

        # Статус бар
        self.status_var = tk.StringVar(value="Готов к подключению")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief='sunken')
        status_bar.pack(side='bottom', fill='x', ipady=5)

        # Бинд Enter на подключение
        self.root.bind('<Return>', lambda e: self.connect_to_database())

    def connect_to_database(self):
        """Подключение к базе данных через DatabaseManager"""
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip()
        database = self.database_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        # Валидация
        if not all([host, port, database, username]):
            messagebox.showerror("Ошибка", "Все поля обязательны для заполнения")
            return

        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Ошибка", "Порт должен быть числом")
            return

        self.status_var.set("Подключение...")
        self.connect_btn.config(state='disabled')
        self.root.update()

        try:
            # Конфигурируем и подключаемся через DatabaseManager
            db_manager.configure(host, port, database, username, password)

            if db_manager.connect() and db_manager.test_connection():
                connection_info = db_manager.get_connection_info()
                self.status_var.set(f"Успешно подключено к {host}:{port}")

                messagebox.showinfo("Успех",
                                    f"Успешное подключение к базе данных!\n\n"
                                    f"Сервер: {host}:{port}\n"
                                    f"База: {database}\n"
                                    f"Пользователь: {username}")

                # Закрываем окно авторизации
                self.root.destroy()
            else:
                self.status_var.set("Ошибка подключения")
                messagebox.showerror("Ошибка подключения",
                                     "Не удалось подключиться к базе данных")

        except Exception as e:
            self.status_var.set("Неизвестная ошибка")
            messagebox.showerror("Ошибка", f"Произошла неизвестная ошибка:\n\n{str(e)}")
        finally:
            self.connect_btn.config(state='normal')

    def run(self):
        """Запуск окна авторизации"""
        self.root.mainloop()
        return db_manager.is_connected()