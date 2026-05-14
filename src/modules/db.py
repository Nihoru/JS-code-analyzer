import psycopg2
from psycopg2 import sql
import subprocess
import sys

class DB_handler:
    """
    Класс для управления взаимодействием с базой данных PostgreSQL.
    Обеспечивает создание БД, таблиц, вставку и получение данных.
    """
    def __init__(self, user_password, port=5432):
        """
        Инициализирует обработчик БД. Проверяет наличие PostgreSQL и устанавливает соединение.
        """
        if not DB_handler.__is_postgresql_installed():
            raise Exception("Критическая ошибка: PostgreSQL не обнаружен в системе. Пожалуйста, установите PostgreSQL.")

        self.config = {
            "dbname": "JS_Code_Analyzer",  # Имя целевой базы данных
            "user": "postgres",           # Имя пользователя
            "password": user_password,     # Пароль для доступа
            "host": "localhost",           # Адрес сервера
            "port": f"{port}"              # Порт подключения
        }

        # Ожидание инициализации соединения
        not_initialised = True
        while not_initialised:
            self.connection = DB_handler.__setup_database(self.config)
            if self.connection:
                not_initialised = False
        

    @staticmethod
    def __is_postgresql_installed():
        """
        Проверяет наличие PostgreSQL в системе через вызов psql.
        """
        try:
            subprocess.run(['psql', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def insert(self, data_tuple):
        """
        Вставляет информацию в БД. 
        Вход: tuple со строгой длиной 8. 
        (Ссылка: String, кол-во чистых строк: int, угроз 1 уровня: int, 2: int, 3: int, 4: int, 5: int, рекомендации: String)
        """
        try:
            cur = self.connection.cursor()
            insert_query = """
                INSERT INTO results (url, purerows, l1rows, l2rows, l3rows, l4rows, l5rows, recommendations)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """
            cur.execute(insert_query, data_tuple)
            self.connection.commit()
        except Exception as e:
            raise Exception(f"Возникла ошибка внутри программы при вставке данных:\n{e}")

    @staticmethod
    def __setup_database(db_config):
        """
        Создает БД в случае, когда она отсутствует на устройстве, или подключается к существующей.
        """
        db_name = db_config['dbname']
        
        try:
            # Подключение к системной БД для проверки/создания целевой БД
            conn = psycopg2.connect(
                dbname='postgres',
                user=db_config['user'],
                password=db_config['password'],
                host=db_config.get('host', 'localhost'),
                port=db_config['port']
            )
            conn.autocommit = True
            cur = conn.cursor()

            # Проверка наличия базы данных
            cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (db_name,))
            if not cur.fetchone():
                cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
            
            cur.close()
            conn.close()

            # Создание таблиц, если они не существуют
            conn = psycopg2.connect(**db_config)
            conn.autocommit = True
            cur = conn.cursor()

            create_table_query = """
            CREATE TABLE IF NOT EXISTS results (
                id SERIAL PRIMARY KEY,
                url VARCHAR(100) NOT NULL,
                purerows INTEGER,
                l1rows INTEGER,
                l2rows INTEGER,
                l3rows INTEGER,
                l4rows INTEGER,
                l5rows INTEGER,
                recommendations VARCHAR(10000)
            );
            """
            cur.execute(create_table_query)
            return conn

        except (Exception, psycopg2.OperationalError) as e:
            # Выбрасываем исключение для обработки в main.py
            raise Exception(f"Ошибка подключения к PostgreSQL: {e}")

    def get_all(self):
        """
        Возвращает все данные из БД в виде массива tuple(9).
        """
        cur = self.connection.cursor()
        select_query = "SELECT * FROM results;"
        cur.execute(select_query)
        return cur.fetchall()
    
    def get_where_link(self, link):
        """
        Возвращает данные (tuple(9)) о конкретном сайте по ссылке на него.
        """
        cur = self.connection.cursor()
        select_where_query = "SELECT * FROM results WHERE url = %s;"
        cur.execute(select_where_query, (link,))
        return cur.fetchall()