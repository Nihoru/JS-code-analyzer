import psycopg2
from psycopg2 import sql
import subprocess
import sys

class DB_handler:
    def __init__(self, user_password, port=5432):
        
        """Класс для работы с БД. Инициализируется с настройками для входа в БД."""
        
        if not DB_handler.__is_postgresql_installed:
                print("Критическая ошибка: PostgreSQL не обнаружен в системе.")
                print("Пожалуйста, установите PostgreSQL (https://www.postgresql.org/download/).")
                sys.exit()
        self.config = {
            "dbname": "JS_Code_Analyzer",
            "user": "postgres",
            "password": user_password,
            "host": "localhost",
            "port": f"{port}"
        }
        not_initialised = True
        while not_initialised:
            self.connection = DB_handler.__setup_database(self.config)
            if self.connection:
                not_initialised = False
        

    def __is_postgresql_installed():
        
        """Проверяет наличие PostgreSQL на машине пользователя"""

        try:
            subprocess.run(['psql', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def insert(self, data_tuple):

        """Вставляет информация в БД. 
        Вход: tuple со строгой длинной 8. 
        (Ссылка: String, кол-во чистых строк: int, угроз 1 уровня: int, 2: int, 3: int, 4: int, 5: int, рекомендации: Sring)"""

        try:
            cur = self.connection.cursor()
            insert_query = """
                INSERT INTO results (url, purerows, l1rows, l2rows, l3rows, l4rows, l5rows, recommendations)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """
            cur.execute(insert_query, data_tuple)
            self.connection.commit()
        except Exception as e:
            print(f"Возникла ошибка внутри программы.\n{e}")
            sys.exit()

    def __setup_database(db_config):
        
        """Создает дб в случае, когда она отсутсвует на устройстве или подключается к существующей"""
        
        db_name = db_config['dbname']
        
        try:
            #Подключение к системе
            conn = psycopg2.connect(
                dbname='postgres',
                user=db_config['user'],
                password=db_config['password'],
                host=db_config.get('host', 'localhost'),
                port=db_config['port']
            )
            conn.autocommit = True
            cur = conn.cursor()

            # Проверка наличия БД
            cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (db_name,))
            if not cur.fetchone():
                confirm = input(f"База '{db_name}' не найдена. Создать? (y/n): ")
                if confirm.lower() == 'y':
                    cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
                    print(f"База '{db_name}' успешно создана.")
                else:
                    print("Создание базы отменено.")
                    return None
            
            cur.close()
            conn.close()

            #Создание таблиц, если их не существует в БД
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
            print(f"Ошибка подключения: Проверьте, запущен ли сервер PostgreSQL и верен ли пароль.\n{e}")
            choice = input("Повторить попытку? (y/n): ")
            if choice != "y":
                sys.exit()

    def get_all(self):

        """Возвращает все даннын из БД в виде массива tuple(9)."""

        cur = self.connection.cursor()
        select_query = """
        SELECT * FROM results;
        """
        cur.execute(select_query)
        return cur.fetchall()
    
    def get_where_link(self, link):
        
        """Возвращает данные (tuple(9)) о конкретном сайте по ссылке на него."""

        cur = self.connection.cursor()
        select_where_query = f"""
        SELECT * FROM results WHERE results.url = '{link}';
        """
        cur.execute(select_where_query)
        return cur.fetchall()

db = DB_handler("passw", "1111")
print(db.get_all())