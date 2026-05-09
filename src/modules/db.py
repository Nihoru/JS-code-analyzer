import psycopg2
from psycopg2 import sql
import subprocess
import sys

def is_postgresql_installed():
    
    """Проверяет наличие PostgreSQL на машине пользователя"""
    
    try:
        subprocess.run(['psql', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def insert_info_into_db(connection, data_tuple):

    """Вставляет информацию в БД о уязвимостях и рекомендациях"""
    try:
        cur = connection.cursor()
        insert_query = """
            INSERT INTO results (url, purerows, l1rows, l2rows, l3rows, l4rows, l5rows, recommendations)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
            """
        cur.execute(insert_query, data_tuple)
        connection.commit()
    except Exception as e:
        print(f"Возникла ошибка внутри программы.\n{e}")
        sys.exit()

def setup_database(db_config):
    
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
            recommendations VARCHAR(200)
        );
        """
        cur.execute(create_table_query)
        return conn

    except (Exception, psycopg2.OperationalError) as e:
        print(f"Ошибка подключения: Проверьте, запущен ли сервер PostgreSQL и верен ли пароль.\n{e}")
        choice = input("Повторить попытку? (y/n): ")
        if choice != "y":
            sys.exit()

def db_main(data):

    """Main для модуля db. 
    Вход: tuple со строгой длинной 8. 
    (Ссылка, кол-во чистых строк, угроз 1 уровня, 2, 3, 4, 5, рекомендации)"""

    if not is_postgresql_installed:
            print("Критическая ошибка: PostgreSQL не обнаружен в системе.")
            print("Пожалуйста, установите PostgreSQL (https://www.postgresql.org/download/).")
            sys.exit()

    not_completed = True
    while not_completed:
        user_password = input("Введите пароль от пользователя postgres: ")
        port = input("Введите порт для вашей PostgreSQL: ")

        # Настройки подключения
        config = {
            "dbname": "JS_Code_Analyzer",
            "user": "postgres",
            "password": user_password,
            "host": "localhost",
            "port": f"{port}"
        }

        connection = setup_database(config)
        if connection:
            insert_info_into_db(connection, data)
            connection.close()
            not_completed = False