import sys
import os
import argparse
import subprocess
import time
import atexit
import io
from contextlib import redirect_stdout, redirect_stderr

# --- ГЛОБАЛЬНЫЕ НАСТРОЙКИ ---
STARTED_BY_SCRIPT = False   # Флаг автоматического запуска PostgreSQL
SERVICE_LOGS = []           # Коллектор для системных сообщений
PROGRESS_ENABLED = False    # Флаг отображения прогресса для whiptail
_REAL_STDERR = sys.stderr   # Ссылка на реальный поток ошибок

# --- ВСПОМОГАТЕЛЬНЫЕ КЛАССЫ И ФУНКЦИИ ---

class OutputCapture:
    """
    Контекстный менеджер для перехвата стандартных потоков вывода (stdout и stderr).
    Используется для сбора логов из модулей.
    """
    def __enter__(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.out_ctx = redirect_stdout(self.stdout)
        self.err_ctx = redirect_stderr(self.stderr)
        self.out_ctx.__enter__()
        self.err_ctx.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.out_ctx.__exit__(exc_type, exc_val, exc_tb)
        self.err_ctx.__exit__(exc_type, exc_val, exc_tb)

    def get_content(self):
        """Возвращает накопленный текст из stdout и stderr."""
        return self.stdout.getvalue(), self.stderr.getvalue()


def log_status(msg):
    """
    Добавляет сообщение в список системных логов для последующего вывода в панели.
    """
    SERVICE_LOGS.append(msg)


def report_progress(percent, message):
    """
    Выводит данные в stderr в формате, понятном для whiptail --gauge.
    """
    if PROGRESS_ENABLED:
        safe_msg = message
        if len(safe_msg) > 55:
            safe_msg = safe_msg[:52] + "..."
            
        # Протокол обновления текста в whiptail
        print("XXX", file=_REAL_STDERR, flush=True)
        print(f"{percent}", file=_REAL_STDERR, flush=True)
        print(f"{safe_msg}", file=_REAL_STDERR, flush=True)
        print("XXX", file=_REAL_STDERR, flush=True)


def print_service_panel(width=None):
    """
    Выводит панель с накопленными системными логами с использованием rich.
    """
    if not SERVICE_LOGS:
        return
    from rich.console import Console
    from rich.panel import Panel
    from rich import box
    
    console = Console(width=width, color_system=None)
    log_content = "\n".join(SERVICE_LOGS)
    console.print(Panel(
        log_content, 
        title="Системные уведомления", 
        border_style="dim", 
        box=box.ROUNDED,
        padding=(0, 1)
    ))


def normalize_url(url: str) -> str:
    """
    Приводит URL к стандартному виду, добавляя протокол https://, если он отсутствует.
    """
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"
    return url


# --- УПРАВЛЕНИЕ СЕРВИСАМИ ---

def manage_postgres_service(action="start"):
    """
    Управляет состоянием сервиса PostgreSQL в зависимости от операционной системы.
    """
    global STARTED_BY_SCRIPT
    
    try:
        # Проверка доступности PostgreSQL
        is_ready = subprocess.run(['pg_isready', '-q'], capture_output=True).returncode == 0
        
        if action == "start":
            if is_ready:
                return False
            
            log_status("PostgreSQL не запущен. Попытка автоматического запуска...")
            if os.name == 'nt':  # Windows
                subprocess.run(['net', 'start', 'postgresql-x64-16'], check=True, capture_output=True)
            else:  # Linux
                subprocess.run(['sudo', 'systemctl', 'start', 'postgresql'], check=True, capture_output=True)
            
            log_status("PostgreSQL успешно запущен.")
            time.sleep(2)  # Время на инициализацию
            STARTED_BY_SCRIPT = True
            return True
            
        elif action == "stop" and STARTED_BY_SCRIPT:
            # Остановка сервиса при выходе, если он был запущен этим скриптом
            if os.name == 'nt':
                subprocess.run(['net', 'stop', 'postgresql-x64-16'], check=True, capture_output=True)
            else:
                subprocess.run(['sudo', 'systemctl', 'stop', 'postgresql'], check=True, capture_output=True)
            
    except Exception as e:
        if action == "start":
            log_status(f"Не удалось автоматически запустить сервис: {e}")
        return False

# Автоматическая остановка при завершении работы
atexit.register(manage_postgres_service, action="stop")


# --- ОСНОВНЫЕ СЦЕНАРИИ ---

def analyze_scenario(url, db_pass, db_port, api_key=None, width=None, show_logs=True, skip_db=False):
    """
    Выполняет полный цикл анализа сайта: сбор кода, поиск уязвимостей, 
    получение советов ИИ и сохранение результатов.
    """
    from modules.parser import save_all_js_from_url
    from modules.analyzer import analyze_code_js, get_vulnerabilities_detailed
    from modules.advisor import LlmVulnerabilityRecommender
    from modules.db import DB_handler
    from modules.calculator import calculate_infection_rate
    from rich.console import Console
    from rich.panel import Panel
    from rich import box

    console = Console(width=width, color_system=None)
    url = normalize_url(url)
    js_file = "src/output/js_code.txt"  # Путь к временному файлу с кодом
    
    with OutputCapture() as capture:
        report_progress(5, "Проверка базы данных...")
        manage_postgres_service("start")
        try:
            report_progress(15, f"Сбор JS кода с {url}...")
            log_status(f"Начинаю сбор JS кода с {url}...")
            save_all_js_from_url(url, js_file)
            
            if not os.path.exists(js_file) or os.path.getsize(js_file) == 0:
                log_status("Код не был собран. Прерывание.")
                report_progress(100, "Ошибка: код не собран.")
            else:
                report_progress(40, "Анализ кода на уязвимости...")
                log_status("Анализ кода на уязвимости...")
                stats = analyze_code_js(url, js_file)
                detailed = get_vulnerabilities_detailed(url, js_file)
                
                report_progress(60, "Расчет показателей зараженности...")
                infection_m, m1, m2, n = calculate_infection_rate(js_file)
                
                log_status(f"Найдено уязвимостей (L1-L5): {len(detailed)}")

                recommendations = ""
                if api_key:
                    report_progress(75, "Запрос рекомендаций у ИИ...")
                    log_status("Запрос рекомендаций у ИИ...")
                    try:
                        with LlmVulnerabilityRecommender(api_key=api_key) as recommender:
                            recommendations = recommender.get_recommendations(detailed)
                            log_status("Рекомендации ИИ успешно получены.")
                    except Exception as e:
                        log_status(f"Ошибка при получении рекомендаций: {e}")

                # Формирование строки для хранения дополнительных данных
                stored_data = f"RATE:{infection_m}%|ADVICE:{recommendations if recommendations else 'Нет советов'}"

                full_data = list(stats)
                full_data[-1] = stored_data
                
                if not skip_db:
                    try:
                        report_progress(90, "Сохранение результатов в БД...")
                        handler = DB_handler(db_pass, db_port)
                        handler.insert(tuple(full_data))
                        log_status("Данные успешно сохранены в БД.")
                    except Exception as e:
                        log_status(f"Ошибка БД при сохранении: {e}")
                else:
                    report_progress(90, "Сохранение в БД пропущено...")
                
                report_progress(100, "Анализ завершен!")
        except Exception as e:
            log_status(f"Критическая ошибка при анализе: {e}")
            report_progress(100, f"Ошибка: {e}")

    # Сбор и очистка логов из захваченного вывода
    out_text, err_text = capture.get_content()
    for line in out_text.strip().split('\n'):
        if line.strip(): SERVICE_LOGS.append(line.strip())
    for line in err_text.strip().split('\n'):
        if line.strip(): SERVICE_LOGS.append(f"ERR: {line.strip()}")

    if show_logs:
        print_service_panel(width=width)

    # Вывод итогового отчета в консоль
    if os.path.exists(js_file) and os.path.getsize(js_file) > 0 and 'infection_m' in locals():
        console.print()
        result_text = f"URL: {url}\n\n"
        result_text += f"[!] Заражённость кода (M): {infection_m}%\n\n"
        result_text += "--- Детали ---\n"
        result_text += f"Заражённых строк (m1): {m1}\n"
        result_text += f"Уязвимостей (m2): {m2}\n"
        result_text += f"Всего строк (n): {n}\n\n"
        result_text += "--- Советы ---\n"
        result_text += recommendations if recommendations else "Рекомендаций от ИИ нет. Проверьте код вручную."
        if skip_db:
            result_text += "\n\n[!] Внимание: Результат не был записан в БД (база недоступна)."

        console.print(Panel(
            result_text,
            title="Итоговый отчет",
            border_style="dim",
            box=box.ROUNDED,
            padding=(0, 2)
        ))


def view_scenario(db_pass, db_port, width=None, show_logs=True):
    """
    Загружает и отображает историю анализов из базы данных в виде таблицы.
    """
    from modules.db import DB_handler
    from rich.console import Console
    from rich.table import Table
    from rich import box
    
    console = Console(width=width, color_system=None)
    
    with OutputCapture() as capture:
        report_progress(20, "Проверка базы данных...")
        manage_postgres_service("start")
        try:
            report_progress(50, "Чтение данных из БД...")
            handler = DB_handler(db_pass, db_port)
            results = handler.get_all()
            report_progress(100, "Данные загружены!")
        except Exception as e:
            log_status(f"Ошибка БД: {e}")
            results = None
            report_progress(100, f"Ошибка: {e}")

    # Обработка логов
    out_text, err_text = capture.get_content()
    for line in out_text.strip().split('\n'):
        if line.strip(): SERVICE_LOGS.append(line.strip())
    for line in err_text.strip().split('\n'):
        if line.strip(): SERVICE_LOGS.append(f"ERR: {line.strip()}")

    if show_logs:
        print_service_panel(width=width)

    if results is not None:
        if not results:
            console.print("База данных пуста.")
            return

        # Настройка таблицы rich
        table = Table(
            title="Результаты анализа JS кода", 
            show_header=True, 
            show_lines=True,
            expand=True,
            box=box.ROUNDED
        )
        
        table.add_column("ID", justify="right", no_wrap=True)
        table.add_column("URL", min_width=20)
        table.add_column("Чист.", justify="right")
        table.add_column("L1-L5", justify="center")
        table.add_column("%", justify="right")
        table.add_column("Советы ИИ", overflow="fold")
        
        for row in results:
            id_val = str(row[0])
            url = row[1]
            clean = str(row[2])
            vulns = f"{row[3]}/{row[4]}/{row[5]}/{row[6]}/{row[7]}"
            
            raw_advice = row[8] if row[8] else "RATE:0%|ADVICE:Нет данных"
            try:
                rate_part = raw_advice.split('|')[0].replace('RATE:', '')
                advice_part = raw_advice.split('|')[1].replace('ADVICE:', '')
            except Exception:
                rate_part = "?"
                advice_part = raw_advice

            table.add_row(id_val, url, clean, vulns, rate_part, advice_part)
            
        console.print()
        console.print(table)


# --- ТОЧКА ВХОДА ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JS Code Analyzer CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Команда 'analyze'
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("url", help="URL сайта для анализа")
    analyze_parser.add_argument("--db-pass", required=True, help="Пароль от PostgreSQL")
    analyze_parser.add_argument("--db-port", default=5432, type=int, help="Порт PostgreSQL")
    analyze_parser.add_argument("--api-key", help="API ключ для Gemini (опционально)")
    analyze_parser.add_argument("--width", type=int, help="Ширина вывода")
    analyze_parser.add_argument("--show-logs", action="store_true", help="Показывать системные уведомления")
    analyze_parser.add_argument("--progress", action="store_true", help="Выводить прогресс для whiptail")
    analyze_parser.add_argument("--skip-db", action="store_true", help="Пропустить сохранение в БД")

    # Команда 'view'
    view_parser = subparsers.add_parser("view")
    view_parser.add_argument("--db-pass", required=True, help="Пароль от PostgreSQL")
    view_parser.add_argument("--db-port", default=5432, type=int, help="Порт PostgreSQL")
    view_parser.add_argument("--width", type=int, help="Ширина таблицы для вывода")
    view_parser.add_argument("--show-logs", action="store_true", help="Показывать системные уведомления")
    view_parser.add_argument("--progress", action="store_true", help="Выводить прогресс для whiptail")
    
    # Команда 'check-db'
    check_db_parser = subparsers.add_parser("check-db")
    check_db_parser.add_argument("--db-pass", required=True, help="Пароль от PostgreSQL")
    check_db_parser.add_argument("--db-port", default=5432, type=int, help="Порт PostgreSQL")

    args = parser.parse_args()

    if args.command:
        if args.progress:
            PROGRESS_ENABLED = True
            
        if args.command == "analyze":
            analyze_scenario(args.url, args.db_pass, args.db_port, args.api_key, args.width, args.show_logs, args.skip_db)
        elif args.command == "view":
            view_scenario(args.db_pass, args.db_port, args.width, args.show_logs)
        elif args.command == "check-db":
            from modules.db import DB_handler
            manage_postgres_service("start")
            try:
                DB_handler._DB_handler__setup_database({
                    "dbname": "JS_Code_Analyzer",
                    "user": "postgres",
                    "password": args.db_pass,
                    "host": "localhost",
                    "port": str(args.db_port)
                })
            except Exception:
                sys.exit(1)
    else:
        parser.print_help()
