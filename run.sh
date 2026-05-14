#!/bin/bash

# --- ЦВЕТОВАЯ ПАЛИТРА ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Без цвета

# --- ПРОВЕРКА ЗАВИСИМОСТЕЙ ---

# Установка whiptail, если он отсутствует
if ! command -v whiptail &> /dev/null; then
    echo -e "${YELLOW}[!] whiptail не найден. Попытка установки...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y whiptail
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y newt
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm libnewt
    else
        echo -e "${RED}[!] Не удалось установить whiptail. Пожалуйста, установите 'newt' или 'whiptail' вручную.${NC}"
        exit 1
    fi
fi

check_system_dependencies() {
    # Поиск команды python
    PYTHON_CMD=""
    if command -v python3 &> /dev/null; then 
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then 
        PYTHON_CMD="python"
    fi

    if [ -z "$PYTHON_CMD" ]; then
        whiptail --title "Ошибка" --msgbox "Python не найден. Пожалуйста, установите Python 3." 8 45
        exit 1
    fi

    if ! command -v psql &> /dev/null; then
        whiptail --title "Внимание" --msgbox "PostgreSQL не найден. Сохранение и просмотр истории будут недоступны." 8 45
        export HAS_PSQL=0
    else
        export HAS_PSQL=1
    fi
}

# --- НАСТРОЙКА ОКРУЖЕНИЯ ---

setup_venv() {
    # Создание виртуального окружения, если его нет
    if [ ! -d ".venv" ]; then
        {
            echo "10" ; sleep 0.5
            $PYTHON_CMD -m venv .venv
            echo "40" ; sleep 0.5
        } | whiptail --title "Настройка" --gauge "Создание виртуального окружения..." 8 50 0
    fi
    
    # Активация окружения (Linux/macOS или Windows)
    if [ -f ".venv/bin/activate" ]; then 
        source .venv/bin/activate
    elif [ -f ".venv/Scripts/activate" ]; then 
        source ".venv/Scripts/activate"
    fi

    # Обновление pip и установка зависимостей
    {
        echo "50"
        python -m pip install -q --no-cache-dir --upgrade pip
        echo "70"
        python -m pip install -q --no-cache-dir -r requirements.txt
        echo "100"
    } | whiptail --title "Настройка" --gauge "Установка зависимостей Python..." 8 50 50
}

setup_db_config() {
    local CURRENT_PASS=""
    local CURRENT_PORT=""
    local CURRENT_KEY=""

    # Чтение текущих настроек из .env
    if [ -f .env ]; then
        CURRENT_PASS=$(grep '^DB_PASS=' .env | cut -d'"' -f2)
        CURRENT_PORT=$(grep '^DB_PORT=' .env | cut -d'"' -f2)
        CURRENT_KEY=$(grep '^GEMINI_API_KEY=' .env | cut -d'"' -f2)
    fi

    local INPUT
    
    # Запрашиваем настройки БД только если она установлена в системе
    if [ "$HAS_PSQL" = "1" ]; then
        DB_PASS="${CURRENT_PASS:-postgres}"
        DB_PORT="${CURRENT_PORT:-5432}"

        INPUT=$(whiptail --title "Конфигурация" --inputbox "Пароль PostgreSQL:" 8 45 "$DB_PASS" 3>&1 1>&2 2>&3)
        [ $? -eq 0 ] && DB_PASS="$INPUT"

        INPUT=$(whiptail --title "Конфигурация" --inputbox "Порт PostgreSQL:" 8 45 "$DB_PORT" 3>&1 1>&2 2>&3)
        [ $? -eq 0 ] && DB_PORT="$INPUT"
    else
        DB_PASS=""
        DB_PORT=""
    fi

    GEMINI_API_KEY="${CURRENT_KEY:-}"
    INPUT=$(whiptail --title "Конфигурация" --inputbox "API ключ Gemini (опционально):" 8 45 "$GEMINI_API_KEY" 3>&1 1>&2 2>&3)
    [ $? -eq 0 ] && GEMINI_API_KEY="$INPUT"

    # Сохранение настроек в .env файл
    > .env
    [ -n "$DB_PASS" ] && echo "DB_PASS=\"$DB_PASS\"" >> .env
    [ -n "$DB_PORT" ] && echo "DB_PORT=\"$DB_PORT\"" >> .env
    [ -n "$GEMINI_API_KEY" ] && echo "GEMINI_API_KEY=\"$GEMINI_API_KEY\"" >> .env
    [ -n "$SHOW_LOGS" ] && echo "SHOW_LOGS=\"$SHOW_LOGS\"" >> .env
    
    export DB_PASS DB_PORT GEMINI_API_KEY
}

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

ensure_sudo_for_db() {
    # Запрос sudo заранее, если сервис БД не запущен
    if command -v pg_isready &> /dev/null && ! pg_isready -q; then
        clear
        echo -e "${YELLOW}[*] Внимание: PostgreSQL не запущен.${NC}"
        echo -e "${YELLOW}[*] Пожалуйста, подтвердите права администратора для его запуска.${NC}"
        sudo -v
    fi
}

# --- ОСНОВНЫЕ ДЕЙСТВИЯ ---

analyze_url() {
    URL=$(whiptail --title "Анализ" --inputbox "Введите URL сайта:" 8 60 "https://" 3>&1 1>&2 2>&3)
    [ -z "$URL" ] && return

    if [ "$HAS_PSQL" = "1" ]; then
        ensure_sudo_for_db

        # Проверка доступности БД
        if ! $PYTHON_CMD src/main.py check-db --db-pass "$DB_PASS" --db-port "$DB_PORT" &> /dev/null; then
            if whiptail --title "Ошибка БД" --yesno "База данных недоступна. Прервать процесс?" 10 60; then
                return
            fi
            SKIP_DB_FLAG="--skip-db"
        else
            SKIP_DB_FLAG=""
        fi
    else
        SKIP_DB_FLAG="--skip-db"
    fi

    mkdir -p src/output
    LOG_FILE="src/output/analysis.log"
    
    # Расчет размеров окна
    WT_HEIGHT=$(tput lines)
    WT_WIDTH=$(tput cols)
    TABLE_WIDTH=$((WT_WIDTH - 14))

    LOG_FLAG=""
    [ "$SHOW_LOGS" = "true" ] && LOG_FLAG="--show-logs"

    # Запуск Python скрипта анализа
    (
        $PYTHON_CMD src/main.py analyze "$URL" \
            --db-pass "${DB_PASS:-none}" \
            --db-port "${DB_PORT:-5432}" \
            --width "$TABLE_WIDTH" \
            ${GEMINI_API_KEY:+--api-key "$GEMINI_API_KEY"} \
            $LOG_FLAG \
            $SKIP_DB_FLAG \
            --progress 2>&1 1>&3 | whiptail --title "Анализ" --gauge "Запуск анализа для $URL..." 8 60 0
    ) 3>"$LOG_FILE"
    
    # Отображение результатов, если лог-файл не пуст
    if [ -s "$LOG_FILE" ]; then
        whiptail --title "Результаты анализа" --scrolltext --textbox "$LOG_FILE" $((WT_HEIGHT - 4)) $((WT_WIDTH - 10))
    else
        whiptail --title "Ошибка" --msgbox "Не удалось получить результаты. Проверьте БД и права доступа." 12 60
    fi
    
    rm -f "$LOG_FILE"
}

view_db() {
    if [ "$HAS_PSQL" = "0" ]; then
        whiptail --title "Внимание" --msgbox "PostgreSQL не установлен. Просмотр истории невозможен." 8 60
        return
    fi

    ensure_sudo_for_db

    # Проверка доступности БД
    if ! $PYTHON_CMD src/main.py check-db --db-pass "$DB_PASS" --db-port "$DB_PORT" &> /dev/null; then
        whiptail --title "Ошибка БД" --msgbox "База данных недоступна. Просмотр истории невозможен." 8 60
        return
    fi

    mkdir -p src/output
    TEMP_DB="src/output/db_view.tmp"
    
    WT_HEIGHT=$(tput lines)
    WT_WIDTH=$(tput cols)
    TABLE_WIDTH=$((WT_WIDTH - 14))
    
    LOG_FLAG=""
    [ "$SHOW_LOGS" = "true" ] && LOG_FLAG="--show-logs"

    # Запуск Python скрипта для просмотра БД
    (
        $PYTHON_CMD src/main.py view \
            --db-pass "$DB_PASS" \
            --db-port "$DB_PORT" \
            --width "$TABLE_WIDTH" \
            $LOG_FLAG \
            --progress 2>&1 1>&3 | whiptail --title "Загрузка" --gauge "Получение данных из базы..." 8 45 0
    ) 3>"$TEMP_DB"
    
    if [ -s "$TEMP_DB" ]; then
        whiptail --title "История анализов" --scrolltext --textbox "$TEMP_DB" $((WT_HEIGHT - 4)) $((WT_WIDTH - 10))
    else
        whiptail --title "Ошибка" --msgbox "Не удалось загрузить данные. Проверьте подключение к БД." 8 45
    fi
    
    rm -f "$TEMP_DB"
}

# --- ГЛАВНЫЙ ЦИКЛ ---

main_menu() {
    check_system_dependencies
    setup_venv
    
    # Загрузка переменных окружения из .env
    if [ -f .env ]; then
        export DB_PASS=$(grep '^DB_PASS=' .env | cut -d'"' -f2)
        export DB_PORT=$(grep '^DB_PORT=' .env | cut -d'"' -f2)
        export GEMINI_API_KEY=$(grep '^GEMINI_API_KEY=' .env | cut -d'"' -f2)
        export SHOW_LOGS=$(grep '^SHOW_LOGS=' .env | cut -d'"' -f2)
    fi
    
    # Если СУБД появилась, но настроек еще нет, запрашиваем их
    if [ "$HAS_PSQL" = "1" ] && { [ -z "$DB_PASS" ] || [ -z "$DB_PORT" ]; }; then
        setup_db_config
    elif [ ! -f .env ]; then
        setup_db_config
    fi
    
    # По умолчанию логи включены
    [ -z "$SHOW_LOGS" ] && SHOW_LOGS="true"

    while true; do
        LOG_STATUS="ВКЛ"
        [ "$SHOW_LOGS" = "false" ] && LOG_STATUS="ВЫКЛ"

        # Отрисовка главного меню whiptail
        CHOICE=$(whiptail --title "JS Code Analyzer CLI" --menu "Главное меню" 16 60 5 \
            --nocancel --notags \
            "1" "Анализировать сайт (URL)" \
            "2" "Просмотреть историю (БД)" \
            "3" "Настройки (.env)" \
            "4" "Системные уведомления: [$LOG_STATUS]" \
            "5" "Выход" 3>&1 1>&2 2>&3)

        case $CHOICE in
            1) analyze_url ;;
            2) view_db ;;
            3) setup_db_config ;;
            4) 
                # Переключение статуса логов
                if [ "$SHOW_LOGS" = "true" ]; then SHOW_LOGS="false"; else SHOW_LOGS="true"; fi
                sed -i '/^SHOW_LOGS=/d' .env
                echo "SHOW_LOGS=\"$SHOW_LOGS\"" >> .env
                ;;
            *) 
                whiptail --title "Выход" --msgbox "До встречи!" 8 30
                exit 0 
                ;;
        esac
    done
}

# Запуск программы
main_menu
