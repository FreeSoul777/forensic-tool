#!/bin/bash
# find_user_artifacts.sh - Поиск артефактов удаленных пользователей
# Оригинальная логика сохранена, добавлен JSON-вывод для Python

# ============================================
# НАСТРОЙКИ
# ============================================
# Для логов (stderr) - видит пользователь
log_info() {
    echo "[INFO] $1" >&2
}

log_debug() {
    echo "[DEBUG] $1" >&2
}

log_error() {
    echo "[ERROR] $1" >&2
}

# Для данных (stdout) - JSON для Python
output_json() {
    echo "$1"
}

# Начало сканирования
output_json "{\"event\":\"scan_start\",\"timestamp\":\"$(date -Iseconds)\"}"

# ============================================
# ЭТАП 1: Пользователи из /etc/passwd
# ============================================
stage1_collect_users() {
    log_info "Этап 1/6: сбор пользователей..."
    
    declare -g -A KNOWN_USERS      # uid -> username
    declare -g -A USER_SHELL
    declare -g -A USER_HOME
    
    local system_users=()
    local active_users=()
    
    while IFS=: read -r username passwd uid gid comment home shell; do
        if [ -n "$uid" ]; then
            KNOWN_USERS["$uid"]="$username"
            USER_SHELL["$uid"]="$shell"
            USER_HOME["$uid"]="$home"
            
            # Для JSON отчета
            if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
                system_users+=("{\"uid\":$uid,\"username\":\"$username\",\"shell\":\"$shell\",\"home\":\"$home\"}")
            elif [ "$uid" -ge 1000 ]; then
                active_users+=("{\"uid\":$uid,\"username\":\"$username\",\"shell\":\"$shell\",\"home\":\"$home\"}")
            fi
        fi
    done < /etc/passwd
    
    # Подсчет системных и активных пользователей
    local sys_count=0
    local active_count=0
    for uid in "${!KNOWN_USERS[@]}"; do
        if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
            ((sys_count++))
        elif [ "$uid" -ge 1000 ]; then
            ((active_count++))
        fi
    done
    
    log_info "    Системных пользователей: $sys_count"
    log_info "    Активных пользователей: $active_count"
    
    # Выводим JSON
    local system_json=$(IFS=,; echo "${system_users[*]}")
    local active_json=$(IFS=,; echo "${active_users[*]}")
    output_json "{\"event\":\"users\",\"system\":[$system_json],\"active\":[$active_json]}"
}

# ============================================
# ЭТАП 2: Сеть (только для удаленных)
# ============================================
stage2_scan_network() {
    log_info "Этап 2/6: сканирование сети..."
    
    declare -g -A PORTS_BY_UID
    declare -g -A SOCKETS_BY_UID
    
    # Сканирование портов (TCP/UDP)
    if command -v ss &> /dev/null; then
        # Сохраняем вывод ss во временный файл для обработки
        local temp_ss=$(mktemp)
        ss -tulpn 2>/dev/null > "$temp_ss"
        
        while IFS= read -r line; do
            # Пропускаем заголовок
            [[ "$line" =~ ^Netid ]] && continue
            
            # Ищем PID в строке
            if [[ "$line" =~ pid=([0-9]+) ]]; then
                pid="${BASH_REMATCH[1]}"
                if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
                    uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null)
                    if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                        PORTS_BY_UID["$uid"]="${PORTS_BY_UID[$uid]}$line"$'\n'
                    fi
                fi
            fi
        done < "$temp_ss"
        rm -f "$temp_ss"
    fi
    
    # Сканирование Unix сокетов
    if command -v ss &> /dev/null; then
        local temp_sockets=$(mktemp)
        ss -x 2>/dev/null > "$temp_sockets"
        
        while IFS= read -r line; do
            [[ "$line" =~ ^Netid ]] && continue
            
            # Путь к сокету обычно в последнем поле
            path=$(echo "$line" | awk '{print $NF}')
            if [ -n "$path" ] && [ -e "$path" ]; then
                uid=$(stat -c %u "$path" 2>/dev/null)
                if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                    SOCKETS_BY_UID["$uid"]="${SOCKETS_BY_UID[$uid]}$path"$'\n'
                fi
            fi
        done < "$temp_sockets"
        rm -f "$temp_sockets"
    fi
    
    log_info "    Найдено удаленных с портами: ${#PORTS_BY_UID[@]}"
    log_info "    Найдено удаленных с сокетами: ${#SOCKETS_BY_UID[@]}"
    
    # Выводим JSON для портов
    for uid in "${!PORTS_BY_UID[@]}"; do
        output_json "{\"event\":\"ports\",\"uid\":$uid,\"data\":\"${PORTS_BY_UID[$uid]//\"/\\\"}\"}"
    done
    
    # Выводим JSON для сокетов
    for uid in "${!SOCKETS_BY_UID[@]}"; do
        output_json "{\"event\":\"sockets\",\"uid\":$uid,\"data\":\"${SOCKETS_BY_UID[$uid]//\"/\\\"}\"}"
    done
}

# ============================================
# ЭТАП 3: Процессы и сервисы (только для удаленных)
# ============================================
stage3_scan_processes() {
    log_info "Этап 3/6: сканирование процессов..."
    
    declare -g -A PROCESSES_BY_UID
    declare -g -A SERVICES_BY_UID
    
    # Сканирование процессов
    while IFS= read -r line; do
        # Пропускаем заголовок
        [[ "$line" =~ ^USER ]] && continue
        
        # Извлекаем пользователя и PID
        user=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        
        if [ -n "$user" ] && [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
            uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null)
            if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                PROCESSES_BY_UID["$uid"]="${PROCESSES_BY_UID[$uid]}$line"$'\n'
            fi
        fi
    done < <(ps aux 2>/dev/null)
    
    # Сканирование systemd сервисов
    for service_dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [ -d "$service_dir" ] || continue
        while IFS= read -r service_file; do
            [ -f "$service_file" ] || continue
            
            # Ищем директиву User=
            while IFS= read -r line; do
                if [[ "$line" =~ ^User=([a-zA-Z0-9_-]+) ]]; then
                    service_user="${BASH_REMATCH[1]}"
                    if [ -n "$service_user" ]; then
                        # Пытаемся получить UID пользователя
                        uid=$(id -u "$service_user" 2>/dev/null)
                        if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                            SERVICES_BY_UID["$uid"]="${SERVICES_BY_UID[$uid]}$service_file (User=$service_user)"$'\n'
                        fi
                    fi
                    break
                fi
            done < "$service_file"
        done < <(find "$service_dir" -name "*.service" -type f 2>/dev/null)
    done
    
    log_info "    Найдено удаленных с процессами: ${#PROCESSES_BY_UID[@]}"
    log_info "    Найдено удаленных с сервисами: ${#SERVICES_BY_UID[@]}"
    
    # Выводим JSON
    for uid in "${!PROCESSES_BY_UID[@]}"; do
        output_json "{\"event\":\"processes\",\"uid\":$uid,\"data\":\"${PROCESSES_BY_UID[$uid]//\"/\\\"}\"}"
    done
    
    for uid in "${!SERVICES_BY_UID[@]}"; do
        output_json "{\"event\":\"services\",\"uid\":$uid,\"data\":\"${SERVICES_BY_UID[$uid]//\"/\\\"}\"}"
    done
}

# ============================================
# ЭТАП 4: Задачи (только для удаленных)
# ============================================
stage4_scan_tasks() {
    log_info "Этап 4/6: сканирование задач..."
    
    declare -g -A CRON_BY_UID
    declare -g -A SYSTEMD_TIMERS_BY_UID
    declare -g -A AT_JOBS_BY_UID
    declare -g -A ANACRON_BY_UID
    
    # ========== CRON ЗАДАЧИ ==========
    log_info "    Поиск cron задач..."
    
    # 1. Пользовательские crontab (/var/spool/cron/crontabs/)
    if [ -d "/var/spool/cron/crontabs" ]; then
        while IFS= read -r cronfile; do
            if [ -f "$cronfile" ]; then
                uid=$(stat -c %u "$cronfile" 2>/dev/null)
                if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                    content=$(cat "$cronfile" 2>/dev/null | grep -v '^#' | grep -v '^$')
                    if [ -n "$content" ]; then
                        CRON_BY_UID["$uid"]="${CRON_BY_UID[$uid]}=== Пользовательский crontab: $cronfile ===\n$content\n"
                    fi
                fi
            fi
        done < <(find /var/spool/cron/crontabs -type f 2>/dev/null)
    fi
    
    # 2. Системные cron директории (/etc/cron.d/)
    if [ -d "/etc/cron.d" ]; then
        while IFS= read -r cronfile; do
            if [ -f "$cronfile" ]; then
                # Проверяем каждую строку на наличие пользователя
                while IFS= read -r line; do
                    [[ "$line" =~ ^# ]] && continue
                    [[ -z "$line" ]] && continue
                    
                    # Ищем имя пользователя в cron строке (обычно 6-е поле)
                    user=$(echo "$line" | awk '{print $6}' | grep -v '^[0-9*]')
                    if [ -n "$user" ]; then
                        uid=$(id -u "$user" 2>/dev/null)
                        if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                            CRON_BY_UID["$uid"]="${CRON_BY_UID[$uid]}=== Системный cron: $cronfile ===\n$line\n"
                        fi
                    fi
                done < "$cronfile"
            fi
        done < <(find /etc/cron.d -type f 2>/dev/null)
    fi
    
    # 3. Cron ежедневные/еженедельные/ежемесячные директории
    for period in hourly daily weekly monthly; do
        cron_dir="/etc/cron.$period"
        if [ -d "$cron_dir" ]; then
            while IFS= read -r script; do
                if [ -f "$script" ] && [ -x "$script" ]; then
                    uid=$(stat -c %u "$script" 2>/dev/null)
                    if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                        CRON_BY_UID["$uid"]="${CRON_BY_UID[$uid]}=== Cron $period скрипт: $script ===\n"
                    fi
                fi
            done < <(find "$cron_dir" -type f 2>/dev/null)
        fi
    done
    
    # 4. /etc/crontab
    if [ -f "/etc/crontab" ]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            [[ -z "$line" ]] && continue
            
            # Ищем имя пользователя в cron строке
            user=$(echo "$line" | awk '{print $6}' | grep -v '^[0-9*]')
            if [ -n "$user" ]; then
                uid=$(id -u "$user" 2>/dev/null)
                if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                    CRON_BY_UID["$uid"]="${CRON_BY_UID[$uid]}=== /etc/crontab ===\n$line\n"
                fi
            fi
        done < /etc/crontab 2>/dev/null
    fi
    
    # ========== SYSTEMD TIMERS ==========
    log_info "    Поиск systemd таймеров..."
    
    for timer_dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [ -d "$timer_dir" ] || continue
        while IFS= read -r timer_file; do
            [ -f "$timer_file" ] || continue
            
            # Проверяем владельца файла таймера
            uid=$(stat -c %u "$timer_file" 2>/dev/null)
            if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                timer_name=$(basename "$timer_file" .timer)
                
                # Ищем связанный сервис
                service_file="${timer_dir}/${timer_name}.service"
                if [ -f "$service_file" ]; then
                    # Проверяем User= в сервисе
                    service_user=$(grep -i "^User=" "$service_file" 2>/dev/null | head -1 | cut -d= -f2)
                    if [ -n "$service_user" ]; then
                        service_uid=$(id -u "$service_user" 2>/dev/null)
                        if [ -n "$service_uid" ] && [ "$service_uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$service_uid]}" ]; then
                            SYSTEMD_TIMERS_BY_UID["$service_uid"]="${SYSTEMD_TIMERS_BY_UID[$service_uid]}=== Таймер: $timer_file ===\n  Сервис: $service_file (User=$service_user)\n"
                        fi
                    fi
                fi
            fi
            
            # Также проверяем содержимое таймера на наличие User=
            while IFS= read -r line; do
                if [[ "$line" =~ ^User=([a-zA-Z0-9_-]+) ]]; then
                    service_user="${BASH_REMATCH[1]}"
                    service_uid=$(id -u "$service_user" 2>/dev/null)
                    if [ -n "$service_uid" ] && [ "$service_uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$service_uid]}" ]; then
                        SYSTEMD_TIMERS_BY_UID["$service_uid"]="${SYSTEMD_TIMERS_BY_UID[$service_uid]}=== Таймер с User=: $timer_file ===\n  $line\n"
                    fi
                    break
                fi
            done < "$timer_file"
            
        done < <(find "$timer_dir" -name "*.timer" -type f 2>/dev/null)
    done
    
    # ========== SYSTEMD UNITS WITH TIMERS ==========
    # Проверяем все юниты на наличие OnCalendar или подобных директив
    for unit_dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [ -d "$unit_dir" ] || continue
        while IFS= read -r unit_file; do
            [ -f "$unit_file" ] || continue
            
            # Ищем временные директивы в юните
            if grep -q -E "OnCalendar|OnBootSec|OnUnitActiveSec|OnStartupSec" "$unit_file" 2>/dev/null; then
                uid=$(stat -c %u "$unit_file" 2>/dev/null)
                if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                    SYSTEMD_TIMERS_BY_UID["$uid"]="${SYSTEMD_TIMERS_BY_UID[$uid]}=== Юнит с таймером: $unit_file ===\n"
                    # Добавляем строки с таймерами
                    grep -E "OnCalendar|OnBootSec|OnUnitActiveSec|OnStartupSec" "$unit_file" 2>/dev/null | while read -r timer_line; do
                        SYSTEMD_TIMERS_BY_UID["$uid"]="${SYSTEMD_TIMERS_BY_UID[$uid]}  $timer_line\n"
                    done
                fi
            fi
        done < <(find "$unit_dir" -name "*.service" -o -name "*.timer" -type f 2>/dev/null)
    done
    
    # ========== AT JOBS ==========
    log_info "    Поиск at задач..."
    
    # at задачи обычно в /var/spool/at/ или /var/spool/cron/atjobs/
    for at_dir in /var/spool/at /var/spool/cron/atjobs; do
        if [ -d "$at_dir" ]; then
            while IFS= read -r atjob; do
                if [ -f "$atjob" ] && [[ ! "$atjob" =~ \.seq$ ]]; then
                    uid=$(stat -c %u "$atjob" 2>/dev/null)
                    if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                        # Читаем первые несколько строк at задачи
                        AT_JOBS_BY_UID["$uid"]="${AT_JOBS_BY_UID[$uid]}=== At job: $atjob ===\n"
                        head -5 "$atjob" 2>/dev/null | while read -r line; do
                            AT_JOBS_BY_UID["$uid"]="${AT_JOBS_BY_UID[$uid]}  $line\n"
                        done
                    fi
                fi
            done < <(find "$at_dir" -type f 2>/dev/null)
        fi
    done
    
    # ========== ANACRON ==========
    log_info "    Поиск anacron задач..."
    
    if [ -f "/etc/anacrontab" ]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            [[ -z "$line" ]] && continue
            
            # Anacron формат: период задержка идентификатор команда
            if [[ "$line" =~ ^[0-9] ]]; then
                # Проверяем владельца файла anacrontab
                uid=$(stat -c %u "/etc/anacrontab" 2>/dev/null)
                if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                    ANACRON_BY_UID["$uid"]="${ANACRON_BY_UID[$uid]}=== /etc/anacrontab ===\n$line\n"
                fi
            fi
        done < /etc/anacrontab 2>/dev/null
    fi
    
    # Anacron spool directory
    if [ -d "/var/spool/anacron" ]; then
        while IFS= read -r anacron_file; do
            if [ -f "$anacron_file" ]; then
                uid=$(stat -c %u "$anacron_file" 2>/dev/null)
                if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                    ANACRON_BY_UID["$uid"]="${ANACRON_BY_UID[$uid]}=== Anacron spool: $anacron_file ===\n"
                    cat "$anacron_file" 2>/dev/null | while read -r line; do
                        ANACRON_BY_UID["$uid"]="${ANACRON_BY_UID[$uid]}  $line\n"
                    done
                fi
            fi
        done < <(find /var/spool/anacron -type f 2>/dev/null)
    fi
    
    log_info "    Найдено удаленных с cron: ${#CRON_BY_UID[@]}"
    log_info "    Найдено удаленных с systemd таймерами: ${#SYSTEMD_TIMERS_BY_UID[@]}"
    log_info "    Найдено удаленных с at jobs: ${#AT_JOBS_BY_UID[@]}"
    log_info "    Найдено удаленных с anacron: ${#ANACRON_BY_UID[@]}"
    
    # Выводим JSON
    for uid in "${!CRON_BY_UID[@]}"; do
        output_json "{\"event\":\"cron\",\"uid\":$uid,\"data\":\"${CRON_BY_UID[$uid]//\"/\\\"}\"}"
    done
    
    for uid in "${!SYSTEMD_TIMERS_BY_UID[@]}"; do
        output_json "{\"event\":\"timers\",\"uid\":$uid,\"data\":\"${SYSTEMD_TIMERS_BY_UID[$uid]//\"/\\\"}\"}"
    done
}

# ============================================
# ФУНКЦИЯ ВЫЧИСЛЕНИЯ ХЭШЕЙ
# ============================================
calculate_file_hashes() {
    local file_path="$1"
    local md5=""
    local sha256=""
    
    if [ -f "$file_path" ]; then
        if command -v md5sum &> /dev/null; then
            md5=$(md5sum "$file_path" 2>/dev/null | cut -d' ' -f1)
        fi
        if command -v sha256sum &> /dev/null; then
            sha256=$(sha256sum "$file_path" 2>/dev/null | cut -d' ' -f1)
        fi
    fi
    
    echo "{\"md5\":\"$md5\",\"sha256\":\"$sha256\"}"
}

# ============================================
# ЭТАП 5: Файловая система (с хэшами)
# ============================================
stage5_scan_filesystem() {
    log_info "Этап 5/6: сканирование файловой системы..."
    
    declare -g -A FILES_BY_UID
    
    local total=0
    local found=0
    local start_time=$(date +%s)
    
    # Сначала подсчитаем примерное количество файлов
    log_info "    Подсчет общего количества файлов..."
    local total_files=$(find / \( -path /proc -o -path /sys \) -prune -o -print 2>/dev/null | wc -l)
    log_info "    Всего объектов для сканирования: $total_files"
    
    echo "PROGRESS:0/$total_files/0"
    
    # Проходим по всем файлам и обрабатываем
    while IFS= read -r item; do
        [ -z "$item" ] && continue
        
        # Получаем UID владельца
        uid=$(stat -c %u "$item" 2>/dev/null)
        if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
            # Получаем информацию о файле
            perms=$(stat -c %A "$item" 2>/dev/null)
            size=$(stat -c %s "$item" 2>/dev/null)
            mtime=$(stat -c %Y "$item" 2>/dev/null)
            
            # Вычисляем хэши
            hashes=$(calculate_file_hashes "$item")
            
            # Сохраняем с хэшами
            FILES_BY_UID["$uid"]="${FILES_BY_UID[$uid]}{\"path\":\"$item\",\"permissions\":\"$perms\",\"size\":$size,\"mtime\":$mtime,\"hashes\":$hashes},"
            ((found++))
        fi
        
        ((total++))
        
        if [ $((total % 100)) -eq 0 ]; then
            echo "PROGRESS:$total/$total_files/$found"
        fi
    done < <(find / \( -path /proc -o -path /sys \) -prune -o -print 2>/dev/null)
    
    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))
    
    echo "PROGRESS:$total/$total_files/$found"
    log_info "    ✅ Сканирование завершено за ${total_time}с"
    log_info "       Найдено удаленных пользователей с файлами: ${#FILES_BY_UID[@]}"
    
    # Выводим JSON с хэшами
    for uid in "${!FILES_BY_UID[@]}"; do
        local files_json="[${FILES_BY_UID[$uid]%?}]"
        output_json "{\"event\":\"files\",\"uid\":$uid,\"files\":$files_json}"
    done
}

# ============================================
# ЭТАП 6: Логи и история (только для удаленных)
# ============================================
stage6_analyze_logs() {
    log_info "Этап 6/6: сканирование логов и истории..."
    
    declare -g -A LOGS_BY_UID
    declare -g -A HISTORY_BY_UID
    
    # Паттерны для поиска в логах
    local patterns=(
        # Создание/удаление пользователей
        "useradd"
        "userdel"
        "groupadd"
        "groupdel"
        "new user"
        "remove user"
        "delete user"
        "added user"
        "removed user"
        "account added"
        "account removed"
        
        # Вход/выход
        "login"
        "logout"
        "session opened"
        "session closed"
        "sshd"
        "Accepted"
        "Failed"
        "authentication failure"
        "invalid user"
        "pam_unix"
        "su:"
        "sudo:"
        
        # Привилегии
        "sudo"
        "su"
        "root"
        "COMMAND="
        
        # Системные события
        "cron"
        "systemd"
        "start"
        "stop"
        "enabled"
        "disabled"
        "Started"
        "Stopped"
        
        # UID упоминания
        "UID="
        "uid="
        "_UID="
    )
    
    # Сканирование лог-файлов
    log_info "    Поиск в /var/log/*.log ..."
    
    local log_count=0
    while IFS= read -r logfile; do
        # Читаем последние 1000 строк
        while read -r line; do
            # Проверяем по паттернам
            for pattern in "${patterns[@]}"; do
                if [[ "$line" == *"$pattern"* ]]; then
                    # Ищем UID в строке
                    uid=""
                    if [[ "$line" =~ UID=([0-9]+) ]] || [[ "$line" =~ uid=([0-9]+) ]] || [[ "$line" =~ _UID=([0-9]+) ]]; then
                        uid="${BASH_REMATCH[1]}"
                    fi
                    
                    if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                        LOGS_BY_UID["$uid"]="${LOGS_BY_UID[$uid]}[$(basename "$logfile")] $line"$'\n'
                    fi
                    break
                fi
            done
        done < <(tail -1000 "$logfile" 2>/dev/null)
        
        ((log_count++))
    done < <(find /var/log -name "*.log" -type f 2>/dev/null | head -50)
    
    # Сканирование journalctl
    if command -v journalctl &> /dev/null; then
        log_info "    Поиск в journalctl (последние 5000 строк)..."
        
        while read -r line; do
            for pattern in "${patterns[@]}"; do
                if [[ "$line" == *"$pattern"* ]]; then
                    # Ищем UID
                    uid=""
                    if [[ "$line" =~ UID=([0-9]+) ]] || [[ "$line" =~ uid=([0-9]+) ]] || [[ "$line" =~ _UID=([0-9]+) ]]; then
                        uid="${BASH_REMATCH[1]}"
                    fi
                    
                    if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                        LOGS_BY_UID["$uid"]="${LOGS_BY_UID[$uid]}[journal] $line"$'\n'
                    fi
                    break
                fi
            done
        done < <(journalctl -n 5000 2>/dev/null)
    fi
    
    # Сканирование истории команд
    log_info "    Поиск в истории команд..."
    
    # История из домашних директорий
    while IFS= read -r user_home; do
        [ -d "$user_home" ] || continue
        
        # Проверяем .bash_history
        for hist_file in "$user_home/.bash_history" "$user_home/.zsh_history" "$user_home/.history"; do
            if [ -f "$hist_file" ]; then
                uid=$(stat -c %u "$hist_file" 2>/dev/null)
                if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                    username=$(basename "$user_home")
                    HISTORY_BY_UID["$uid"]="${HISTORY_BY_UID[$uid]}=== $username ($hist_file) ===\n"
                    
                    # Читаем последние 100 строк и добавляем их
                    local hist_lines=0
                    while read -r cmd; do
                        if [ -n "$cmd" ]; then
                            HISTORY_BY_UID["$uid"]="${HISTORY_BY_UID[$uid]}  $cmd\n"
                            ((hist_lines++))
                        fi
                    done < <(tail -100 "$hist_file" 2>/dev/null)
                    
                    # Если строк не нашлось, добавляем пометку
                    if [ $hist_lines -eq 0 ]; then
                        HISTORY_BY_UID["$uid"]="${HISTORY_BY_UID[$uid]}  (история пуста)\n"
                    fi
                fi
            fi
        done
    done < <(find /home -maxdepth 1 -type d 2>/dev/null)
    
    # История root
    if [ -f "/root/.bash_history" ]; then
        uid=0
        if [ -z "${KNOWN_USERS[$uid]}" ]; then
            HISTORY_BY_UID["$uid"]="${HISTORY_BY_UID[$uid]}=== root (/root/.bash_history) ===\n"
            
            local hist_lines=0
            while read -r cmd; do
                if [ -n "$cmd" ]; then
                    HISTORY_BY_UID["$uid"]="${HISTORY_BY_UID[$uid]}  $cmd\n"
                    ((hist_lines++))
                fi
            done < <(tail -100 "/root/.bash_history" 2>/dev/null)
            
            if [ $hist_lines -eq 0 ]; then
                HISTORY_BY_UID["$uid"]="${HISTORY_BY_UID[$uid]}  (история пуста)\n"
            fi
        fi
    fi
    
    log_info "    Найдено удаленных пользователей в логах: ${#LOGS_BY_UID[@]}"
    log_info "    Найдено удаленных пользователей с историей: ${#HISTORY_BY_UID[@]}"
    
    # Выводим JSON
    for uid in "${!LOGS_BY_UID[@]}"; do
        output_json "{\"event\":\"logs\",\"uid\":$uid,\"data\":\"${LOGS_BY_UID[$uid]//\"/\\\"}\"}"
    done
    
    for uid in "${!HISTORY_BY_UID[@]}"; do
        output_json "{\"event\":\"history\",\"uid\":$uid,\"data\":\"${HISTORY_BY_UID[$uid]//\"/\\\"}\"}"
    done
}

# ============================================
# ФИНАЛЬНЫЙ ВЫВОД
# ============================================
final_summary() {
    log_info "Формирование итогового отчета..."
    
    # Собираем всех удаленных пользователей
    declare -A DELETED_UIDS
    for uid in "${!PORTS_BY_UID[@]}" "${!SOCKETS_BY_UID[@]}" "${!PROCESSES_BY_UID[@]}" \
               "${!CRON_BY_UID[@]}" "${!SERVICES_BY_UID[@]}" "${!SYSTEMD_TIMERS_BY_UID[@]}" \
               "${!AT_JOBS_BY_UID[@]}" "${!FILES_BY_UID[@]}" "${!LOGS_BY_UID[@]}" "${!HISTORY_BY_UID[@]}"; do
        DELETED_UIDS["$uid"]=1
    done
    
    # Формируем массив UID для JSON
    local uids_json=""
    for uid in "${!DELETED_UIDS[@]}"; do
        if [ -n "$uids_json" ]; then
            uids_json="$uids_json,"
        fi
        uids_json="$uids_json$uid"
    done
    
    output_json "{\"event\":\"scan_complete\",\"duration\":$SECONDS,\"deleted_users\":[${uids_json}],\"deleted_count\":${#DELETED_UIDS[@]}}"
}

# ============================================
# ОСНОВНАЯ ПРОГРАММА
# ============================================
main() {
    log_info "========================================="
    log_info "FORENSIC ANALYZER - ПОИСК АРТЕФАКТОВ"
    log_info "========================================="
    
    # Проверка root (bash скрипт должен запускаться от root)
    if [ "$EUID" -ne 0 ]; then
        log_error "Скрипт требует root прав"
        exit 1
    fi
    
    stage1_collect_users
    stage2_scan_network
    stage3_scan_processes
    stage4_scan_tasks
    stage5_scan_filesystem
    stage6_analyze_logs
    final_summary
    
    log_info "✅ Сканирование завершено"
}

main "$@"