#!/bin/bash
# find_user_artifacts.sh - Поиск артефактов удаленных пользователей

# ============================================
# НАСТРОЙКИ
# ============================================
log_info() {
    echo "[INFO] $1" >&2
}

log_error() {
    echo "[ERROR] $1" >&2
}

output_json() {
    echo "$1"
}

progress_update() {
    local current=$1
    local total=$2
    local found=$3
    echo "PROGRESS:$current:$total:$found"
}

output_json "{\"event\":\"scan_start\",\"timestamp\":\"$(date -Iseconds)\"}"
log_info "========================================="
log_info "ЗАПУСК СКАНИРОВАНИЯ"
log_info "========================================="

# ============================================
# ЭТАП 1: Пользователи из /etc/passwd
# ============================================
stage1_collect_users() {
    log_info "Этап 1/6: сбор пользователей..."
    
    declare -g -A KNOWN_USERS
    declare -g -A USER_SHELL
    declare -g -A USER_HOME
    
    local system_users=()
    local active_users=()
    
    while IFS=: read -r username passwd uid gid comment home shell; do
        if [ -n "$uid" ]; then
            KNOWN_USERS["$uid"]="$username"
            USER_SHELL["$uid"]="$shell"
            USER_HOME["$uid"]="$home"
            
            if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
                system_users+=("{\"uid\":$uid,\"username\":\"$username\",\"shell\":\"$shell\",\"home\":\"$home\"}")
            elif [ "$uid" -ge 1000 ]; then
                active_users+=("{\"uid\":$uid,\"username\":\"$username\",\"shell\":\"$shell\",\"home\":\"$home\"}")
            fi
        fi
    done < /etc/passwd
    
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
    
    local system_json=$(IFS=,; echo "${system_users[*]}")
    local active_json=$(IFS=,; echo "${active_users[*]}")
    output_json "{\"event\":\"users\",\"system\":[$system_json],\"active\":[$active_json]}"
}

# ============================================
# ЭТАП 2: Сеть
# ============================================
stage2_scan_network() {
    log_info "Этап 2/6: сканирование сети..."
    
    declare -g -A PORTS_BY_UID
    declare -g -A SOCKETS_BY_UID
    
    if command -v ss &> /dev/null; then
        local temp_ss=$(mktemp)
        ss -tulpn 2>/dev/null > "$temp_ss"
        
        while IFS= read -r line; do
            [[ "$line" =~ ^Netid ]] && continue
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
        
        local temp_sockets=$(mktemp)
        ss -x 2>/dev/null > "$temp_sockets"
        
        while IFS= read -r line; do
            [[ "$line" =~ ^Netid ]] && continue
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
    
    for uid in "${!PORTS_BY_UID[@]}"; do
        output_json "{\"event\":\"ports\",\"uid\":$uid,\"data\":\"${PORTS_BY_UID[$uid]//\"/\\\"}\"}"
    done
    
    for uid in "${!SOCKETS_BY_UID[@]}"; do
        output_json "{\"event\":\"sockets\",\"uid\":$uid,\"data\":\"${SOCKETS_BY_UID[$uid]//\"/\\\"}\"}"
    done
}

# ============================================
# ЭТАП 3: Процессы
# ============================================
stage3_scan_processes() {
    log_info "Этап 3/6: сканирование процессов..."
    
    declare -g -A PROCESSES_BY_UID
    declare -g -A SERVICES_BY_UID
    
    while IFS= read -r line; do
        [[ "$line" =~ ^USER ]] && continue
        pid=$(echo "$line" | awk '{print $2}')
        if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
            uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null)
            if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                PROCESSES_BY_UID["$uid"]="${PROCESSES_BY_UID[$uid]}$line"$'\n'
            fi
        fi
    done < <(ps aux 2>/dev/null)
    
    for service_dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [ -d "$service_dir" ] || continue
        while IFS= read -r service_file; do
            [ -f "$service_file" ] || continue
            while IFS= read -r line; do
                if [[ "$line" =~ ^User=([a-zA-Z0-9_-]+) ]]; then
                    service_user="${BASH_REMATCH[1]}"
                    uid=$(id -u "$service_user" 2>/dev/null)
                    if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                        SERVICES_BY_UID["$uid"]="${SERVICES_BY_UID[$uid]}$service_file (User=$service_user)"$'\n'
                    fi
                    break
                fi
            done < "$service_file"
        done < <(find "$service_dir" -name "*.service" -type f 2>/dev/null)
    done
    
    log_info "    Найдено удаленных с процессами: ${#PROCESSES_BY_UID[@]}"
    log_info "    Найдено удаленных с сервисами: ${#SERVICES_BY_UID[@]}"
    
    for uid in "${!PROCESSES_BY_UID[@]}"; do
        output_json "{\"event\":\"processes\",\"uid\":$uid,\"data\":\"${PROCESSES_BY_UID[$uid]//\"/\\\"}\"}"
    done
    
    for uid in "${!SERVICES_BY_UID[@]}"; do
        output_json "{\"event\":\"services\",\"uid\":$uid,\"data\":\"${SERVICES_BY_UID[$uid]//\"/\\\"}\"}"
    done
}

# ============================================
# ЭТАП 4: Задачи
# ============================================
stage4_scan_tasks() {
    log_info "Этап 4/6: сканирование задач..."
    
    declare -g -A CRON_BY_UID
    declare -g -A SYSTEMD_TIMERS_BY_UID
    
    log_info "    Поиск cron задач..."
    
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
    
    if [ -d "/etc/cron.d" ]; then
        while IFS= read -r cronfile; do
            if [ -f "$cronfile" ]; then
                while IFS= read -r line; do
                    [[ "$line" =~ ^# ]] && continue
                    [[ -z "$line" ]] && continue
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
    
    log_info "    Поиск systemd таймеров..."
    
    for timer_dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [ -d "$timer_dir" ] || continue
        while IFS= read -r timer_file; do
            [ -f "$timer_file" ] || continue
            uid=$(stat -c %u "$timer_file" 2>/dev/null)
            if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                SYSTEMD_TIMERS_BY_UID["$uid"]="${SYSTEMD_TIMERS_BY_UID[$uid]}=== Таймер: $timer_file ===\n"
            fi
        done < <(find "$timer_dir" -name "*.timer" -type f 2>/dev/null)
    done
    
    log_info "    Найдено удаленных с cron: ${#CRON_BY_UID[@]}"
    log_info "    Найдено удаленных с таймерами: ${#SYSTEMD_TIMERS_BY_UID[@]}"
    
    for uid in "${!CRON_BY_UID[@]}"; do
        output_json "{\"event\":\"cron\",\"uid\":$uid,\"data\":\"${CRON_BY_UID[$uid]//\"/\\\"}\"}"
    done
    
    for uid in "${!SYSTEMD_TIMERS_BY_UID[@]}"; do
        output_json "{\"event\":\"timers\",\"uid\":$uid,\"data\":\"${SYSTEMD_TIMERS_BY_UID[$uid]//\"/\\\"}\"}"
    done
}

# ============================================
# ФУНКЦИЯ ХЭШЕЙ
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
# ЭТАП 5: Файловая система
# ============================================
stage5_scan_filesystem() {
    log_info "Этап 5/6: сканирование файловой системы..."
    
    declare -g -A FILES_BY_UID
    
    local total=0
    local found=0
    local start_time=$(date +%s)
    
    log_info "    Подсчет общего количества файлов..."
    local total_files=$(find / \( -path /proc -o -path /sys \) -prune -o -print 2>/dev/null | wc -l)
    log_info "    Всего файлов для сканирования: $total_files"
    
    progress_update 0 $total_files 0
    
    while IFS= read -r item; do
        [ -z "$item" ] && continue
        
        uid=$(stat -c %u "$item" 2>/dev/null)
        if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
            perms=$(stat -c %A "$item" 2>/dev/null)
            size=$(stat -c %s "$item" 2>/dev/null)
            mtime=$(stat -c %Y "$item" 2>/dev/null)
            hashes=$(calculate_file_hashes "$item")
            
            if [ -n "${FILES_BY_UID[$uid]}" ]; then
                FILES_BY_UID["$uid"]="${FILES_BY_UID[$uid]},{\"path\":\"$item\",\"permissions\":\"$perms\",\"size\":$size,\"mtime\":$mtime,\"hashes\":$hashes}"
            else
                FILES_BY_UID["$uid"]="{\"path\":\"$item\",\"permissions\":\"$perms\",\"size\":$size,\"mtime\":$mtime,\"hashes\":$hashes}"
            fi
            ((found++))
        fi
        
        ((total++))
        
        if [ $((total % 100)) -eq 0 ]; then
            progress_update $total $total_files $found
        fi
    done < <(find / \( -path /proc -o -path /sys \) -prune -o -print 2>/dev/null)
    
    progress_update $total $total_files $found
    
    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))
    
    log_info "    Сканирование завершено за ${total_time}с"
    log_info "    Найдено файлов удаленных пользователей: $found"
    log_info "    Найдено удаленных пользователей с файлами: ${#FILES_BY_UID[@]}"
    
    for uid in "${!FILES_BY_UID[@]}"; do
        local files_json="[${FILES_BY_UID[$uid]}]"
        output_json "{\"event\":\"files\",\"uid\":$uid,\"files\":$files_json}"
    done
}

# ============================================
# ЭТАП 6: Логи
# ============================================
stage6_analyze_logs() {
    log_info "Этап 6/6: сканирование логов и истории..."
    
    declare -g -A LOGS_BY_UID
    declare -g -A HISTORY_BY_UID
    
    local patterns=(
        "useradd" "userdel" "groupadd" "groupdel"
        "login" "logout" "sshd" "Accepted" "Failed"
        "sudo" "su" "root" "COMMAND="
        "cron" "systemd"
        "UID=" "uid="
    )
    
    log_info "    Поиск в /var/log/*.log ..."
    
    while IFS= read -r logfile; do
        while read -r line; do
            for pattern in "${patterns[@]}"; do
                if [[ "$line" == *"$pattern"* ]]; then
                    uid=""
                    if [[ "$line" =~ UID=([0-9]+) ]] || [[ "$line" =~ uid=([0-9]+) ]]; then
                        uid="${BASH_REMATCH[1]}"
                    fi
                    if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                        LOGS_BY_UID["$uid"]="${LOGS_BY_UID[$uid]}[$(basename "$logfile")] $line"$'\n'
                    fi
                    break
                fi
            done
        done < <(tail -1000 "$logfile" 2>/dev/null)
    done < <(find /var/log -name "*.log" -type f 2>/dev/null | head -50)
    
    log_info "    Поиск в истории команд..."
    
    while IFS= read -r user_home; do
        [ -d "$user_home" ] || continue
        for hist_file in "$user_home/.bash_history" "$user_home/.zsh_history" "$user_home/.history"; do
            if [ -f "$hist_file" ]; then
                uid=$(stat -c %u "$hist_file" 2>/dev/null)
                if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ -z "${KNOWN_USERS[$uid]}" ]; then
                    username=$(basename "$user_home")
                    HISTORY_BY_UID["$uid"]="${HISTORY_BY_UID[$uid]}=== $username ($hist_file) ===\n"
                    while read -r cmd; do
                        if [ -n "$cmd" ]; then
                            HISTORY_BY_UID["$uid"]="${HISTORY_BY_UID[$uid]}  $cmd\n"
                        fi
                    done < <(tail -100 "$hist_file" 2>/dev/null)
                fi
            fi
        done
    done < <(find /home -maxdepth 1 -type d 2>/dev/null)
    
    log_info "    Найдено удаленных пользователей в логах: ${#LOGS_BY_UID[@]}"
    log_info "    Найдено удаленных пользователей с историей: ${#HISTORY_BY_UID[@]}"
    
    for uid in "${!LOGS_BY_UID[@]}"; do
        output_json "{\"event\":\"logs\",\"uid\":$uid,\"data\":\"${LOGS_BY_UID[$uid]//\"/\\\"}\"}"
    done
    
    for uid in "${!HISTORY_BY_UID[@]}"; do
        output_json "{\"event\":\"history\",\"uid\":$uid,\"data\":\"${HISTORY_BY_UID[$uid]//\"/\\\"}\"}"
    done
}

# ============================================
# ФИНАЛЬНЫЙ ОТЧЕТ
# ============================================
final_summary() {
    log_info "Формирование итогового отчета..."
    
    declare -A DELETED_UIDS
    
    for uid in "${!PORTS_BY_UID[@]}"; do DELETED_UIDS["$uid"]=1; done
    for uid in "${!SOCKETS_BY_UID[@]}"; do DELETED_UIDS["$uid"]=1; done
    for uid in "${!PROCESSES_BY_UID[@]}"; do DELETED_UIDS["$uid"]=1; done
    for uid in "${!CRON_BY_UID[@]}"; do DELETED_UIDS["$uid"]=1; done
    for uid in "${!SERVICES_BY_UID[@]}"; do DELETED_UIDS["$uid"]=1; done
    for uid in "${!SYSTEMD_TIMERS_BY_UID[@]}"; do DELETED_UIDS["$uid"]=1; done
    for uid in "${!FILES_BY_UID[@]}"; do DELETED_UIDS["$uid"]=1; done
    for uid in "${!LOGS_BY_UID[@]}"; do DELETED_UIDS["$uid"]=1; done
    for uid in "${!HISTORY_BY_UID[@]}"; do DELETED_UIDS["$uid"]=1; done
    
    local uids_json=""
    local uid_list=()
    for uid in "${!DELETED_UIDS[@]}"; do
        uid_list+=($uid)
    done
    
    IFS=$'\n' uid_list=($(sort -n <<<"${uid_list[*]}"))
    unset IFS
    
    for uid in "${uid_list[@]}"; do
        if [ -n "$uids_json" ]; then
            uids_json="$uids_json,$uid"
        else
            uids_json="$uid"
        fi
    done
    
    log_info "Всего найдено удаленных пользователей: ${#DELETED_UIDS[@]}"
    log_info "   UID: ${uid_list[*]}"
    
    output_json "{\"event\":\"scan_complete\",\"duration\":$SECONDS,\"deleted_users\":[${uids_json}],\"deleted_count\":${#DELETED_UIDS[@]}}"
}

# ============================================
# ОСНОВНАЯ ПРОГРАММА
# ============================================
main() {
    if [ "$EUID" -ne 0 ]; then
        echo "[ERROR] Скрипт требует root прав" >&2
        exit 1
    fi
    
    stage1_collect_users
    stage2_scan_network
    stage3_scan_processes
    stage4_scan_tasks
    stage5_scan_filesystem
    stage6_analyze_logs
    final_summary
}

main "$@"