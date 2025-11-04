#!/bin/bash

# ============================================================================
# Linux 进程检测脚本 v2.1
# ============================================================================
# 功能: 检测恶意进程、rootkit、后门和可疑活动
# 作者: Security Team
# 版本: 2.1
# ============================================================================

# set -e  # 已注释：严格模式会导致遇到小错误时脚本直接退出
# set -o pipefail  # 已注释：允许管道中的某些命令失败

# ============================================================================
# 安全策略：仅检测，不修改系统
# 说明：
#   1. 仅读取检测，不修改任何系统文件或配置
#   2. 不修改环境变量（避免影响业务系统）
#   3. 使用 --busybox 选项指定静态 busybox 路径（推荐）
#   4. 所有检测命令通过 $CMD_XX 变量调用
#   5. 静态 busybox 完全不受 LD_PRELOAD 影响
#   6. 所有操作都是只读的（grep、cat、readlink、stat 等）
# ============================================================================

# ============================================================================
# 全局变量
# ============================================================================
DAYS_THRESHOLD=7
CUSTOM_DATE=""
BASELINE_TIMESTAMP=0
OUTPUT_FILE=""

# Busybox 支持（安全增强：防止系统命令被篡改）
BUSYBOX_PATH=""
USE_BUSYBOX=0

# 静默模式（抑制LD_PRELOAD错误信息）
QUIET_MODE=0

# ============================================================================
# 参数解析
# ============================================================================
show_help() {
    echo "Linux 进程检测脚本 v2.1"
    echo ""
    echo "说明: 本脚本仅执行只读检测，不会修改系统任何文件或配置"
    echo ""
    echo "用法: $0 [选项] [输出文件]"
    echo ""
    echo "选项:"
    echo "  --days N            检测最近 N 天修改的文件（默认：7天）"
    echo "  --since DATE        检测指定日期之后修改的文件（格式：YYYY-MM-DD）"
    echo "  --busybox <路径>    指定 busybox 路径，使用 busybox 中的命令进行检测"
    echo "                      (防止攻击者替换系统命令)"
    echo "  --quiet, -q         静默模式：抑制 LD_PRELOAD 错误信息（仅在使用busybox时）"
    echo "                      注意：此模式会重定向stderr，可能影响其他错误输出"
    echo "  --help, -h          显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0                                 # 检测最近7天（默认）"
    echo "  $0 --days 30                       # 检测最近30天修改的文件"
    echo "  $0 --since 2025-05-01              # 检测2025年5月1日之后修改的文件"
    echo "  $0 --since 2025-05-15 output.txt   # 事件发生在5月，结果保存到文件"
    echo "  $0 --busybox /bin/busybox          # 使用 busybox 命令进行检测"
    echo "  $0 --busybox /bin/busybox --quiet  # 使用 busybox + 静默模式"
    echo "  $0 --days 30 --busybox /bin/busybox # 组合使用"
    echo ""
    echo "典型场景:"
    echo "  * 日常巡检：--days 7"
    echo "  * 月度审计：--days 30"
    echo "  * 事件溯源：--since 2025-05-01（事件发生日期）"
    echo "  * 应急响应：--since 2025-05-15 --busybox /bin/busybox"
    echo ""
    exit 0
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        --days)
            if [ -z "$2" ] || [[ "$2" == --* ]]; then
                echo "[错误] --days 选项需要指定天数"
                echo "用法: $0 --days N"
                exit 1
            fi
            DAYS_THRESHOLD="$2"
            # 验证是否为数字
            if ! [[ "$DAYS_THRESHOLD" =~ ^[0-9]+$ ]]; then
                echo "[错误] --days 参数必须是正整数: $DAYS_THRESHOLD"
                exit 1
            fi
            shift 2
            ;;
        --since)
            if [ -z "$2" ] || [[ "$2" == --* ]]; then
                echo "[错误] --since 选项需要指定日期"
                echo "用法: $0 --since YYYY-MM-DD"
                exit 1
            fi
            CUSTOM_DATE="$2"
            # 验证日期格式
            if ! [[ "$CUSTOM_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
                echo "[错误] 日期格式错误，请使用 YYYY-MM-DD 格式: $CUSTOM_DATE"
                exit 1
            fi
            shift 2
            ;;
        --busybox)
            if [ -z "$2" ] || [[ "$2" == --* ]]; then
                echo "[错误] --busybox 选项需要指定路径"
                echo "用法: $0 --busybox /path/to/busybox"
                exit 1
            fi
            BUSYBOX_PATH="$2"
            if [ ! -f "$BUSYBOX_PATH" ]; then
                echo "[错误] busybox 文件不存在: $BUSYBOX_PATH"
                exit 1
            fi
            if [ ! -x "$BUSYBOX_PATH" ]; then
                echo "[错误] busybox 文件不可执行: $BUSYBOX_PATH"
                exit 1
            fi
            USE_BUSYBOX=1
            
            # 检查 Busybox 是否静态编译
            echo "[提示] 已启用 Busybox 模式: $BUSYBOX_PATH"
            if command -v ldd &>/dev/null; then
                LDD_OUTPUT=$(ldd "$BUSYBOX_PATH" 2>&1)
                if echo "$LDD_OUTPUT" | grep -q "not a dynamic executable\|statically linked"; then
                    echo "[✓] Busybox 是静态编译的，完全不受 LD_PRELOAD 影响"
                    
                    # 检测系统是否被 LD_PRELOAD 劫持
                    if [ -f /etc/ld.so.preload ]; then
                        echo ""
                        echo "╔════════════════════════════════════════════════════════════════════════════╗"
                        echo "║ [重要说明] 系统 LD_PRELOAD 劫持检测                                       ║"
                        echo "╠════════════════════════════════════════════════════════════════════════════╣"
                        echo "║ 检测到: /etc/ld.so.preload                                                ║"
                        echo "║ 内容: $(cat /etc/ld.so.preload 2>/dev/null | head -1)"
                        echo "║                                                                            ║"
                        echo "║ [✓] 静态 Busybox 完全不受影响                                             ║"
                        echo "║ [✓] 所有检测功能正常运行                                                  ║"
                        echo "║                                                                            ║"
                        if [ $QUIET_MODE -eq 1 ]; then
                            echo "║ [静默模式] LD_PRELOAD 错误信息将被抑制                                    ║"
                            echo "║            stderr 已重定向到 /dev/null                                    ║"
                            echo "║            警告：此模式可能影响其他错误信息的显示                        ║"
                        else
                            echo "║ [提示] 后续可能出现的 'ERROR: ld.so: object' 信息：                       ║"
                            echo "║        - 这些是预期的stderr输出                                           ║"
                            echo "║        - 不影响检测准确性                                                 ║"
                            echo "║        - 不会修改系统任何文件                                             ║"
                            echo "║        - 检测结果完全可信                                                 ║"
                            echo "║        - 如不想看到这些信息，请使用 --quiet 选项                         ║"
                        fi
                        echo "╚════════════════════════════════════════════════════════════════════════════╝"
                        echo ""
                        
                        # 设置标志
                        export LD_PRELOAD_DETECTED=1
                        
                        # 如果是静默模式，简单地将stderr重定向到/dev/null
                        if [ $QUIET_MODE -eq 1 ]; then
                            echo "[提示] 正在启用静默模式（stderr -> /dev/null）..."
                            exec 2>/dev/null
                        fi
                    fi
                else
                    echo "[!] 警告: Busybox 是动态链接的，仍可能受 LD_PRELOAD 影响"
                    echo "[!] 建议使用静态编译的 Busybox 以获得最佳安全性"
                fi
            fi
            shift 2
            ;;
        --quiet|-q)
            QUIET_MODE=1
            shift
            ;;
        --help|-h)
            show_help
            ;;
        --*)
            echo "[错误] 未知选项: $1"
            echo "使用 --help 查看帮助信息"
            exit 1
            ;;
        *)
            # 非选项参数视为输出文件
            OUTPUT_FILE="$1"
            shift
            ;;
    esac
done

# ============================================================================
# 计算基准时间戳
# ============================================================================

# Helper function: Convert date string to timestamp (Busybox compatible)
date_to_timestamp() {
    local date_str="$1"
    
    # Parse YYYY-MM-DD format
    local year=$(echo "$date_str" | cut -d'-' -f1)
    local month=$(echo "$date_str" | cut -d'-' -f2)
    local day=$(echo "$date_str" | cut -d'-' -f3)
    
    # Remove leading zeros
    month=$((10#$month))
    day=$((10#$day))
    
    # Calculate days since epoch (1970-01-01)
    # Simple calculation (not accounting for leap years perfectly, but good enough)
    local days_in_year=365
    local years_since_epoch=$((year - 1970))
    local leap_years=$(( (years_since_epoch + 1) / 4 ))
    
    # Days in each month (non-leap year)
    local days_per_month=(0 31 28 31 30 31 30 31 31 30 31 30 31)
    
    # Check if current year is leap year
    if [ $((year % 4)) -eq 0 ] && ([ $((year % 100)) -ne 0 ] || [ $((year % 400)) -eq 0 ]); then
        days_per_month[2]=29
    fi
    
    # Calculate total days
    local total_days=$((years_since_epoch * days_in_year + leap_years))
    
    # Add days for completed months
    for ((m=1; m<month; m++)); do
        total_days=$((total_days + ${days_per_month[$m]}))
    done
    
    # Add current day
    total_days=$((total_days + day - 1))
    
    # Convert to seconds
    echo $((total_days * 86400))
}

# Get current timestamp (Busybox compatible)
get_current_timestamp() {
    if [ $USE_BUSYBOX -eq 1 ]; then
        # Busybox date only supports current time
        $BUSYBOX_PATH date +%s
    else
        date +%s
    fi
}

# Format timestamp to date string (Busybox compatible)
timestamp_to_date() {
    local timestamp="$1"
    
    if [ $USE_BUSYBOX -eq 1 ]; then
        # Busybox date @timestamp support may be limited
        # Use printf for simple date formatting
        local days=$((timestamp / 86400))
        local years=$((days / 365))
        local year=$((1970 + years))
        local remaining_days=$((days - years * 365 - years / 4))
        
        # Simplified: just return year (or use stat if available)
        if [ -d /proc/self ]; then
            # Use /proc/self as reference and calculate
            echo "$year-??-??"
        else
            echo "unknown"
        fi
    else
        date -d "@$timestamp" +%Y-%m-%d 2>/dev/null || date -r "$timestamp" +%Y-%m-%d 2>/dev/null || echo "unknown"
    fi
}

if [ -n "$CUSTOM_DATE" ]; then
    # 用户指定了具体日期
    if [ $USE_BUSYBOX -eq 1 ]; then
        # Busybox mode: Use our helper function
        BASELINE_TIMESTAMP=$(date_to_timestamp "$CUSTOM_DATE")
        if [ -z "$BASELINE_TIMESTAMP" ] || [ "$BASELINE_TIMESTAMP" = "0" ]; then
            echo "[错误] 无效的日期格式 '$CUSTOM_DATE'，请使用 YYYY-MM-DD 格式"
            echo "示例: 2025-05-01"
            exit 1
        fi
    else
        BASELINE_TIMESTAMP=$(date -d "$CUSTOM_DATE" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "$CUSTOM_DATE" "+%s" 2>/dev/null || echo "0")
        if [ "$BASELINE_TIMESTAMP" -eq 0 ]; then
            echo "[错误] 无效的日期格式 '$CUSTOM_DATE'，请使用 YYYY-MM-DD 格式"
            echo "示例: 2025-05-01"
            exit 1
        fi
    fi
    TIME_DESC="自 $CUSTOM_DATE 以来"
    BASELINE_DATE_STR="$CUSTOM_DATE"
    echo "[提示] 时间范围: $TIME_DESC"
else
    # 使用天数计算
    CURRENT_TIMESTAMP=$(get_current_timestamp)
    SECONDS_TO_SUBTRACT=$((DAYS_THRESHOLD * 86400))
    BASELINE_TIMESTAMP=$((CURRENT_TIMESTAMP - SECONDS_TO_SUBTRACT))
    
    if [ "$BASELINE_TIMESTAMP" -le 0 ]; then
        echo "[错误] 无法计算时间戳，日期超出有效范围"
        exit 1
    fi
    
    TIME_DESC="最近 $DAYS_THRESHOLD 天"
    
    # Format baseline date
    if [ $USE_BUSYBOX -eq 1 ]; then
        BASELINE_DATE_STR=$(timestamp_to_date "$BASELINE_TIMESTAMP")
    else
        BASELINE_DATE_STR=$(date -d "@$BASELINE_TIMESTAMP" +%Y-%m-%d 2>/dev/null || date -r "$BASELINE_TIMESTAMP" +%Y-%m-%d 2>/dev/null || echo "unknown")
    fi
    
    echo "[提示] 时间范围: $TIME_DESC (基准日期: $BASELINE_DATE_STR, 基准时间戳: $BASELINE_TIMESTAMP)"
fi

# ============================================================================
# 命令初始化（支持 Busybox 模式）
# ============================================================================
init_commands() {
    if [ $USE_BUSYBOX -eq 1 ]; then
        # 使用 Busybox 命令（stderr已在全局层面过滤）
        CMD_PS="$BUSYBOX_PATH ps"
        CMD_LS="$BUSYBOX_PATH ls"
        CMD_FIND="$BUSYBOX_PATH find"
        CMD_GREP="$BUSYBOX_PATH grep"
        CMD_AWK="$BUSYBOX_PATH awk"
        CMD_SED="$BUSYBOX_PATH sed"
        CMD_STAT="$BUSYBOX_PATH stat"
        CMD_CAT="$BUSYBOX_PATH cat"
        CMD_HEAD="$BUSYBOX_PATH head"
        CMD_TAIL="$BUSYBOX_PATH tail"
        CMD_WC="$BUSYBOX_PATH wc"
        CMD_SORT="$BUSYBOX_PATH sort"
        CMD_UNIQ="$BUSYBOX_PATH uniq"
        CMD_CUT="$BUSYBOX_PATH cut"
        CMD_READLINK="$BUSYBOX_PATH readlink"
        CMD_BASENAME="$BUSYBOX_PATH basename"
        CMD_DIRNAME="$BUSYBOX_PATH dirname"
        CMD_XARGS="$BUSYBOX_PATH xargs"
        CMD_TR="$BUSYBOX_PATH tr"
        CMD_ECHO="$BUSYBOX_PATH echo"
        CMD_PRINTF="$BUSYBOX_PATH printf"
        CMD_TEST="$BUSYBOX_PATH test"
        CMD_DATE="$BUSYBOX_PATH date"
        CMD_UNAME="$BUSYBOX_PATH uname"
        CMD_WHOAMI="$BUSYBOX_PATH whoami"
        CMD_ID="$BUSYBOX_PATH id"
        CMD_NL="$BUSYBOX_PATH nl"
        
        echo "[提示] Busybox 命令已初始化"
    else
        # 使用系统命令
        CMD_PS="ps"
        CMD_LS="ls"
        CMD_FIND="find"
        CMD_GREP="grep"
        CMD_AWK="awk"
        CMD_SED="sed"
        CMD_STAT="stat"
        CMD_CAT="cat"
        CMD_HEAD="head"
        CMD_TAIL="tail"
        CMD_WC="wc"
        CMD_SORT="sort"
        CMD_UNIQ="uniq"
        CMD_CUT="cut"
        CMD_READLINK="readlink"
        CMD_BASENAME="basename"
        CMD_DIRNAME="dirname"
        CMD_XARGS="xargs"
        CMD_TR="tr"
        CMD_ECHO="echo"
        CMD_PRINTF="printf"
        CMD_TEST="test"
        CMD_DATE="date"
        CMD_UNAME="uname"
        CMD_WHOAMI="whoami"
        CMD_ID="id"
        CMD_NL="nl"
    fi
}

# 初始化命令
init_commands

TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/log"
TMP_DIR="${SCRIPT_DIR}/tmp"

# 清理旧数据（log 和 tmp 目录）
if [ -d "$LOG_DIR" ]; then
    rm -rf "$LOG_DIR"/* 2>/dev/null
fi
if [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"/* 2>/dev/null
fi

# 创建目录
mkdir -p "$LOG_DIR" 2>/dev/null
mkdir -p "$TMP_DIR" 2>/dev/null

# 日志文件路径
LOG_SUMMARY="${LOG_DIR}/00_summary_${TIMESTAMP}.log"
LOG_PS_PROC="${LOG_DIR}/01_ps_proc_diff_${TIMESTAMP}.log"
LOG_WORKDIR="${LOG_DIR}/02_process_workdir_${TIMESTAMP}.log"
LOG_MTIME="${LOG_DIR}/03_file_mtime_${TIMESTAMP}.log"
LOG_LDPRELOAD="${LOG_DIR}/04_ld_preload_${TIMESTAMP}.log"
LOG_DISGUISE="${LOG_DIR}/05_process_disguise_${TIMESTAMP}.log"
LOG_NETWORK="${LOG_DIR}/06_network_${TIMESTAMP}.log"
LOG_TMPDIR="${LOG_DIR}/07_tmpdir_check_${TIMESTAMP}.log"
LOG_SHELL="${LOG_DIR}/08_reverse_shell_${TIMESTAMP}.log"
LOG_SYSTEMD="${LOG_DIR}/09_systemd_${TIMESTAMP}.log"
LOG_BINARY="${LOG_DIR}/10_binary_scan_${TIMESTAMP}.log"
LOG_SUGGESTIONS="${LOG_DIR}/11_cleanup_${TIMESTAMP}.log"
LOG_CORRELATION="${LOG_DIR}/15_threat_correlation_${TIMESTAMP}.log"

# 检测结果数组
declare -a DETECTION_RESULTS

# ============================================================================
# 全局威胁情报库 - 用于关联分析
# ============================================================================
declare -a GLOBAL_THREAT_INTEL
# 数据格式: "类型|标识|路径|PID|详情|来源检测"
# 例如: "process|suspicious|/tmp/backdoor|1234|高熵命名,可疑路径|检测2"
#       "file|suspicious|/tmp/malware.sh||可疑命名|检测7"
#       "service|suspicious|evil.service||可疑路径|检测9"
#       "cron|suspicious|/tmp/cron.sh||恶意命令|检测11"

declare -A THREAT_PATHS
# 记录可疑路径及其出现次数: ["路径"]="次数|来源列表"

declare -A THREAT_PROCESSES
# 记录可疑进程: ["PID"]="进程名|路径|原因列表|来源列表"

declare -A THREAT_FILES
# 记录可疑文件: ["文件路径"]="类型|原因列表|来源检测列表"

# ============================================================================
# 参数解析
# ============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --days)
            DAYS_THRESHOLD="$2"
            shift 2
            ;;
        --since)
            CUSTOM_DATE="$2"
            shift 2
            ;;
        --help|-h)
            echo "用法: $0 [选项] [输出文件]"
            echo ""
            echo "选项:"
            echo "  --days N          检查最近 N 天内修改的文件 (默认: 7)"
            echo "  --since DATE      检查自指定日期以来修改的文件 (格式: YYYY-MM-DD)"
            echo "  --help, -h        显示此帮助信息"
            echo ""
            echo "示例:"
            echo "  $0                     # 检查最近 7 天"
            echo "  $0 --days 30           # 检查最近 30 天"
            echo "  $0 --since 2025-05-01  # 检查自指定日期"
            exit 0
            ;;
        --*)
            echo "错误: 未知选项 '$1'"
            echo "使用 --help 查看帮助信息"
            exit 1
            ;;
        *)
            OUTPUT_FILE="$1"
            shift
            ;;
    esac
done

# 计算基准时间戳
if [ -n "$CUSTOM_DATE" ]; then
    BASELINE_TIMESTAMP=$(date -d "$CUSTOM_DATE" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "$CUSTOM_DATE" "+%s" 2>/dev/null || echo "0")
    if [ "$BASELINE_TIMESTAMP" -eq 0 ]; then
        echo "错误: 无效的日期格式 '$CUSTOM_DATE' (使用 YYYY-MM-DD)"
        exit 1
    fi
    TIME_DESC="自 $CUSTOM_DATE 起"
    BASELINE_DATE_STR="$CUSTOM_DATE"
else
    BASELINE_TIMESTAMP=$(date -d "$DAYS_THRESHOLD days ago" +%s 2>/dev/null || date -v -${DAYS_THRESHOLD}d +%s 2>/dev/null || echo "0")
    if [ "$BASELINE_TIMESTAMP" -eq 0 ]; then
        echo "错误: 无法计算时间戳"
        exit 1
    fi
    TIME_DESC="最近 $DAYS_THRESHOLD 天"
    BASELINE_DATE_STR=$(date -d "$DAYS_THRESHOLD days ago" +%Y-%m-%d 2>/dev/null || date -v -${DAYS_THRESHOLD}d +%Y-%m-%d 2>/dev/null || echo "unknown")
fi

# ============================================================================
# 辅助函数
# ============================================================================

# 添加检测结果
add_detection() {
    local severity="$1"
    local message="$2"
    DETECTION_RESULTS+=("[$severity] $message")
}

# 统计字符串中某类字符的数量（纯 Bash 实现，不依赖外部命令）
count_chars() {
    local str="$1"
    local pattern="$2"  # 如 "[0-9]" 或 "[a-z]" 或 "[aeiou]"
    local count=0
    local i
    
    for ((i=0; i<${#str}; i++)); do
        local char="${str:i:1}"
        if [[ "$char" =~ $pattern ]]; then
            ((count++))
        fi
    done
    
    echo "$count"
}

# 递归解析软链接到真实路径（实现 readlink -f 功能）
resolve_link() {
    local path="$1"
    local max_depth=20
    local depth=0
    
    while [ -L "$path" ] && [ $depth -lt $max_depth ]; do
        local target=$($CMD_READLINK "$path" 2>/dev/null)
        if [ -z "$target" ]; then
            break
        fi
        
        # 如果是相对路径，需要相对于链接所在目录解析
        if [[ "$target" != /* ]]; then
            local dir=$($CMD_DIRNAME "$path")
            path="$dir/$target"
        else
            path="$target"
        fi
        
        ((depth++))
    done
    
    echo "$path"
}

# 根据 UID 获取用户名（替代 getent passwd）
get_username_by_uid() {
    local uid="$1"
    local username=""
    
    # 尝试从 /etc/passwd 读取
    if [ -f /etc/passwd ]; then
        username=$($CMD_GREP "^[^:]*:[^:]*:$uid:" /etc/passwd 2>/dev/null | $CMD_CUT -d: -f1 | $CMD_HEAD -1)
    fi
    
    # 如果找到用户名，返回；否则返回 uid:数字
    if [ -n "$username" ]; then
        echo "$username"
    else
        echo "uid:$uid"
    fi
}

# ============================================================================
# 可疑性检测框架
# ============================================================================

# 计算Shannon熵值（信息熵）
calculate_shannon_entropy() {
    local str="$1"
    local len=${#str}
    
    [ $len -eq 0 ] && echo "0" && return
    
    # 统计每个字符出现的次数
    declare -A char_freq
    local i char
    
    for ((i=0; i<len; i++)); do
        char="${str:i:1}"
        ((char_freq[$char]++))
    done
    
    # 计算熵值
    local entropy=0
    local freq prob
    
    for freq in "${char_freq[@]}"; do
        prob=$($CMD_AWK "BEGIN {printf \"%.6f\", $freq/$len}")
        # entropy += -prob * log2(prob)
        entropy=$($CMD_AWK "BEGIN {printf \"%.6f\", $entropy + (-$prob * log($prob)/log(2))}")
    done
    
    echo "$entropy"
}

# 检查文件名是否具有随机性特征（多维度检测）
# ============================================================================
# 专门用于systemd服务名的可疑性检测
# ============================================================================
check_service_name_suspicious() {
    local service_name="$1"
    local len=${#service_name}
    
    # === systemd服务白名单（标准系统服务命名模式）===
    
    # Ubuntu/Debian标准服务
    local COMMON_SERVICES="^(motd-news|ua-timer|ua-reboot-cmds|esm-cache|packagekit|apport-.*)"
    COMMON_SERVICES="${COMMON_SERVICES}|^(logrotate|setvtrgb|kmod-.*|debug-shell)"
    
    # systemd标准服务命名模式
    local SYSTEMD_PATTERNS="^(systemd-.*|initrd-.*)"
    
    # systemd模板服务（@.service）
    local TEMPLATE_SERVICES=".*@$"
    
    # 标准系统服务
    local SYSTEM_SERVICES="^(cron|sshd|rsyslog|audit|dbus|network|bluetooth|cups|apache2|nginx|mysql|postgresql)"
    SYSTEM_SERVICES="${SYSTEM_SERVICES}|^(docker|containerd|snapd|unattended-upgrades|cloud-.*)"
    
    # 组合白名单
    local ALL_WHITELIST="${COMMON_SERVICES}|${SYSTEMD_PATTERNS}|${TEMPLATE_SERVICES}|${SYSTEM_SERVICES}"
    
    if [[ "$service_name" =~ $ALL_WHITELIST ]]; then
        echo "0"  # 白名单服务，不可疑
        return
    fi
    
    # 检查是否是真正的随机命名（纯字母数字混合，无语义）
    # 例如: x7q9m2k5p8, a2f8k9x3m, h4x0r123
    
    # 长度检查：3-15字符
    if [ $len -lt 3 ] || [ $len -gt 15 ]; then
        echo "0"  # 太短或太长，不检测
        return
    fi
    
    # 纯小写字母+数字混合（无连字符、下划线等）
    if [[ "$service_name" =~ ^[a-z0-9]+$ ]]; then
        local has_digit=$(count_chars "$service_name" "[0-9]")
        
        local has_letter=$(count_chars "$service_name" "[a-z]")
        
        # 必须同时包含字母和数字
        if [ $has_digit -ge 2 ] && [ $has_letter -ge 2 ]; then
            # 字母和数字混合度高（都占20%以上）
            local digit_ratio=$($CMD_AWK "BEGIN {printf \"%.2f\", $has_digit/$len}")
            local letter_ratio=$($CMD_AWK "BEGIN {printf \"%.2f\", $has_letter/$len}")
            
            if $CMD_AWK "BEGIN {exit !($digit_ratio > 0.2 && $letter_ratio > 0.2)}"; then
                # 检查是否有连续的数字和字母交替（真正的随机特征）
                # 例如: x7q9 (字母-数字-字母-数字)
                if [[ "$service_name" =~ [a-z][0-9]|[0-9][a-z] ]]; then
                    echo "1"  # 可疑：随机命名
                    return
                fi
            fi
        fi
    fi
    
    echo "0"  # 不可疑
}

check_name_entropy() {
    local name="$1"
    local len=${#name}
    
    # 名称太短，跳过
    [ $len -lt 5 ] && echo "0" && return
    
    # === 白名单检查（已知系统工具和命名模式）===
    
    # 1. 精确匹配白名单（扩展版）
    local SYSTEM_TOOLS_WHITELIST="sha1sum|sha224sum|sha256sum|sha384sum|sha512sum|md5sum|base64|base32"
    
    # 文件系统工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|e2fsck|e2label|e4crypt|e4defrag|e2freefrag|resize2fs|dumpe2fs|tune2fs|mke2fs"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|badblocks|blockdev|filefrag|swaplabel|readprofile|fixparts"
    
    # 压缩工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|xz|7z|7za|bzip2|gzip2|lzmainfo|zipdetails|streamzip|uncompress"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|mksquashfs|unsquashfs"
    
    # Python工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|py3compile|py3clean|python2|python3|perl5|pygmentize"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|pybabel-python3|pyserial-ports|pyhtmlizer3"
    
    # Perl工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|pod2html|pod2text|pod2usage|pod2man|perlthanks|corelist"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|instmodsh|podchecker|ptardiff"
    
    # 基础系统工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|mkfs|fsck|fdisk|killall5|runlevel|telinit"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|fusermount|fusermount3|ec2metadata|cloud-init"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|hostname|printenv|realpath|readlink|truncate|tempfile"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|manifest|unexpand|envsubst|fallocate|hardlink|ischroot"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|resizepart|scriptlive|scriptreplay|vimtutor|whiptail"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|eatmydata|dircolors|growpart|pastebinit|broadwayd"
    
    # 用户管理
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|chage|chfn|chsh|chgpasswd|newgrp|chpasswd"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|groupadd|groupmod|groupdel|groupmems|grpunconv|pwunconv"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|pwhistory_helper"
    
    # 键盘和控制台工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|dumpkeys|loadkeys|kbd_mode|setlogcons|screendump"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|deallocvt|loadunimap|setupcon|psfxtable|fgconsole"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|splitfont|resizecons|codepage|unicode_start|unicode_stop"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|getkeycodes|mk_modmap|setvtrgb|setvesablank"
    
    # JSON工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|jsonpointer|jsonpatch|jsonschema"
    
    # FontConfig工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|fc-match|fc-conflist|fc-pattern|fc-query|fc-validate"
    
    # systemd工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|loginctl|hostnamectl|resolvectl|varlinkctl"
    
    # Apport工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|apport-cli|apport-bug|apport-unpack"
    
    # GnuPG工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|gpgparsemail|watchgnupg|addgnupghome|applygnupgdefaults"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|c_rehash|dirmngr-client"
    
    # sudo工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|sudoreplay|cvtsudoers|sudo_logsrvd|sudo_sendlog"
    
    # GLib/GTK工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|gresource|gapplication"
    
    # 配置和本地化
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|localedef|libnetcfg|uclampset|gettext|getpcaps"
    
    # 包管理
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|add-apt-repository"
    
    # 其他系统工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|appstreamcli|uuidparse|ctrlaltdel|logrotate"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|ldconfig|fstab-decode|faillock|invoke-rc|shadowconfig"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|helpztags|markdown-it|ckeygen3|tkconch3|automat-visualize3"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|pinentry-curses|pkaction|pkttyagent"
    
    # 网络工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|rsync-ssl|nc"
    
    # 合法的shell工具（特别添加）
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|git-shell|add-shell|remove-shell|byobu-shell"
    
    # Ubuntu特有工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|ubuntu-security-status|hwe-support-status|purge-old-kernels"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|select-editor|sensible-pager|lsb_release"
    
    # 其他Debian/Ubuntu工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|man-recode|update-shells|invoke-rc|which"
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|run-parts|switch_root|mklost+found"
    
    # Netcat变种
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|nc"
    
    # 动态链接器
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|ldconfig"
    
    # util-linux工具
    SYSTEM_TOOLS_WHITELIST="${SYSTEM_TOOLS_WHITELIST}|rename"
    
    if [[ "$name" =~ ^(${SYSTEM_TOOLS_WHITELIST})$ ]]; then
        echo "0"  # 在白名单中，正常
        return
    fi
    
    # 2. 系统命名模式白名单（前缀匹配）
    # systemd相关
    if [[ "$name" =~ ^systemd- ]] || [[ "$name" =~ ^journalctl ]]; then
        echo "0"  # systemd组件
        return
    fi
    
    # 包管理器相关
    if [[ "$name" =~ ^(apt-|dpkg-|deb-|rpm-|yum-|debconf-) ]]; then
        echo "0"  # 包管理工具
        return
    fi
    
    # 云平台相关
    if [[ "$name" =~ ^(cloud-|ec2-|aws-|azure-|gcp-) ]]; then
        echo "0"  # 云平台工具
        return
    fi
    
    # 图形界面相关
    if [[ "$name" =~ ^(gtk-|gdk-|x11-|xdg-) ]]; then
        echo "0"  # 图形工具
        return
    fi
    
    # 文件系统和设备相关
    if [[ "$name" =~ ^(e2|e4|mkfs\.|fsck\.|mount\.|blk) ]]; then
        echo "0"  # 文件系统工具
        return
    fi
    
    # 终端和控制台相关
    if [[ "$name" =~ ^(console-|keyboard-|getty|agetty) ]]; then
        echo "0"  # 终端工具
        return
    fi
    
    # 开发和调试工具（带架构前缀）
    if [[ "$name" =~ ^x86_64-linux-gnu- ]] || [[ "$name" =~ ^aarch64-linux-gnu- ]]; then
        echo "0"  # 交叉编译工具
        return
    fi
    
    # Python工具（带版本后缀）
    if [[ "$name" =~ ^(pydoc|pygettext|python3\.) ]] || [[ "$name" =~ \.(py|pyw)$ ]]; then
        echo "0"  # Python工具
        return
    fi
    
    # Perl工具（带版本后缀）
    if [[ "$name" =~ ^(perl5\.|cpan5\.) ]] || [[ "$name" =~ \.(pl|pm)$ ]]; then
        echo "0"  # Perl工具
        return
    fi
    
    # 系统工具合法后缀（发行版变种/备份/脚本版本）
    if [[ "$name" =~ \.(openbsd|freebsd|debianutils|debian|ubuntu)$ ]]; then
        echo "0"  # 发行版特定变种（如nc.openbsd, which.debianutils）
        return
    fi
    
    if [[ "$name" =~ \.(ul|real|orig|bin|sh)$ ]]; then
        echo "0"  # util-linux工具/实际执行文件/备份/shell脚本（如rename.ul, ldconfig.real, gettext.sh）
        return
    fi
    
    if [[ "$name" =~ \.(d|rc)$ ]] || [[ "$name" =~ -rc$ ]]; then
        echo "0"  # init脚本和配置目录（如invoke-rc.d）
        return
    fi
    
    # Debian辅助工具
    if [[ "$name" =~ ^dh_ ]]; then
        echo "0"  # Debian helper工具
        return
    fi
    
    # AppArmor工具
    if [[ "$name" =~ ^aa- ]]; then
        echo "0"  # AppArmor工具
        return
    fi
    
    # JSON工具（带前缀）
    if [[ "$name" =~ ^json- ]]; then
        echo "0"  # JSON工具
        return
    fi
    
    # 特殊字符命名的合法工具
    if [[ "$name" =~ ^mklost\+found$ ]] || [[ "$name" =~ ^run-parts$ ]]; then
        echo "0"  # 特殊命名的系统工具（mklost+found, run-parts）
        return
    fi
    
    # 其他常见系统工具前缀
    if [[ "$name" =~ ^(byobu-|landscape-|snap|update-|install-|locale-|dbus-|gpg-|ssh-|git-|vim\.|pam_|unix_) ]]; then
        echo "0"  # 系统管理/开发工具
        return
    fi
    
    # 服务和守护进程相关
    if [[ "$name" =~ ^(network|rsyslog|audit|cron|atd|cups|apache|nginx|mysql|postgres) ]]; then
        echo "0"  # 系统服务
        return
    fi
    
    # Mesa/图形相关
    if [[ "$name" =~ ^mesa- ]] || [[ "$name" =~ \.py$ ]]; then
        echo "0"  # Mesa/Python脚本
        return
    fi
    
    # 名称中包含连字符的工具（通常是合法的系统工具）
    # 例如：migrate-pubring-from-classic-gpg
    if [[ "$name" =~ ^[a-z]+-[a-z]+-[a-z]+ ]]; then
        # 检查是否是常见系统工具模式
        if [[ "$name" =~ (migrate|switch|rename|which) ]]; then
            echo "0"  # 多词连字符命名的系统工具
            return
        fi
    fi
    
    # === 语义检查（排除有意义的命名）===
    # 先去除文件扩展名（只检查基础名）
    local basename="$name"
    basename="${basename%.sh}"
    basename="${basename%.py}"
    basename="${basename%.pl}"
    basename="${basename%.rb}"
    
    # 包含下划线或连字符的名称通常是有意义的（非随机）
    if [[ "$basename" =~ _ ]] || [[ "$basename" =~ - ]]; then
        # 有分隔符的名称如果由常见单词组成，则不是随机命名
        # 例如: process_scanner, orphan_maker, suspicious_daemon
        # 这些虽然可疑，但不是"随机命名"，应该由关键词检测来处理
        local word_pattern="(process|scanner|daemon|maker|delete|orphan|service|backup|update|check|monitor|system|network|file|data|config|manager|handler|worker|task|job|script|self)"
        if [[ "$basename" =~ $word_pattern ]]; then
            echo "0"  # 有意义的命名（非随机）
            return
        fi
    fi
    
    # 全小写英文单词（无数字）通常不是随机命名
    if [[ "$name" =~ ^[a-z]+$ ]] && [ $len -ge 5 ] && [ $len -le 20 ]; then
        # 常见英文单词不算随机（即使它们可能是恶意的）
        local english_words="hidden|stealth|suspicious|malicious|backdoor|rootkit|trojan"
        english_words="${english_words}|exploit|payload|reverse|shell|inject|hijack|bypass|evade"
        if [[ "$name" =~ ^($english_words)$ ]]; then
            echo "0"  # 英文单词（应由关键词检测处理）
            return
        fi
    fi
    
    # === 检测1: Shannon熵值检测 ===
    # 随机字符串通常熵值较高（接近理论最大值）
    if [ $len -ge 8 ]; then
        local entropy=$(calculate_shannon_entropy "$name")
        local max_entropy=$($CMD_AWK "BEGIN {printf \"%.2f\", log($len)/log(2)}")
        local entropy_ratio=$($CMD_AWK "BEGIN {if ($max_entropy > 0) printf \"%.2f\", $entropy/$max_entropy; else print 0}")
        
        # 熵值比率 > 0.85 表示高度随机（字符分布很均匀）
        if $CMD_AWK "BEGIN {exit !($entropy_ratio > 0.85)}" 2>/dev/null; then
            # 排除常见模式后判定为可疑
            if [[ ! "$name" =~ (test|admin|user|config|server|client|manager|system) ]]; then
                echo "1"  # 高熵，可疑
                return
            fi
        fi
    fi
    
    # === 检测2: 字符类型混合度检测 ===
    # 随机命名通常是字母+数字混合，且分布随机
    if [ $len -ge 8 ] && [ $len -le 20 ]; then
        if [[ "$name" =~ ^[a-z0-9]+$ ]]; then
            local lower_count=$(count_chars "$name" "[a-z]")
            local digit_count=$(count_chars "$name" "[0-9]")
            
            # 数字占比在25%-70%之间，且字母+数字都存在
            if [ $lower_count -gt 0 ] && [ $digit_count -gt 0 ]; then
                local digit_ratio=$($CMD_AWK "BEGIN {printf \"%.2f\", $digit_count/$len}")
                if $CMD_AWK "BEGIN {exit !($digit_ratio >= 0.25 && $digit_ratio <= 0.70)}" 2>/dev/null; then
                    # 检查字符交替程度（随机名称字母和数字交替出现）
                    local transitions=0
                    local prev_type="" curr_type
                    local i char
                    for ((i=0; i<len; i++)); do
                        char="${name:i:1}"
                        if [[ "$char" =~ [0-9] ]]; then
                            curr_type="digit"
                        else
                            curr_type="letter"
                        fi
                        if [ -n "$prev_type" ] && [ "$curr_type" != "$prev_type" ]; then
                            ((transitions++))
                        fi
                        prev_type="$curr_type"
                    done
                    
                    # 交替次数 >= 3 表示字符混杂（随机特征）
                    if [ $transitions -ge 3 ]; then
                        echo "1"  # 可疑
                        return
                    fi
                fi
            fi
        fi
    fi
    
    # === 检测3: 纯数字后缀检测 ===
    # 形如 x7q9m2k5p8, a2f8k9x3m 这类随机字符串
    if [ $len -ge 7 ] && [ $len -le 15 ]; then
        if [[ "$name" =~ ^[a-z]+[0-9]+[a-z0-9]+$ ]] || [[ "$name" =~ ^[a-z0-9]+[0-9]+[a-z]+$ ]]; then
            local digit_count=$(count_chars "$name" "[0-9]")
            
            # 至少3个数字，且不是常见工具模式
            if [ $digit_count -ge 3 ]; then
                if [[ ! "$name" =~ ^(sha|md5|base|python|perl|vim|gcc|g\+\+)[0-9]+$ ]]; then
                    # 检查是否有可识别的单词前缀
                    local has_word=0
                    local common_words="test|temp|tmp|user|admin|root|sys|log|bin|lib|var|etc|opt|dev|proc|run|srv|mnt"
                    if [[ "$name" =~ ^($common_words) ]]; then
                        has_word=1
                    fi
                    
                    if [ $has_word -eq 0 ]; then
                        echo "1"  # 可疑
                        return
                    fi
                fi
            fi
        fi
    fi
    
    # === 检测4: 无意义字符序列检测 ===
    # 检查是否包含难以发音的辅音连续（随机特征）
    if [ $len -ge 9 ]; then
        # 检查元音比例
        local vowels=$(count_chars "$name" "[aeiou]")
        local vowel_ratio=$($CMD_AWK "BEGIN {printf \"%.2f\", $vowels/$len}")
        
        # 元音占比 < 15% 表示难以发音（随机特征）
        if $CMD_AWK "BEGIN {exit !($vowel_ratio < 0.15)}" 2>/dev/null; then
            echo "1"  # 可疑
            return
        fi
        
        # 检查辅音连续（3个以上辅音连续）
        if [[ "$name" =~ [^aeiou]{4,} ]]; then
            echo "1"  # 可疑
            return
        fi
    fi
    
    # === 检测5: 单字符重复度检测 ===
    # 完全随机的字符串重复字符很少
    if [ $len -ge 10 ]; then
        # 使用纯 Bash 统计唯一字符数
        declare -A seen_chars
        local i char unique_chars=0
        for ((i=0; i<len; i++)); do
            char="${name:i:1}"
            if [ -z "${seen_chars[$char]}" ]; then
                seen_chars[$char]=1
                ((unique_chars++))
            fi
        done
        
        local uniqueness_ratio=$($CMD_AWK "BEGIN {printf \"%.2f\", $unique_chars/$len}")
        
        # 唯一字符占比 > 0.75 表示字符几乎不重复（随机特征）
        if $CMD_AWK "BEGIN {exit !($uniqueness_ratio > 0.75)}" 2>/dev/null; then
            echo "1"  # 可疑
            return
        fi
    fi
    
    echo "0"  # 正常
}

# 检查白名单程序是否被伪造/篡改（信任但验证机制）
# 返回值：0=正常，1=伪造/篡改，输出错误原因
verify_whitelist_program() {
    local name="$1"
    local path="$2"
    local is_process="$3"  # 1=进程，0=文件
    
    # 白名单程序及其合法路径映射
    declare -A WHITELIST_PATHS
    
    # 核心系统工具
    WHITELIST_PATHS["systemd"]="^/usr/lib/systemd/systemd$|^/lib/systemd/systemd$|^/sbin/init$"
    WHITELIST_PATHS["systemctl"]="^/usr/bin/systemctl$|^/bin/systemctl$"
    WHITELIST_PATHS["journalctl"]="^/usr/bin/journalctl$|^/bin/journalctl$"
    
    # 哈希和编码工具
    WHITELIST_PATHS["sha1sum"]="^/usr/bin/sha1sum$"
    WHITELIST_PATHS["sha224sum"]="^/usr/bin/sha224sum$"
    WHITELIST_PATHS["sha256sum"]="^/usr/bin/sha256sum$"
    WHITELIST_PATHS["sha384sum"]="^/usr/bin/sha384sum$"
    WHITELIST_PATHS["sha512sum"]="^/usr/bin/sha512sum$"
    WHITELIST_PATHS["md5sum"]="^/usr/bin/md5sum$|^/bin/md5sum$"
    WHITELIST_PATHS["base64"]="^/usr/bin/base64$|^/bin/base64$"
    WHITELIST_PATHS["base32"]="^/usr/bin/base32$|^/bin/base32$"
    
    # 文件系统工具
    WHITELIST_PATHS["e2fsck"]="^/usr/sbin/e2fsck$|^/sbin/e2fsck$"
    WHITELIST_PATHS["resize2fs"]="^/usr/sbin/resize2fs$|^/sbin/resize2fs$"
    WHITELIST_PATHS["dumpe2fs"]="^/usr/sbin/dumpe2fs$|^/sbin/dumpe2fs$"
    WHITELIST_PATHS["e4defrag"]="^/usr/sbin/e4defrag$|^/sbin/e4defrag$"
    WHITELIST_PATHS["tune2fs"]="^/usr/sbin/tune2fs$|^/sbin/tune2fs$"
    WHITELIST_PATHS["mke2fs"]="^/usr/sbin/mke2fs$|^/sbin/mke2fs$"
    WHITELIST_PATHS["mkfs"]="^/usr/sbin/mkfs$|^/sbin/mkfs$"
    WHITELIST_PATHS["fsck"]="^/usr/sbin/fsck$|^/sbin/fsck$"
    WHITELIST_PATHS["fdisk"]="^/usr/sbin/fdisk$|^/sbin/fdisk$"
    
    # Python工具
    WHITELIST_PATHS["py3compile"]="^/usr/bin/py3compile$"
    WHITELIST_PATHS["py3clean"]="^/usr/bin/py3clean$"
    WHITELIST_PATHS["python2"]="^/usr/bin/python2$"
    WHITELIST_PATHS["python3"]="^/usr/bin/python3$"
    
    # Perl工具
    WHITELIST_PATHS["pod2html"]="^/usr/bin/pod2html$"
    WHITELIST_PATHS["pod2text"]="^/usr/bin/pod2text$"
    WHITELIST_PATHS["pod2usage"]="^/usr/bin/pod2usage$"
    WHITELIST_PATHS["pod2man"]="^/usr/bin/pod2man$"
    
    # 其他系统工具
    WHITELIST_PATHS["fusermount"]="^/usr/bin/fusermount$|^/bin/fusermount$"
    WHITELIST_PATHS["fusermount3"]="^/usr/bin/fusermount3$|^/bin/fusermount3$"
    WHITELIST_PATHS["killall5"]="^/usr/sbin/killall5$|^/sbin/killall5$"
    WHITELIST_PATHS["runlevel"]="^/usr/sbin/runlevel$|^/sbin/runlevel$"
    WHITELIST_PATHS["ec2metadata"]="^/usr/bin/ec2metadata$"
    
    # 用户管理工具
    WHITELIST_PATHS["chage"]="^/usr/bin/chage$"
    WHITELIST_PATHS["chfn"]="^/usr/bin/chfn$"
    WHITELIST_PATHS["chsh"]="^/usr/bin/chsh$"
    WHITELIST_PATHS["chgpasswd"]="^/usr/sbin/chgpasswd$"
    WHITELIST_PATHS["newgrp"]="^/usr/bin/newgrp$"
    
    # 系统服务和守护进程
    WHITELIST_PATHS["init"]="^/sbin/init$|^/lib/systemd/systemd$"
    WHITELIST_PATHS["dbus-daemon"]="^/usr/bin/dbus-daemon$|^/bin/dbus-daemon$"
    WHITELIST_PATHS["NetworkManager"]="^/usr/sbin/NetworkManager$"
    WHITELIST_PATHS["polkitd"]="^/usr/lib/polkit-1/polkitd$|^/usr/libexec/polkitd$"
    WHITELIST_PATHS["rsyslogd"]="^/usr/sbin/rsyslogd$"
    WHITELIST_PATHS["syslogd"]="^/usr/sbin/syslogd$"
    WHITELIST_PATHS["auditd"]="^/sbin/auditd$|^/usr/sbin/auditd$"
    WHITELIST_PATHS["crond"]="^/usr/sbin/crond$|^/usr/sbin/cron$"
    WHITELIST_PATHS["cron"]="^/usr/sbin/cron$|^/usr/sbin/crond$"
    WHITELIST_PATHS["atd"]="^/usr/sbin/atd$"
    WHITELIST_PATHS["sshd"]="^/usr/sbin/sshd$"
    WHITELIST_PATHS["cupsd"]="^/usr/sbin/cupsd$"
    
    # Web服务器
    WHITELIST_PATHS["nginx"]="^/usr/sbin/nginx$"
    WHITELIST_PATHS["apache2"]="^/usr/sbin/apache2$"
    WHITELIST_PATHS["httpd"]="^/usr/sbin/httpd$"
    
    # 数据库服务
    WHITELIST_PATHS["mysql"]="^/usr/sbin/mysqld$|^/usr/bin/mysql$"
    WHITELIST_PATHS["mysqld"]="^/usr/sbin/mysqld$"
    WHITELIST_PATHS["postgres"]="^/usr/lib/postgresql/.*/bin/postgres$"
    WHITELIST_PATHS["postgresql"]="^/usr/lib/postgresql/.*/bin/postgres$"
    WHITELIST_PATHS["agetty"]="^/sbin/agetty$|^/usr/sbin/agetty$"
    
    # 检查1：路径验证
    if [ -n "${WHITELIST_PATHS[$name]}" ]; then
        local expected_pattern="${WHITELIST_PATHS[$name]}"
        
        # 检查实际路径是否匹配预期
        if [[ ! "$path" =~ $expected_pattern ]]; then
            echo "路径不匹配预期"
            return 1
        fi
    fi
    
    # 检查2：软链接验证（如果是软链接，检查目标）
    if [ -L "$path" ]; then
        local link_target=$(resolve_link "$path")
        
        # 软链接目标不应该在临时目录
        if [[ "$link_target" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
            echo "软链接指向临时目录"
            return 1
        fi
        
        # 软链接目标不应该在用户目录
        if [[ "$link_target" =~ ^/home/|^/root/ ]]; then
            echo "软链接指向用户目录"
            return 1
        fi
        
        # 软链接目标应该在系统目录
        if [[ ! "$link_target" =~ ^/(usr/)?(bin|sbin|lib|lib64)/ ]]; then
            echo "软链接目标可疑"
            return 1
        fi
    fi
    
    # 检查3：文件完整性（仅对文件，不对进程）
    if [ "$is_process" = "0" ] && [ -f "$path" ]; then
        # 检查文件是否最近被修改（7天内）
        if [ -n "$BASELINE_TIMESTAMP" ]; then
            local file_mtime=$(stat -c %Y "$path" 2>/dev/null || echo "0")
            if [ "$file_mtime" -gt "$BASELINE_TIMESTAMP" ] 2>/dev/null; then
                echo "最近修改:白名单程序在7天内被修改"
                return 1
            fi
        fi
    fi
    
    # 检查4：路径位置验证（不应该在异常目录）
    if [[ "$path" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
        echo "位于临时目录"
        return 1
    fi
    
    if [[ "$path" =~ ^/home/|^/root/ ]]; then
        echo "位于用户目录"
        return 1
    fi
    
    return 0  # 验证通过
}

# ============================================================================
# 内核模块白名单验证 - Trust but Verify机制
# ============================================================================
verify_kernel_module_whitelist() {
    local module_name="$1"
    
    # 获取内核版本
    local kernel_version=$($CMD_UNAME -r)
    
    # 定义合法的内核模块路径
    local MODULE_BASE_PATHS=(
        "/lib/modules/$kernel_version"
        "/usr/lib/modules/$kernel_version"
        "/lib/modules"
        "/usr/lib/modules"
    )
    
    # 尝试查找模块文件
    local module_file=""
    local module_found=0
    
    for base_path in "${MODULE_BASE_PATHS[@]}"; do
        if [ -d "$base_path" ]; then
            # 查找 .ko 或 .ko.xz 或 .ko.gz 文件
            module_file=$($CMD_FIND "$base_path" -name "${module_name}.ko*" 2>/dev/null | $CMD_HEAD -1)
            if [ -n "$module_file" ]; then
                module_found=1
                break
            fi
        fi
    done
    
    # 检查1：模块文件必须存在于合法路径
    if [ $module_found -eq 0 ]; then
        # 内置模块可能没有.ko文件（如loop, fuse等）
        # 检查是否是内置模块
        if [ -d "/sys/module/$module_name" ]; then
            # 检查是否有initstate文件（内置模块的特征）
            if [ -f "/sys/module/$module_name/initstate" ]; then
                local initstate=$(cat "/sys/module/$module_name/initstate" 2>/dev/null)
                if [ "$initstate" = "live" ]; then
                    # 这是合法的内置模块
                    return 0
                fi
            fi
        fi
        
        # 既不是外部模块，也不是内置模块
        echo "模块文件不存在于合法路径"
        return 1
    fi
    
    # 检查2：模块文件路径必须在合法的内核模块目录
    local path_ok=0
    for base_path in "${MODULE_BASE_PATHS[@]}"; do
        if [[ "$module_file" =~ ^${base_path}/ ]]; then
            path_ok=1
            break
        fi
    done
    
    if [ $path_ok -eq 0 ]; then
        echo "模块文件路径异常:$module_file"
        return 1
    fi
    
    # 检查3：模块文件不应该是指向临时目录的软链接
    if [ -L "$module_file" ]; then
        local link_target=$(resolve_link "$module_file")
        
        # 软链接目标不应该在临时目录
        if [[ "$link_target" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
            echo "模块软链接指向临时目录"
            return 1
        fi
        
        # 软链接目标不应该在用户目录
        if [[ "$link_target" =~ ^/home/|^/root/ ]]; then
            echo "模块软链接指向用户目录"
            return 1
        fi
        
        # 软链接目标应该还在内核模块目录
        local link_path_ok=0
        for base_path in "${MODULE_BASE_PATHS[@]}"; do
            if [[ "$link_target" =~ ^${base_path}/ ]] || [[ "$link_target" =~ ^/lib/modules/ ]] || [[ "$link_target" =~ ^/usr/lib/modules/ ]]; then
                link_path_ok=1
                break
            fi
        done
        
        if [ $link_path_ok -eq 0 ]; then
            echo "模块软链接目标异常"
            return 1
        fi
    fi
    
    # 检查4：模块文件不应该有异常权限
    if [ -f "$module_file" ]; then
        local mod_perm=$(stat -c %a "$module_file" 2>/dev/null || echo "000")
        
        # 内核模块通常是644或444权限，不应该是777/666
        if [[ "$mod_perm" == "777" ]] || [[ "$mod_perm" == "666" ]]; then
            echo "模块权限异常:$mod_perm"
            return 1
        fi
        
        # 内核模块不应该有执行权限
        if [[ "$mod_perm" =~ [1357]$ ]]; then
            echo "模块不应有执行权限"
            return 1
        fi
    fi
    
    return 0  # 验证通过
}

# ============================================================================
# 通用白名单路径验证 - 用于没有精确路径映射的白名单程序
# ============================================================================
verify_whitelist_path_generic() {
    local name="$1"
    local path="$2"
    
    # 如果没有路径信息，无法验证
    [ -z "$path" ] || [ "$path" = "N/A" ] || [ "$path" = "-" ] && return 0
    
    # === 检查1：不应该在临时目录 ===
    if [[ "$path" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
        echo "程序在临时目录"
        return 1
    fi
    
    # === 检查2：不应该在用户目录 ===
    if [[ "$path" =~ ^/home/|^/root/ ]]; then
        echo "程序在用户目录"
        return 1
    fi
    
    # === 检查3：应该在标准系统目录 ===
    # 白名单程序通常应该在这些目录
    local VALID_SYSTEM_DIRS="^/(bin|sbin|usr/bin|usr/sbin|usr/lib|usr/libexec|lib|lib64|usr/local/bin|usr/local/sbin|opt)"
    if [[ ! "$path" =~ $VALID_SYSTEM_DIRS ]]; then
        echo "程序路径异常"
        return 1
    fi
    
    # === 检查4：软链接验证 ===
    if [ -L "$path" ]; then
        local link_target=$(resolve_link "$path")
        
        # 软链接目标不应该在临时目录
        if [[ "$link_target" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
            echo "软链接指向临时目录"
            return 1
        fi
        
        # 软链接目标不应该在用户目录
        if [[ "$link_target" =~ ^/home/|^/root/ ]]; then
            echo "软链接指向用户目录"
            return 1
        fi
    fi
    
    # === 检查5：文件名与路径匹配性 ===
    # 文件名应该与路径中的程序名一致
    local basename_path=$(basename "$path" 2>/dev/null)
    if [ "$basename_path" != "$name" ]; then
        # 允许一些常见的例外（如软链接别名）
        # 例如：python -> python3, vim -> vim.basic
        if [[ ! "$basename_path" =~ ^${name} ]] && [[ ! "$name" =~ ^${basename_path} ]]; then
            echo "程序名与路径不匹配"
            return 1
        fi
    fi
    
    return 0  # 验证通过
}

# ============================================================================
# 增强的权限检测函数 - 智能检测恶意权限特征
# ============================================================================
check_suspicious_permission() {
    local perm="$1"
    local file="$2"
    
    # 获取文件所有者信息（如果文件存在）
    local file_owner=""
    local file_uid=""
    if [ -f "$file" ] || [ -L "$file" ]; then
        file_owner=$(stat -c %U "$file" 2>/dev/null || echo "unknown")
        file_uid=$(stat -c %u "$file" 2>/dev/null || echo "0")
    fi
    
    # === WSL特殊文件豁免 ===
    if [ "$file" = "/init" ] || [[ "$file" =~ ^/init$ ]]; then
        return 1  # 正常
    fi
    
    # === 检测1: 恶意/挖矿木马常用权限（最高优先级）===
    # 这些权限在任何场景下都极度可疑
    case "$perm" in
        999)
            echo "挖矿木马权限(999)"
            return 0
            ;;
        1777)
            # 1777通常用于/tmp等目录，但在其他位置可疑
            if [[ ! "$file" =~ ^/(tmp|var/tmp)$ ]]; then
                echo "异常Sticky+777($perm)"
                return 0
            fi
            ;;
        4777)
            # SUID+777：任何人可执行，以文件所有者权限运行
            echo "高危SUID+777($perm)"
            return 0
            ;;
        2777)
            # SGID+777：任何人可执行，以组权限运行
            echo "高危SGID+777($perm)"
            return 0
            ;;
        6777)
            # SUID+SGID+777
            echo "极危险SUID+SGID+777($perm)"
            return 0
            ;;
        7777)
            # Sticky+SUID+SGID+777
            echo "完全开放+特殊位($perm)"
            return 0
            ;;
    esac
    
    # === 检测2: 异常/无效的权限值 ===
    # 检查包含8或9的权限（Unix权限只能0-7）
    if [[ "$perm" =~ [8-9] ]]; then
        echo "无效权限值($perm)"
        return 0
    fi
    
    # 检查权限长度异常（应该是3或4位）
    local perm_len=${#perm}
    if [ $perm_len -lt 3 ] || [ $perm_len -gt 4 ]; then
        echo "异常权限长度($perm)"
        return 0
    fi
    
    # === 检测3: 完全开放权限（基于文件类型和位置）===
    local base_perm=""
    if [ $perm_len -eq 4 ]; then
        base_perm="${perm:1:3}"
    else
        base_perm="$perm"
    fi
    
    case "$base_perm" in
        777)
            # 777在某些系统目录下可能正常，但在用户目录/临时目录可疑
            if [[ "$file" =~ ^/(home|tmp|dev/shm|var/tmp)/ ]]; then
                echo "可疑目录完全开放($perm)"
                return 0
            elif [ "$file_owner" != "root" ] && [ "$file_uid" -ge 1000 ]; then
                # 普通用户的777权限文件
                echo "非root用户777($perm)"
                return 0
            fi
            # 系统目录下root拥有的777可能是配置需要，暂不标记
            ;;
        666)
            # 666：所有人可读写（不可执行）
            echo "完全可读写($perm)"
            return 0
            ;;
        *7*7*)
            # 包含多个7的权限（如747, 757, 775, 577等）
            if [[ ! "$file" =~ ^/(bin|sbin|usr/bin|usr/sbin|lib|usr/lib)/ ]]; then
                echo "过于宽松权限($perm)"
                return 0
            fi
            ;;
    esac
    
    # === 检测4: SUID/SGID/Sticky位检测 ===
    if [ $perm_len -eq 4 ]; then
        local special_bit="${perm:0:1}"
        local base_perm="${perm:1:3}"
        
        # 非系统目录下的特殊位都可疑
        if [[ ! "$file" =~ ^/(bin|sbin|usr/bin|usr/sbin|lib|usr/lib)/ ]]; then
            case "$special_bit" in
                1)
                    # Sticky位：通常用于/tmp，其他位置可疑
                    if [[ ! "$file" =~ ^/(tmp|var/tmp)$ ]]; then
                        echo "非系统目录Sticky位($perm)"
                        return 0
                    fi
                    ;;
                2)
                    echo "非系统目录SGID($perm)"
                    return 0
                    ;;
                4)
                    echo "非系统目录SUID($perm)"
                    return 0
                    ;;
                6)
                    echo "非系统目录SUID+SGID($perm)"
                    return 0
                    ;;
                7)
                    echo "非系统目录全特殊位($perm)"
                    return 0
                    ;;
            esac
        else
            # 系统目录下的特殊位需要白名单验证
            local basename_file=$(basename "$file")
            
            # SUID白名单（标准系统工具）
            local SUID_WHITELIST="sudo|su|passwd|gpasswd|chsh|chfn|newgrp|mount|umount"
            SUID_WHITELIST="${SUID_WHITELIST}|fusermount|fusermount3|pkexec"
            SUID_WHITELIST="${SUID_WHITELIST}|dbus-daemon-launch-helper|polkit-agent-helper-1"
            SUID_WHITELIST="${SUID_WHITELIST}|at|crontab|ping|ping6|traceroute|traceroute6"
            SUID_WHITELIST="${SUID_WHITELIST}|unix_chkpwd|pam_timestamp_check"
            
            # SGID白名单（标准系统工具）
            local SGID_WHITELIST="chage|expiry|crontab|ssh-agent|wall|write|bsd-write"
            SGID_WHITELIST="${SGID_WHITELIST}|unix_chkpwd|pam_extrausers_chkpwd|unix_update"
            SGID_WHITELIST="${SGID_WHITELIST}|lockfile|dotlockfile|dotlock|mail|mutt"
            
            case "$special_bit" in
                1)
                    # Sticky位在系统目录下很少见
                    echo "系统目录异常Sticky($perm)"
                    return 0
                    ;;
                2)
                    # SGID
                    if [[ ! "$basename_file" =~ ^(${SGID_WHITELIST})$ ]]; then
                        echo "非白名单SGID($perm)"
                        return 0
                    fi
                    ;;
                4)
                    # SUID：最危险的权限
                    if [[ ! "$basename_file" =~ ^(${SUID_WHITELIST})$ ]]; then
                        echo "非白名单SUID($perm)"
                        return 0
                    fi
                    ;;
                6)
                    # SUID+SGID：极少数工具需要
                    echo "系统目录SUID+SGID($perm)"
                    return 0
                    ;;
                7)
                    # 全特殊位：极度可疑
                    echo "系统目录全特殊位($perm)"
                    return 0
                    ;;
            esac
        fi
    fi
    
    # === 检测5: 其他可疑权限模式 ===
    # 检查其他可疑权限（基于实际恶意软件使用的权限）
    case "$perm" in
        755|750|700|644|640|600)
            # 这些是正常权限，直接返回
            return 1
            ;;
        775|770|664|660)
            # 这些权限在某些场景下正常，暂不标记
            return 1
            ;;
        *)
            # 检查是否所有位都相同（如111, 222, 333等，很少见）
            if [ $perm_len -eq 3 ]; then
                local d1="${perm:0:1}"
                local d2="${perm:1:1}"
                local d3="${perm:2:1}"
                if [ "$d1" = "$d2" ] && [ "$d2" = "$d3" ] && [ "$d1" != "0" ] && [ "$d1" != "7" ]; then
                    echo "重复位权限($perm)"
                    return 0
                fi
            fi
            ;;
    esac
    
    return 1  # 正常权限
}

# 检查是否是伪造的系统进程名
check_fake_system_process() {
    local name="$1"
    local path="$2"
    
    # 常见系统进程名及其合法路径
    case "$name" in
        systemd|init)
            if [[ ! "$path" =~ ^(/usr)?/(lib|sbin)/systemd|^/sbin/init|^/init ]]; then
                echo "伪造systemd/init"
                return 0
            fi
            ;;
        sshd)
            # sshd是SSH服务端，应该在/usr/sbin/
            if [[ ! "$path" =~ ^/usr/sbin/sshd ]]; then
                echo "伪造sshd"
                return 0
            fi
            ;;
        ssh)
            # ssh是SSH客户端，应该在/usr/bin/，不是sshd
            if [[ ! "$path" =~ ^/usr/bin/ssh$ ]]; then
                # 排除ssh-agent, ssh-add等合法工具
                if [[ ! "$path" =~ ^/usr/bin/ssh- ]]; then
                    echo "伪造ssh"
                    return 0
                fi
            fi
            ;;
        cron|crond)
            if [[ ! "$path" =~ ^/usr/sbin/cron ]]; then
                echo "伪造cron"
                return 0
            fi
            ;;
        kworker)
            # kworker是内核线程，不应该有可执行文件路径
            if [ -n "$path" ] && [ "$path" != "N/A" ]; then
                echo "伪造kworker"
                return 0
            fi
            ;;
        nginx|apache2|httpd)
            if [[ ! "$path" =~ ^/usr/(s)?bin/ ]]; then
                echo "伪造Web服务"
                return 0
            fi
            ;;
        mysql|mysqld|postgres)
            if [[ ! "$path" =~ ^/usr/(s)?bin/ ]]; then
                echo "伪造数据库"
                return 0
            fi
            ;;
    esac
    
    return 1
}

# 检查软链接是否可疑
check_suspicious_symlink() {
    local file="$1"
    
    [ ! -L "$file" ] && return 1
    
    local target=$(readlink "$file" 2>/dev/null)
    [ -z "$target" ] && return 1
    
    # 检查链接到临时目录
    if [[ "$target" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
        echo "链接到临时目录"
        return 0
    fi
    
    # 检查链接到用户目录
    if [[ "$target" =~ ^/home/|^/root/ ]]; then
        echo "链接到用户目录"
        return 0
    fi
    
    # 检查链接目标不存在
    if [ ! -e "$target" ]; then
        echo "链接目标不存在"
        return 0
    fi
    
    # 检查跨目录链接（系统目录链接到非系统目录）
    if [[ "$file" =~ ^/(bin|sbin|usr/bin|usr/sbin)/ ]]; then
        if [[ ! "$target" =~ ^/(bin|sbin|usr|lib|lib64)/ ]]; then
            echo "异常跨目录链接"
            return 0
        fi
    fi
    
    return 1
}

# 检查路径是否合法
check_path_legitimacy() {
    local name="$1"
    local path="$2"
    local check_type="$3"  # binary/service/process
    
    case "$check_type" in
        binary)
            # 二进制程序应该在系统目录
            if [[ ! "$path" =~ ^/(bin|sbin|usr/bin|usr/sbin|usr/local/bin|usr/local/sbin)/ ]]; then
                echo "非标准路径"
                return 0
            fi
            ;;
        service)
            # 服务文件应该在systemd目录
            if [[ ! "$path" =~ ^/(etc|usr/lib|lib)/systemd/system/ ]]; then
                echo "非标准服务路径"
                return 0
            fi
            ;;
        process)
            # 运行进程在临时目录
            if [[ "$path" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
                echo "临时目录执行"
                return 0
            fi
            ;;
    esac
    
    return 1
}

# 打印分隔线
print_separator() {
    local char="${1:-=}"
    local length="${2:-100}"
    printf "%${length}s\n" | $CMD_TR ' ' "$char"
}

# ============================================================================
# 威胁情报收集函数 - 用于关联分析
# ============================================================================

# 添加威胁情报到全局情报库
add_threat_intel() {
    local type="$1"          # process/file/service/cron/network/module
    local identifier="$2"    # 名称或标识
    local path="$3"          # 路径
    local pid="$4"           # PID（如果是进程）
    local details="$5"       # 详细原因
    local source="$6"        # 来源检测（如"检测2"）
    
    # 添加到全局情报库
    GLOBAL_THREAT_INTEL+=("$type|$identifier|$path|$pid|$details|$source")
    
    # 记录路径信息（用于路径关联）
    if [ -n "$path" ] && [ "$path" != "N/A" ] && [ "$path" != "-" ]; then
        # 提取目录路径
        local dir_path=$(dirname "$path" 2>/dev/null || echo "")
        if [ -n "$dir_path" ] && [ "$dir_path" != "." ]; then
            if [ -n "${THREAT_PATHS[$dir_path]}" ]; then
                local old_data="${THREAT_PATHS[$dir_path]}"
                local old_count=$($CMD_ECHO "$old_data" | $CMD_CUT -d'|' -f1)
                local old_sources=$($CMD_ECHO "$old_data" | $CMD_CUT -d'|' -f2-)
                THREAT_PATHS[$dir_path]="$((old_count + 1))|${old_sources},$source"
            else
                THREAT_PATHS[$dir_path]="1|$source"
            fi
        fi
    fi
    
    # 记录进程信息（用于进程关联）
    if [ "$type" = "process" ] && [ -n "$pid" ] && [ "$pid" != "-" ]; then
        if [ -n "${THREAT_PROCESSES[$pid]}" ]; then
            local old_data="${THREAT_PROCESSES[$pid]}"
            THREAT_PROCESSES[$pid]="${old_data};${details}|${source}"
        else
            THREAT_PROCESSES[$pid]="$identifier|$path|$details|$source"
        fi
    fi
    
    # 记录文件信息（用于文件关联）
    if [ "$type" = "file" ] && [ -n "$path" ] && [ "$path" != "N/A" ] && [ "$path" != "-" ]; then
        if [ -n "${THREAT_FILES[$path]}" ]; then
            local old_data="${THREAT_FILES[$path]}"
            THREAT_FILES[$path]="${old_data};${details}|${source}"
        else
            THREAT_FILES[$path]="$type|$details|$source"
        fi
    fi
}

# 提取路径中的目录（支持多层关联）
extract_path_hierarchy() {
    local path="$1"
    local current_path="$path"
    declare -a hierarchy
    
    while [ "$current_path" != "/" ] && [ "$current_path" != "." ] && [ -n "$current_path" ]; do
        hierarchy+=("$current_path")
        current_path=$(dirname "$current_path" 2>/dev/null || echo "")
    done
    
    printf '%s\n' "${hierarchy[@]}"
}

# ============================================================================
# 威胁关联分析引擎 - 分析威胁情报之间的关联
# ============================================================================
perform_threat_correlation() {
    echo ""
    echo "============================================================================"
    echo "  [检测 15/15] 威胁关联分析 | 类别: 综合分析 | 风险: 智能评估 | 技术: 关联溯源"
    echo "============================================================================"
    
    {
        echo "================================================================================"
        echo "检测 15: 威胁关联分析 (Threat Correlation Analysis)"
        echo "================================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "分析方法: 路径关联+进程关联+文件关联+时间关联+行为关联"
        echo "分析目的: 发现攻击链、持久化机制、横向移动"
        echo ""
    } > "$LOG_CORRELATION"
    
    # 检查是否有威胁情报
    local total_threats=${#GLOBAL_THREAT_INTEL[@]}
    
    if [ $total_threats -eq 0 ]; then
        echo "[*] 未发现需要关联分析的威胁"
        {
            echo "分析结果: 未发现需要关联分析的威胁"
            echo ""
            echo "说明: 所有检测模块均未发现可疑项，系统状态正常。"
        } >> "$LOG_CORRELATION"
        echo ""
        return
    fi
    
    echo "[*] 开始关联分析..."
    echo "[*] 收集到 $total_threats 个威胁情报项"
    
    {
        echo "================================================================================"
        echo "第1部分：威胁情报汇总"
        echo "================================================================================"
        echo "收集到的威胁情报总数: $total_threats"
        echo ""
        printf "| %-10s | %-20s | %-40s | %-10s | %-30s | %-12s |\n" "类型" "标识" "路径" "PID" "详情" "来源检测"
        print_separator "-" 135
    } >> "$LOG_CORRELATION"
    
    # 输出所有威胁情报
    for intel in "${GLOBAL_THREAT_INTEL[@]}"; do
        IFS='|' read -r type identifier path pid details source <<< "$intel"
        printf "| %-10s | %-20s | %-40s | %-10s | %-30s | %-12s |\n" \
            "$type" "${identifier:0:20}" "${path:0:40}" "${pid:-N/A}" "${details:0:30}" "$source" >> "$LOG_CORRELATION"
    done
    
    {
        echo ""
        echo "================================================================================"
        echo "第2部分：路径关联分析"
        echo "================================================================================"
        echo "说明: 分析同一目录下的多个可疑项，识别恶意软件部署路径"
        echo ""
    } >> "$LOG_CORRELATION"
    
    # 路径关联分析
    local high_risk_paths=0
    declare -a correlated_paths
    
    for dir_path in "${!THREAT_PATHS[@]}"; do
        local path_data="${THREAT_PATHS[$dir_path]}"
        local count=$($CMD_ECHO "$path_data" | $CMD_CUT -d'|' -f1)
        local sources=$($CMD_ECHO "$path_data" | $CMD_CUT -d'|' -f2-)
        
        # 同一路径下有3个或以上可疑项，判定为高风险
        if [ "$count" -ge 3 ]; then
            ((high_risk_paths++))
            correlated_paths+=("$dir_path|$count|$sources")
        fi
    done
    
    if [ $high_risk_paths -gt 0 ]; then
        {
            echo "[关联发现] 检测到 $high_risk_paths 个高风险路径（包含3个以上可疑项）"
            echo ""
            printf "| %-50s | %-8s | %-60s |\n" "路径" "可疑项数" "涉及检测模块"
            print_separator "-" 125
        } >> "$LOG_CORRELATION"
        
        for path_info in "${correlated_paths[@]}"; do
            IFS='|' read -r path count sources <<< "$path_info"
            printf "| %-50s | %-8s | %-60s |\n" "${path:0:50}" "$count" "${sources:0:60}" >> "$LOG_CORRELATION"
        done
        
        {
            echo ""
            echo "[分析结论] 这些路径极可能是恶意软件的部署目录，建议立即隔离！"
            echo ""
        } >> "$LOG_CORRELATION"
        
        echo "[!!] 发现 $high_risk_paths 个高风险路径（多模块关联）"
    else
        echo "[*] 未发现高风险路径关联"
        echo "未发现高风险路径关联（同一路径下3个以上可疑项）" >> "$LOG_CORRELATION"
        echo "" >> "$LOG_CORRELATION"
    fi
    
    {
        echo "================================================================================"
        echo "第3部分：进程关联分析"
        echo "================================================================================"
        echo "说明: 分析可疑进程的多维度特征，识别复合型威胁"
        echo ""
    } >> "$LOG_CORRELATION"
    
    # 进程关联分析
    local high_risk_processes=0
    declare -a correlated_processes
    
    for pid in "${!THREAT_PROCESSES[@]}"; do
        local proc_data="${THREAT_PROCESSES[$pid]}"
        # 计算该进程被多少个检测模块标记（使用纯 Bash 字符串操作）
        local temp="${proc_data//|检测/}"
        local detection_count=$(( (${#proc_data} - ${#temp}) / 6 ))
        
        # 被2个或以上检测模块标记的进程
        if [ "$detection_count" -ge 2 ]; then
            ((high_risk_processes++))
            correlated_processes+=("$pid|$proc_data|$detection_count")
        fi
    done
    
    if [ $high_risk_processes -gt 0 ]; then
        {
            echo "[关联发现] 检测到 $high_risk_processes 个高风险进程（多模块检测命中）"
            echo ""
            printf "| %-10s | %-20s | %-40s | %-8s | %-35s |\n" "PID" "进程名" "路径" "命中数" "检测原因"
            print_separator "-" 120
        } >> "$LOG_CORRELATION"
        
        for proc_info in "${correlated_processes[@]}"; do
            IFS='|' read -r pid name path reasons sources count <<< "$proc_info"
            # 处理数据（可能包含分号分隔的多个原因）
            all_reasons=$($CMD_ECHO "$reasons" | $CMD_TR ';' ',' | $CMD_CUT -d'|' -f1)
            printf "| %-10s | %-20s | %-40s | %-8s | %-35s |\n" \
                "$pid" "${name:0:20}" "${path:0:40}" "$count" "${all_reasons:0:35}" >> "$LOG_CORRELATION"
        done
        
        {
            echo ""
            echo "[分析结论] 这些进程被多个检测模块识别，威胁置信度极高！"
            echo ""
        } >> "$LOG_CORRELATION"
        
        echo "[!!] 发现 $high_risk_processes 个高风险进程（多模块命中）"
    else
        echo "[*] 未发现高风险进程关联"
        echo "未发现高风险进程关联（多检测模块命中）" >> "$LOG_CORRELATION"
        echo "" >> "$LOG_CORRELATION"
    fi
    
    {
        echo "================================================================================"
        echo "第4部分：攻击链重建分析"
        echo "================================================================================"
        echo "说明: 基于威胁情报重建可能的攻击链和持久化机制"
        echo ""
    } >> "$LOG_CORRELATION"
    
    # 攻击链分析
    local has_initial_access=0
    local has_execution=0
    local has_persistence=0
    local has_privilege_escalation=0
    local has_evasion=0
    local has_command_control=0
    
    # 检查初始访问（Initial Access）
    for intel in "${GLOBAL_THREAT_INTEL[@]}"; do
        if [[ "$intel" =~ (反向|shell|下载|wget|curl|nc -e|bash -i) ]]; then
            has_initial_access=1
            break
        fi
    done
    
    # 检查执行（Execution）
    for intel in "${GLOBAL_THREAT_INTEL[@]}"; do
        if [[ "$intel" =~ (可执行|/tmp/|/dev/shm/|高熵命名|伪造) ]]; then
            has_execution=1
            break
        fi
    done
    
    # 检查持久化（Persistence）
    for intel in "${GLOBAL_THREAT_INTEL[@]}"; do
        if [[ "$intel" =~ (cron|service|rc.local|检测11|检测14|检测9) ]]; then
            has_persistence=1
            break
        fi
    done
    
    # 检查权限提升（Privilege Escalation）
    for intel in "${GLOBAL_THREAT_INTEL[@]}"; do
        if [[ "$intel" =~ (SUID|SGID|4777|6777|权限) ]]; then
            has_privilege_escalation=1
            break
        fi
    done
    
    # 检查防御规避（Defense Evasion）
    for intel in "${GLOBAL_THREAT_INTEL[@]}"; do
        if [[ "$intel" =~ (隐藏|rootkit|LD_PRELOAD|伪装|hidden) ]]; then
            has_evasion=1
            break
        fi
    done
    
    # 检查命令控制（Command and Control）
    for intel in "${GLOBAL_THREAT_INTEL[@]}"; do
        if [[ "$intel" =~ (网络|连接|守护|daemon|检测6) ]]; then
            has_command_control=1
            break
        fi
    done
    
    local attack_chain_score=$((has_initial_access + has_execution + has_persistence + has_privilege_escalation + has_evasion + has_command_control))
    
    {
        echo "[攻击链分析] MITRE ATT&CK 战术检测"
        echo ""
        printf "| %-30s | %-10s | %-60s |\n" "战术阶段" "检测到" "说明"
        print_separator "-" 105
    } >> "$LOG_CORRELATION"
    
    local status
    
    [ $has_initial_access -eq 1 ] && status="是" || status="否"
    printf "| %-30s | %-10s | %-60s |\n" "初始访问 (Initial Access)" "$status" "反向Shell、远程下载" >> "$LOG_CORRELATION"
    
    [ $has_execution -eq 1 ] && status="是" || status="否"
    printf "| %-30s | %-10s | %-60s |\n" "执行 (Execution)" "$status" "可疑可执行文件" >> "$LOG_CORRELATION"
    
    [ $has_persistence -eq 1 ] && status="是" || status="否"
    printf "| %-30s | %-10s | %-60s |\n" "持久化 (Persistence)" "$status" "Cron任务、Systemd服务、启动项" >> "$LOG_CORRELATION"
    
    [ $has_privilege_escalation -eq 1 ] && status="是" || status="否"
    printf "| %-30s | %-10s | %-60s |\n" "权限提升 (Privilege Escalation)" "$status" "SUID/SGID异常权限" >> "$LOG_CORRELATION"
    
    [ $has_evasion -eq 1 ] && status="是" || status="否"
    printf "| %-30s | %-10s | %-60s |\n" "防御规避 (Defense Evasion)" "$status" "进程隐藏、Rootkit、LD_PRELOAD" >> "$LOG_CORRELATION"
    
    [ $has_command_control -eq 1 ] && status="是" || status="否"
    printf "| %-30s | %-10s | %-60s |\n" "命令控制 (Command & Control)" "$status" "可疑网络连接、守护进程" >> "$LOG_CORRELATION"
    
    {
        echo ""
        echo "[威胁评分] 攻击链完整度: $attack_chain_score/6"
        echo ""
    } >> "$LOG_CORRELATION"
    
    if [ $attack_chain_score -ge 4 ]; then
        {
            echo "[!!!] 严重威胁: 检测到完整的攻击链（$attack_chain_score/6阶段）"
            echo "      这表明系统可能已被完全入侵，攻击者已建立持久化机制和命令控制通道。"
            echo "      建议: 立即隔离系统，进行深度取证分析，重装系统前备份关键数据。"
        } >> "$LOG_CORRELATION"
        echo "[!!!] 严重威胁: 检测到完整攻击链（$attack_chain_score/6阶段）"
        DETECTION_RESULTS+=("[HIGH] 威胁关联分析: 检测到完整攻击链（$attack_chain_score/6阶段）")
    elif [ $attack_chain_score -ge 2 ]; then
        {
            echo "[!!] 中等威胁: 检测到部分攻击链（$attack_chain_score/6阶段）"
            echo "     这表明系统可能正在遭受攻击或已被部分入侵。"
            echo "     建议: 立即进行详细调查，隔离可疑项，加强监控。"
        } >> "$LOG_CORRELATION"
        echo "[!!] 中等威胁: 检测到部分攻击链（$attack_chain_score/6阶段）"
        DETECTION_RESULTS+=("[MEDIUM] 威胁关联分析: 检测到部分攻击链（$attack_chain_score/6阶段）")
    else
        {
            echo "[*] 低风险: 仅检测到孤立的可疑项（$attack_chain_score/6阶段）"
            echo "    这些可疑项可能是误报或孤立的异常，但仍需进一步调查。"
        } >> "$LOG_CORRELATION"
        echo "[*] 低风险: 仅检测到孤立可疑项（$attack_chain_score/6阶段）"
    fi
    
    {
        echo ""
        echo "================================================================================"
        echo "第5部分：关联分析总结"
        echo "================================================================================"
        echo ""
        echo "威胁情报统计:"
        echo "  - 总威胁项: $total_threats"
        echo "  - 高风险路径: $high_risk_paths"
        echo "  - 高风险进程: $high_risk_processes"
        echo "  - 攻击链完整度: $attack_chain_score/6"
        echo ""
        echo "关联分析结论:"
        if [ $attack_chain_score -ge 4 ] || [ $high_risk_paths -ge 2 ] || [ $high_risk_processes -ge 2 ]; then
            echo "  [!!!] 系统极可能已被入侵，发现多个强关联的威胁指标。"
            echo "        建议立即采取应急响应措施，隔离系统并进行深度取证。"
        elif [ $attack_chain_score -ge 2 ] || [ $high_risk_paths -ge 1 ] || [ $high_risk_processes -ge 1 ]; then
            echo "  [!!] 系统存在安全风险，发现关联的可疑行为。"
            echo "       建议进行详细调查，确认是否为误报或真实威胁。"
        else
            echo "  [*] 检测到的可疑项之间关联度较低，可能为孤立异常或误报。"
            echo "      建议进行人工复核，排除误报可能。"
        fi
        echo ""
        echo "================================================================================"
    } >> "$LOG_CORRELATION"
    
    echo "[*] 关联分析完成，详见: $(basename "$LOG_CORRELATION")"
    echo ""
}

# 打印检测标题（控制台）
print_check_title() {
    local check_num="$1"
    local title="$2"
    local category="$3"
    local risk_level="$4"
    local tech="$5"
    
    # 格式化检测编号（补零）
    local formatted_num=$(printf "%02d" "$check_num")
    
    echo ""
    echo "+============================================================================+"
    echo "| [检测 ${formatted_num}/14] ${title}"
    echo "| 类别: ${category} | 风险等级: ${risk_level} | 检测技术: ${tech}"
    echo "+============================================================================+"
}

# 打印检测信息（控制台）
print_check_info() {
    local label="$1"
    local content="$2"
    echo "> ${label}: ${content}"
}

# 打印统计信息（控制台）
print_statistics() {
    local total="$1"
    local suspicious="$2"
    local details="$3"
    
    echo ""
    echo "[*] 统计信息:"
    echo "   总检测数: ${total}"
    echo "   可疑数量: ${suspicious}"
    if [ -n "$details" ]; then
        echo "   详细统计: ${details}"
    fi
}

# 打印结果（控制台）
print_result() {
    local level="$1"
    local message="$2"
    
    case "$level" in
        "OK")
            echo ""
            echo "[OK] 检测结果: ${message}"
            ;;
        "WARN")
            echo ""
            echo "[WARN] 检测结果: ${message}"
            ;;
        "CRITICAL")
            echo ""
            echo "[CRIT] 检测结果: ${message}"
            ;;
    esac
}

# ============================================================================
# 主程序开始
# ============================================================================

clear
echo "+============================================================================+"
echo "|                      Linux 进程检测脚本 v2.1                               |"
echo "+============================================================================+"
echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "主机名称: $(hostname)"
echo "时间范围: ${TIME_DESC} (基准日期: ${BASELINE_DATE_STR})"
echo "日志目录: ${LOG_DIR}"

# 显示Busybox模式状态
if [ $USE_BUSYBOX -eq 1 ]; then
    echo ""
    echo "+----------------------------------------------------------------------------+"
    echo "| [安全模式] Busybox 已启用                                                  |"
    echo "| 路径: $BUSYBOX_PATH"
    echo "| 说明: 所有命令将通过 Busybox 执行，防止系统命令被篡改                      |"
    echo "+----------------------------------------------------------------------------+"
    echo ""
fi

echo "[提示] 已清理旧日志和临时文件"
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "[!] 警告: 以 root 权限运行可获取完整信息 (sudo $0)"
    echo ""
fi

if [ -n "$OUTPUT_FILE" ]; then
    exec > >(tee -a "$OUTPUT_FILE")
    exec 2>&1
    echo "输出文件: $OUTPUT_FILE"
    echo ""
fi

echo "================================================================================"
echo "  开始安全检测分析..."
echo "  [安全提示] 本脚本仅执行只读检测，不会修改系统任何文件或配置"
echo "================================================================================"

# ============================================================================
# 检测 1: PS 命令与 /proc 目录对比
# ============================================================================
check_ps_proc_diff() {
    print_check_title "1" "隐藏进程检测 - PS vs /proc 对比" "进程检测" "高危" "Rootkit检测"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH ps -eo pid && $BUSYBOX_PATH ls /proc/"
    else
        DISPLAY_CMD="ps -eo pid && ls /proc/"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "通过比对 PS 命令输出和 /proc 目录，检测被 rootkit 隐藏的进程"
    
    {
        echo "================================================================"
        echo "检测 1: PS 命令与 /proc 目录对比检测"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测命令: $DISPLAY_CMD"
        echo "检测策略: 通过比对 PS 命令输出和 /proc 目录，检测被 rootkit 隐藏的进程"
        echo ""
    } > "$LOG_PS_PROC"
    
    PS_OUTPUT=$($CMD_PS -e -o pid= 2>/dev/null | $CMD_AWK '{print $1}' | $CMD_SORT -n)
    PS_COUNT=$($CMD_ECHO "$PS_OUTPUT" | $CMD_WC -l)
    PS_COUNT=${PS_COUNT//[^0-9]/}
    PS_COUNT=${PS_COUNT:-0}
    
    PROC_OUTPUT=$($CMD_LS /proc/ 2>/dev/null | $CMD_GREP -E '^[0-9]+$' | $CMD_SORT -n)
    PROC_COUNT=$($CMD_ECHO "$PROC_OUTPUT" | $CMD_WC -l)
    PROC_COUNT=${PROC_COUNT//[^0-9]/}
    PROC_COUNT=${PROC_COUNT:-0}
    
    SCRIPT_PID=$$
    SCRIPT_PPID=$($CMD_GREP "^PPid:" "/proc/$SCRIPT_PID/status" 2>/dev/null | $CMD_AWK '{print $2}')
    SCRIPT_PGID=$($CMD_PS -o pgid= -p $SCRIPT_PID 2>/dev/null | $CMD_TR -d ' ')
    
    declare -a SUSPICIOUS_PROCESSES
    declare -a NORMAL_PROCESSES
    DIFF_COUNT=0
    SKIPPED_COUNT=0
    
    while read -r pid; do
        [ ! -d "/proc/$pid" ] && continue
            
            NAME=$($CMD_GREP "^Name:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
            [ -z "$NAME" ] && NAME=$($CMD_CAT "/proc/$pid/comm" 2>/dev/null | $CMD_TR -d '\n')
            [ -z "$NAME" ] && NAME="[unknown]"
            
            EXE=$($CMD_READLINK "/proc/$pid/exe" 2>/dev/null)
            [ -z "$EXE" ] && EXE="N/A"
        
        if ! $CMD_ECHO "$PS_OUTPUT" | $CMD_GREP -q "^${pid}$"; then
            PGID=$($CMD_PS -o pgid= -p $pid 2>/dev/null | $CMD_TR -d ' ')
            if [ "$pid" = "$SCRIPT_PID" ] || [ "$pid" = "$SCRIPT_PPID" ] || [ "$PGID" = "$SCRIPT_PGID" ]; then
                ((SKIPPED_COUNT++))
                continue
            fi
            
            STATUS="异常"
            if [ ! -r "/proc/$pid/exe" ] && [ -r "/proc/$pid/status" ]; then
                # 注意：Busybox grep 不支持 \s，使用空格匹配
                $CMD_GREP -q "^VmSize:[ 	]*0 kB" "/proc/$pid/status" 2>/dev/null && STATUS="内核线程"
            fi
            
            ((DIFF_COUNT++))
            SUSPICIOUS_PROCESSES+=("可疑|$pid|$NAME|$EXE|$STATUS")
        else
            NORMAL_PROCESSES+=("正常|$pid|$NAME|$EXE|PS匹配")
        fi
    done <<< "$PROC_OUTPUT"
    
    # 首先输出PS命令的完整进程列表
    {
        echo "================================================================================"
        echo "第1部分：PS命令输出的进程列表（共 $PS_COUNT 个）"
        echo "================================================================================"
        echo "$PS_OUTPUT" | while read -r pid; do
            [ -z "$pid" ] && continue
            NAME=$($CMD_PS -p "$pid" -o comm= 2>/dev/null | $CMD_TR -d '\n')
            [ -z "$NAME" ] && NAME="unknown"
            printf "PID: %-10s | 进程名: %-30s\n" "$pid" "$NAME"
        done
        echo ""
    } >> "$LOG_PS_PROC"
    
    # 然后输出/proc目录的完整进程列表
    {
        echo "================================================================================"
        echo "第2部分：/proc目录下的进程列表（共 $PROC_COUNT 个）"
        echo "================================================================================"
        echo "$PROC_OUTPUT" | while read -r pid; do
            [ -z "$pid" ] && continue
            [ ! -d "/proc/$pid" ] && continue
            NAME=$($CMD_GREP "^Name:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
            [ -z "$NAME" ] && NAME=$($CMD_CAT "/proc/$pid/comm" 2>/dev/null | $CMD_TR -d '\n')
            [ -z "$NAME" ] && NAME="unknown"
            EXE=$($CMD_READLINK "/proc/$pid/exe" 2>/dev/null)
            [ -z "$EXE" ] && EXE="N/A"
            printf "PID: %-10s | 进程名: %-20s | 路径: %-60s\n" "$pid" "$NAME" "$EXE"
        done
        echo ""
    } >> "$LOG_PS_PROC"
    
    # 最后输出对比结果
    {
        echo "================================================================================"
        echo "第3部分：对比结果（可疑进程排在前面）"
        echo "================================================================================"
        printf "| %-10s | %-10s | %-25s | %-55s | %-20s |\n" "状态" "PID" "进程名" "可执行文件路径" "备注"
        print_separator "-" 135
    } >> "$LOG_PS_PROC"
    
    # 输出所有可疑进程
    for proc_info in "${SUSPICIOUS_PROCESSES[@]}"; do
        IFS='|' read -r status pid name exe note <<< "$proc_info"
        printf "| %-10s | %-10s | %-25s | %-55s | %-20s |\n" "$status" "$pid" "${name:0:25}" "${exe:0:55}" "$note" >> "$LOG_PS_PROC"
    done
    
    # 输出所有正常进程
    for proc_info in "${NORMAL_PROCESSES[@]}"; do
        IFS='|' read -r status pid name exe note <<< "$proc_info"
        printf "| %-10s | %-10s | %-25s | %-55s | %-20s |\n" "$status" "$pid" "${name:0:25}" "${exe:0:55}" "$note" >> "$LOG_PS_PROC"
    done
    
    {
        print_separator "=" 120
        echo ""
        echo "统计信息:"
        echo "  PS 命令输出进程数: $PS_COUNT"
        echo "  /proc 目录进程数: $PROC_COUNT"
        echo "  差异进程数: $DIFF_COUNT"
        echo "  跳过进程数: $SKIPPED_COUNT"
        echo ""
    } >> "$LOG_PS_PROC"
    
    echo ""
    if [ $DIFF_COUNT -gt 0 ]; then
        echo "发现可疑进程 (仅显示可疑项):"
        echo ""
        printf "%-25s  %-8s  %-60s  %-25s\n" "进程名" "PID" "可执行文件路径" "备注"
        print_separator "-" 125
        
        for proc_info in "${SUSPICIOUS_PROCESSES[@]}"; do
            IFS='|' read -r status pid name exe note <<< "$proc_info"
            printf "%-25s  %-8s  %-60s  %-25s\n" "${name:0:25}" "$pid" "${exe:0:60}" "$note"
        done
    else
        echo "未发现可疑进程"
    fi
    
    print_statistics "$PROC_COUNT" "$DIFF_COUNT" "PS进程=${PS_COUNT}, /proc进程=${PROC_COUNT}, 差异=${DIFF_COUNT}"
    
    if [ $DIFF_COUNT -eq 0 ]; then
        print_result "OK" "正常，PS 和 /proc 匹配"
        add_detection "INFO" "检测 1: PS 和 /proc 匹配"
        echo "Result: Normal" >> "$LOG_PS_PROC"
    else
        LOG_BASENAME=$($CMD_BASENAME "$LOG_PS_PROC")
        print_result "WARN" "发现 ${DIFF_COUNT} 个差异进程 (详见日志: ${LOG_BASENAME})"
        add_detection "MEDIUM" "检测 1: 发现 ${DIFF_COUNT} 个进程差异"
        echo "Result: Warning - Found ${DIFF_COUNT} process differences" >> "$LOG_PS_PROC"
    fi
}

# ============================================================================
# 检测 2: 进程工作目录检查
# ============================================================================
check_process_workdir() {
    print_check_title "2" "进程工作目录与路径检查" "进程分析" "高危" "多维度检测"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH readlink /proc/*/cwd && $BUSYBOX_PATH readlink /proc/*/exe"
    else
        DISPLAY_CMD="readlink /proc/*/cwd && readlink /proc/*/exe"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "累积检测: 1)已删除/临时目录 2)伪造系统进程 3)伪装内核线程 4)可疑关键词 5)软链接 6)权限 7)高熵命名"
    
    {
        echo "================================================================"
        echo "检测 2: 进程工作目录检查"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测命令: readlink /proc/*/cwd && readlink /proc/*/exe"
        echo "检测策略: 全面检查进程路径、权限、命名、伪装等可疑特征"
        echo "检测维度: 路径/权限/命名熵值/软链接/伪造进程/已删除程序"
        echo ""
    } > "$LOG_WORKDIR"
    
    declare -a SUSPICIOUS_PROCESSES
    declare -a NORMAL_PROCESSES
    
    DELETED_COUNT=0
    SUSPICIOUS_DIR_COUNT=0
    SUSPICIOUS_PERM_COUNT=0
    SUSPICIOUS_NAME_COUNT=0
    FAKE_PROCESS_COUNT=0
    SUSPICIOUS_SYMLINK_COUNT=0
    NORMAL_COUNT=0
    TOTAL_PROC_COUNT=0
    
    for pid in $($CMD_LS /proc/ 2>/dev/null | $CMD_GREP -E '^[0-9]+$' | $CMD_SORT -n); do
        [ ! -d "/proc/$pid" ] && continue
        
        NAME=$($CMD_GREP "^Name:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
        [ -z "$NAME" ] && NAME="unknown"
        CWD=$($CMD_READLINK "/proc/$pid/cwd" 2>/dev/null)
        EXE=$($CMD_READLINK "/proc/$pid/exe" 2>/dev/null)
        
        # 如果是解释器，尝试获取实际脚本路径
        SCRIPT_PATH=""
        if [[ "$EXE" =~ (bash|sh|python|python2|python3|perl|ruby|php)$ ]]; then
            # 读取 cmdline，第二个参数通常是脚本路径
            CMDLINE=$($CMD_CAT "/proc/$pid/cmdline" 2>/dev/null | $CMD_TR '\0' ' ')
            # 尝试提取脚本路径（通常是第二个参数）
            SCRIPT_PATH=$(echo "$CMDLINE" | $CMD_AWK '{print $2}' 2>/dev/null)
            # 如果脚本路径是绝对路径且存在，使用它来检测
            if [[ "$SCRIPT_PATH" =~ ^/ ]] && [ -f "$SCRIPT_PATH" ]; then
                # 保留原始 EXE，但在后续检测中也考虑脚本路径
                :
            else
                SCRIPT_PATH=""
            fi
        fi
        
        # 跳过WSL特殊进程和脚本自身
        if [[ "$NAME" =~ ^(init\(|SessionLeader|Relay\() ]]; then
            continue
        fi
        
        # 跳过WSL的/init进程
        if [ "$NAME" = "init" ] && [ "$EXE" = "/init" ]; then
            continue
        fi
        
        # 跳过脚本自身进程
        if [ $pid -eq $$ ] || [[ "$NAME" =~ ^process_scanner ]]; then
            continue
        fi
        
        # 只有有效进程才计数
        ((TOTAL_PROC_COUNT++))
        
        SUSPICIOUS_REASONS=()
        IS_SUSPICIOUS=0
        
        # 检查1：已删除程序（最高优先级）
        if [[ "$EXE" == *"(deleted)"* ]]; then
            SUSPICIOUS_REASONS+=("已删除程序")
            ((DELETED_COUNT++))
            IS_SUSPICIOUS=1
        fi
        
        # 检查2：可疑路径（临时目录执行）
        if [[ "$EXE" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
            SUSPICIOUS_REASONS+=("临时目录执行")
            ((SUSPICIOUS_DIR_COUNT++))
            IS_SUSPICIOUS=1
        elif [ -n "$SCRIPT_PATH" ] && [[ "$SCRIPT_PATH" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
            SCRIPT_DIR=$(dirname "$SCRIPT_PATH" 2>/dev/null)
            SUSPICIOUS_REASONS+=("临时目录脚本")
            ((SUSPICIOUS_DIR_COUNT++))
            IS_SUSPICIOUS=1
            # 更新显示为更有意义的信息
            INTERPRETER_NAME=$($CMD_BASENAME "$EXE")
            EXE="$SCRIPT_PATH (via $INTERPRETER_NAME)"
            # 如果原工作目录不在临时目录，更新为脚本目录（更直观）
            if [[ ! "$CWD" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
                CWD="$SCRIPT_DIR (脚本位置)"
            fi
        elif [[ "$CWD" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
            SUSPICIOUS_REASONS+=("临时目录工作")
            ((SUSPICIOUS_DIR_COUNT++))
            IS_SUSPICIOUS=1
        fi
        
        # 检查3：系统进程白名单验证（信任但验证）- 所有关键系统进程必须验证
        IS_WHITELIST=0
        # 基础工具
        local WHITELIST_CHECK="sha1sum|sha224sum|sha256sum|sha384sum|sha512sum|md5sum|base64|base32"
        WHITELIST_CHECK="${WHITELIST_CHECK}|e2fsck|e2label|e4crypt|e4defrag|e2freefrag|resize2fs|dumpe2fs|tune2fs|mke2fs"
        WHITELIST_CHECK="${WHITELIST_CHECK}|py3compile|py3clean|python2|python3|perl5"
        WHITELIST_CHECK="${WHITELIST_CHECK}|pod2html|pod2text|pod2usage|pod2man"
        WHITELIST_CHECK="${WHITELIST_CHECK}|fusermount|fusermount3|killall5|runlevel|telinit|ec2metadata"
        WHITELIST_CHECK="${WHITELIST_CHECK}|chage|chfn|chsh|chgpasswd|newgrp"
        
        # ✨ 新增：核心系统守护进程（必须验证！）
        WHITELIST_CHECK="${WHITELIST_CHECK}|systemd|init|systemctl|journalctl"
        WHITELIST_CHECK="${WHITELIST_CHECK}|sshd|crond|cron|atd"
        WHITELIST_CHECK="${WHITELIST_CHECK}|rsyslogd|syslogd|auditd|dbus-daemon"
        WHITELIST_CHECK="${WHITELIST_CHECK}|NetworkManager|polkitd|cupsd"
        
        # ✨ 新增：Web服务和数据库（必须验证！）
        WHITELIST_CHECK="${WHITELIST_CHECK}|nginx|apache2|httpd"
        WHITELIST_CHECK="${WHITELIST_CHECK}|mysql|mysqld|postgres|postgresql"
        
        if [[ "$NAME" =~ ^(${WHITELIST_CHECK})$ ]] && [ -n "$EXE" ] && [[ ! "$EXE" =~ deleted ]]; then
            IS_WHITELIST=1
            
            # 白名单程序进行深度验证（返回0=成功，1=失败）
            whitelist_error=$(verify_whitelist_program "$NAME" "$EXE" "1" 2>&1)
            if [ $? -ne 0 ]; then
                # 验证失败，记录为高危伪造
                SUSPICIOUS_REASONS+=("白名单伪造:$whitelist_error")
                ((FAKE_PROCESS_COUNT++))
                IS_SUSPICIOUS=1
            fi
        fi
        
        # 非白名单程序才进行常规检测
        if [ $IS_WHITELIST -eq 0 ]; then
            # === 累积检测策略（不互斥，检测所有可疑特征）===
            
            # 检测1: 检查伪造系统进程名（详细路径验证）
            if [ -n "$EXE" ] && [ "$EXE" != "N/A" ] && [[ ! "$EXE" =~ deleted ]]; then
                if fake_reason=$(check_fake_system_process "$NAME" "$EXE"); then
                    SUSPICIOUS_REASONS+=("伪造:$fake_reason")
                    ((FAKE_PROCESS_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 检测2: 检查内核进程伪装（进程名包含中括号[]）
            if [[ "$NAME" =~ ^\[.*\]$ ]]; then
                # 内核线程通常没有可执行文件路径或路径为空
                if [ -n "$EXE" ] && [ "$EXE" != "N/A" ] && [[ ! "$EXE" =~ ^$ ]]; then
                    SUSPICIOUS_REASONS+=("伪装内核线程")
                    ((FAKE_PROCESS_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 检测3: 检查可疑关键词
            local keywords=("hidden" "stealth" "suspicious" "malicious" "backdoor" "rootkit" "trojan" "payload" "exploit" "reverse" "shell")
            local matched_keywords=()
            for keyword in "${keywords[@]}"; do
                if [[ "$NAME" =~ $keyword ]] || [[ "$EXE" =~ $keyword ]]; then
                    matched_keywords+=("$keyword")
                fi
            done
            if [ ${#matched_keywords[@]} -gt 0 ]; then
                local all_keywords=$(IFS=','; echo "${matched_keywords[*]}")
                SUSPICIOUS_REASONS+=("可疑关键词($all_keywords)")
                ((FAKE_PROCESS_COUNT++))
                IS_SUSPICIOUS=1
            fi
            
            # 检测4: 检查攻击工具命名
            ATTACK_PATTERNS="(maker|inject|spawn|hijack|daemon)"
            if [[ "$NAME" =~ $ATTACK_PATTERNS ]]; then
                SUSPICIOUS_REASONS+=("攻击工具命名")
                ((FAKE_PROCESS_COUNT++))
                IS_SUSPICIOUS=1
            fi
            
            # 检测5: 检查fake标识
            if [[ "$NAME" =~ ^fake ]]; then
                SUSPICIOUS_REASONS+=("伪造标识(fake)")
                ((FAKE_PROCESS_COUNT++))
                IS_SUSPICIOUS=1
            fi
            
            # 检测6：可疑软链接
            if [ -n "$EXE" ] && [ "$EXE" != "N/A" ] && [[ ! "$EXE" =~ deleted ]]; then
                if [ -L "/proc/$pid/exe" ]; then
                    if symlink_reason=$(check_suspicious_symlink "/proc/$pid/exe"); then
                        SUSPICIOUS_REASONS+=("软链接:$symlink_reason")
                        ((SUSPICIOUS_SYMLINK_COUNT++))
                        IS_SUSPICIOUS=1
                    fi
                fi
            fi
            
            # 检测7：高熵命名（只有在没有其他更明确的检测时才用）
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if [ "$(check_name_entropy "$NAME")" = "1" ]; then
                    SUSPICIOUS_REASONS+=("高熵命名")
                    ((SUSPICIOUS_NAME_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
        fi
        
        # 计算命名熵值（用于显示）
        NAME_ENTROPY=$(calculate_shannon_entropy "$NAME")
        NAME_ENTROPY=$(printf "%.2f" $NAME_ENTROPY 2>/dev/null || echo "0.00")
        
        # 检查7：可疑权限（如果可执行文件存在）
        if [ -n "$EXE" ] && [ "$EXE" != "N/A" ] && [[ ! "$EXE" =~ deleted ]] && [ -f "$EXE" ]; then
            FILE_PERM=$($CMD_STAT -c %a "$EXE" 2>/dev/null || echo "000")
            if perm_reason=$(check_suspicious_permission "$FILE_PERM" "$EXE"); then
                SUSPICIOUS_REASONS+=("权限:$perm_reason")
                ((SUSPICIOUS_PERM_COUNT++))
                IS_SUSPICIOUS=1
            fi
        fi
        
        if [ $IS_SUSPICIOUS -eq 1 ]; then
            ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
            SUSPICIOUS_PROCESSES+=("可疑|$pid|$NAME|$CWD|$EXE|$NAME_ENTROPY|$ALL_REASONS")
            
            # 添加到全局威胁情报库（用于关联分析）
            add_threat_intel "process" "$NAME" "$EXE" "$pid" "$ALL_REASONS" "检测2"
        else
            ((NORMAL_COUNT++))
            NORMAL_PROCESSES+=("正常|$pid|$NAME|$CWD|$EXE|$NAME_ENTROPY|正常")
        fi
    done
    
    {
        echo "--------------------------------------------------------------------------------"
        echo "完整数据列表（可疑进程排在前面）"
        echo "--------------------------------------------------------------------------------"
        printf "| %-10s | %-10s | %-18s | %-30s | %-40s | %-10s | %-35s |\n" "状态" "PID" "进程名" "工作目录" "可执行文件" "熵值" "检测原因"
        print_separator "-" 165
    } >> "$LOG_WORKDIR"
    
    # 输出所有可疑进程
    for proc_info in "${SUSPICIOUS_PROCESSES[@]}"; do
        IFS='|' read -r status pid name cwd exe entropy reasons <<< "$proc_info"
        printf "| %-10s | %-10s | %-18s | %-30s | %-40s | %-10s | %-35s |\n" "$status" "$pid" "${name:0:18}" "${cwd:0:30}" "${exe:0:40}" "$entropy" "${reasons:0:35}" >> "$LOG_WORKDIR"
    done
    
    # 输出所有正常进程
    for proc_info in "${NORMAL_PROCESSES[@]}"; do
        IFS='|' read -r status pid name cwd exe entropy reasons <<< "$proc_info"
        printf "| %-10s | %-10s | %-18s | %-30s | %-40s | %-10s | %-35s |\n" "$status" "$pid" "${name:0:18}" "${cwd:0:30}" "${exe:0:40}" "$entropy" "${reasons:0:35}" >> "$LOG_WORKDIR"
    done
    
    {
        print_separator "=" 135
        echo ""
        echo "统计信息:"
        echo "  总进程数: $TOTAL_PROC_COUNT"
        echo "  已删除程序: $DELETED_COUNT"
        echo "  可疑目录进程: $SUSPICIOUS_DIR_COUNT"
        echo "  可疑权限: $SUSPICIOUS_PERM_COUNT"
        echo "  可疑命名: $SUSPICIOUS_NAME_COUNT"
        echo "  伪造进程: $FAKE_PROCESS_COUNT"
        echo "  可疑软链接: $SUSPICIOUS_SYMLINK_COUNT"
        echo "  正常进程: $NORMAL_COUNT"
        echo ""
    } >> "$LOG_WORKDIR"
    
    echo ""
    # 使用数组长度统计真实的可疑进程数量（避免同一进程多个原因导致重复计数）
    SUSPICIOUS_TOTAL=${#SUSPICIOUS_PROCESSES[@]}
    if [ $SUSPICIOUS_TOTAL -gt 0 ]; then
        echo "发现可疑进程 (仅显示可疑项):"
        echo ""
        printf "%-20s %-6s %-6s %-30s %-40s %-30s\n" "进程名" "PID" "熵值" "工作目录" "可执行文件" "检测原因"
        print_separator "-" 138
        
        for proc_info in "${SUSPICIOUS_PROCESSES[@]}"; do
            IFS='|' read -r status pid name cwd exe entropy reasons <<< "$proc_info"
            printf "%-20s %-6s %-6s %-30s %-40s %-30s\n" "${name:0:20}" "$pid" "$entropy" "${cwd:0:30}" "${exe:0:40}" "${reasons:0:30}"
        done
    else
        echo "未发现可疑进程"
    fi
    
    # 计算严重级别的数量（排除仅"可疑目录"或"高熵命名"的）
    # 严重级别包括：已删除、权限、伪造、软链接
    CRITICAL_COUNT=0
    for proc_info in "${SUSPICIOUS_PROCESSES[@]}"; do
        IFS='|' read -r status pid name cwd exe entropy reasons <<< "$proc_info"
        # 如果包含严重原因（已删除、权限、伪造、软链接），则计入严重
        if [[ "$reasons" =~ (已删除|权限:|伪造|软链接:) ]]; then
            ((CRITICAL_COUNT++))
        fi
    done
    
    print_statistics "$TOTAL_PROC_COUNT" "$SUSPICIOUS_TOTAL" "已删除=$DELETED_COUNT, 可疑目录=$SUSPICIOUS_DIR_COUNT, 权限=$SUSPICIOUS_PERM_COUNT, 高熵命名=$SUSPICIOUS_NAME_COUNT, 伪造=$FAKE_PROCESS_COUNT, 软链接=$SUSPICIOUS_SYMLINK_COUNT"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_WORKDIR")
    if [ $CRITICAL_COUNT -gt 0 ]; then
        print_result "CRITICAL" "发现 ${SUSPICIOUS_TOTAL} 个可疑进程 (严重=${CRITICAL_COUNT}) (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 2: 发现 ${SUSPICIOUS_TOTAL} 个可疑进程"
        echo "Result: Critical - Found ${SUSPICIOUS_TOTAL} suspicious processes" >> "$LOG_WORKDIR"
    elif [ $SUSPICIOUS_DIR_COUNT -gt 0 ]; then
        print_result "WARN" "发现 ${SUSPICIOUS_DIR_COUNT} 个可疑目录进程 (详见日志: ${LOG_BASENAME})"
        add_detection "MEDIUM" "检测 2: 发现 ${SUSPICIOUS_DIR_COUNT} 个可疑目录进程"
        echo "Result: Warning" >> "$LOG_WORKDIR"
    else
        print_result "OK" "正常，路径检查通过"
        add_detection "INFO" "检测 2: 路径正常"
        echo "Result: Normal" >> "$LOG_WORKDIR"
    fi
}

# ============================================================================
# 检测 3: 文件修改时间检查
# ============================================================================
check_file_mtime() {
    print_check_title "3" "可执行文件修改时间检查" "文件完整性" "中危" "时间线分析"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH stat -c '%Y' /proc/*/exe"
    else
        DISPLAY_CMD="stat -c '%Y' /proc/*/exe"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "检查进程可执行文件的修改时间，识别${TIME_DESC}内修改的程序"
    
    {
        echo "================================================================"
        echo "检测 3: 文件修改时间检查"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "时间范围: ${TIME_DESC}"
        echo "检测命令: stat -c '%Y' /proc/*/exe"
        echo "检测策略: 检查进程可执行文件的修改时间"
        echo ""
    } > "$LOG_MTIME"
    
    declare -a RECENT_PROCESSES
    declare -a ALL_PROCESSES
    RECENT_MODIFIED=0
    TOTAL_CHECKED=0
    
    for pid in $($CMD_LS /proc/ 2>/dev/null | $CMD_GREP -E '^[0-9]+$'); do
        # 跳过脚本自身
        [ $pid -eq $$ ] && continue
        
        NAME=$($CMD_GREP "^Name:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
        
        # 跳过WSL特殊进程和脚本自身
        if [[ "$NAME" =~ ^(init\(|SessionLeader|Relay\(|process_scanner) ]]; then
            continue
        fi
        
        # 跳过WSL的/init进程
        EXE=$($CMD_READLINK "/proc/$pid/exe" 2>/dev/null)
        if [ "$NAME" = "init" ] && [ "$EXE" = "/init" ]; then
            continue
        fi
        
        if [ -n "$EXE" ] && [ -f "$EXE" ] && [[ ! "$EXE" == *"deleted"* ]]; then
            ((TOTAL_CHECKED++))
            MTIME=$($CMD_STAT -c '%Y' "$EXE" 2>/dev/null || echo 0)
            MTIME_STR=$($CMD_DATE -d @$MTIME '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "Unknown")
            
            if [ "$MTIME" -gt "$BASELINE_TIMESTAMP" ]; then
                ((RECENT_MODIFIED++))
                RECENT_PROCESSES+=("可疑|$pid|$NAME|$EXE|$MTIME_STR")
                ALL_PROCESSES+=("可疑|$pid|$NAME|$EXE|$MTIME_STR")
            else
                ALL_PROCESSES+=("正常|$pid|$NAME|$EXE|$MTIME_STR")
            fi
        fi
    done
    
    {
        echo "--------------------------------------------------------------------------------"
        echo "完整数据列表（所有检测的进程，可疑项排在前面）"
        echo "--------------------------------------------------------------------------------"
        printf "| %-8s | %-10s | %-20s | %-50s | %-20s |\n" "状态" "PID" "进程名" "可执行文件" "修改时间"
        print_separator "-" 120
    } >> "$LOG_MTIME"
    
    # 日志输出全部数据
    for proc_info in "${ALL_PROCESSES[@]}"; do
        IFS='|' read -r status pid name exe mtime <<< "$proc_info"
        printf "| %-8s | %-10s | %-20s | %-50s | %-20s |\n" "$status" "$pid" "${name:0:20}" "${exe:0:50}" "$mtime" >> "$LOG_MTIME"
    done
    
    {
        print_separator "=" 120
        echo ""
        echo "统计信息:"
        echo "  时间范围: ${TIME_DESC}"
        echo "  检查的进程数: $TOTAL_CHECKED"
        echo "  最近修改的程序数: $RECENT_MODIFIED"
        echo ""
    } >> "$LOG_MTIME"
    
    echo ""
    if [ $RECENT_MODIFIED -gt 0 ]; then
        echo "发现最近修改的程序:"
        echo ""
        printf "%-26s  %-8s  %-20s  %-60s\n" "进程名" "PID" "修改时间" "可执行文件"
        print_separator "-" 120
        
        for proc_info in "${RECENT_PROCESSES[@]}"; do
            IFS='|' read -r status pid name exe mtime <<< "$proc_info"
            printf "%-26s  %-8s  %-20s  %-60s\n" "${name:0:26}" "$pid" "$mtime" "${exe:0:60}"
        done
    else
        echo "未发现最近修改的程序"
    fi
    
    print_statistics "$TOTAL_CHECKED" "$RECENT_MODIFIED" "时间范围=${TIME_DESC}"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_MTIME")
    if [ $RECENT_MODIFIED -gt 0 ]; then
        print_result "WARN" "发现 ${RECENT_MODIFIED} 个最近修改的程序 (详见日志: ${LOG_BASENAME})"
        add_detection "INFO" "检测 3: ${RECENT_MODIFIED} 个最近修改的程序"
        echo "Result: Warning" >> "$LOG_MTIME"
    else
        print_result "OK" "正常"
        add_detection "INFO" "检测 3: 无最近修改"
        echo "Result: Normal" >> "$LOG_MTIME"
    fi
}

# ============================================================================
# 检测 4: LD_PRELOAD 劫持检查
# ============================================================================
check_ld_preload() {
    print_check_title "4" "动态库劫持检测 - LD_PRELOAD" "库劫持" "高危" "用户态Rootkit检测"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH grep LD_PRELOAD /proc/*/environ && $BUSYBOX_PATH cat /etc/ld.so.preload"
    else
        DISPLAY_CMD="grep LD_PRELOAD /proc/*/environ && cat /etc/ld.so.preload"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "检测动态库劫持攻击，读取进程 LD_PRELOAD 环境变量和 /etc/ld.so.preload 文件内容（仅读取不修改，仅当文件包含有效劫持内容时才报警）"
    
    {
        echo "================================================================"
        echo "检测 4: LD_PRELOAD 劫持检查"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测命令: grep LD_PRELOAD /proc/*/environ && cat /etc/ld.so.preload"
        echo "检测策略: 检测动态库劫持攻击（仅读取检测，不修改系统。空文件或仅含注释不报警）"
        echo ""
    } > "$LOG_LDPRELOAD"
    
    declare -a LD_PRELOAD_PROCESSES
    declare -a ALL_PROCESSES
    LD_PRELOAD_COUNT=0
    TOTAL_PROC_CHECKED=0
    
    for pid in $($CMD_LS /proc/ 2>/dev/null | $CMD_GREP -E '^[0-9]+$'); do
        # 跳过脚本自身
        [ $pid -eq $$ ] && continue
        
        # 获取进程名用于过滤
        NAME=$($CMD_GREP "^Name:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
        
        # 跳过WSL特殊进程和脚本自身
        if [[ "$NAME" =~ ^(init\(|SessionLeader|Relay\(|process_scanner) ]]; then
            continue
        fi
        
        # 只计算有效进程
        ((TOTAL_PROC_CHECKED++))
        
        if [ -r "/proc/$pid/environ" ]; then
            LD_VAR=$($CMD_TR '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | $CMD_GREP "^LD_PRELOAD=" | $CMD_CUT -d= -f2-)
            if [ -n "$LD_VAR" ]; then
                ((LD_PRELOAD_COUNT++))
                LD_PRELOAD_PROCESSES+=("可疑|$pid|$NAME|$LD_VAR")
                ALL_PROCESSES+=("可疑|$pid|$NAME|$LD_VAR")
            else
                ALL_PROCESSES+=("正常|$pid|$NAME|-")
            fi
        else
            ALL_PROCESSES+=("正常|$pid|$NAME|-")
        fi
    done
    
    LD_SO_PRELOAD_EXISTS=0
    LD_SO_CONTENT=""
    LD_PRELOAD_FILE="/etc/ld.so.preload"
    
    # 调试信息（可选显示）
    if [ "${DEBUG:-0}" -eq 1 ]; then
        echo "[DEBUG] 检查 $LD_PRELOAD_FILE 是否存在..."
        $CMD_LS -la "$LD_PRELOAD_FILE" 2>&1 | $CMD_SED 's/^/[DEBUG] /'
    fi
    
    if [ -f "$LD_PRELOAD_FILE" ]; then
        LD_SO_CONTENT=$($CMD_CAT "$LD_PRELOAD_FILE" 2>/dev/null)
        
        # 过滤掉空行和注释，检查是否有实际内容
        EFFECTIVE_CONTENT=$(echo "$LD_SO_CONTENT" | $CMD_GREP -v '^#' | $CMD_GREP -v '^[[:space:]]*$' 2>/dev/null)
        
        if [ -n "$EFFECTIVE_CONTENT" ]; then
            # 只有在有实际内容时才认为是可疑的
            LD_SO_PRELOAD_EXISTS=1
            if [ "${DEBUG:-0}" -eq 1 ]; then
                echo "[DEBUG] 文件存在且包含有效内容！"
                echo "[DEBUG] 有效内容："
                echo "$EFFECTIVE_CONTENT" | $CMD_SED 's/^/[DEBUG]   /'
            fi
        else
            # 文件存在但是空的或只有注释，认为是正常的
            LD_SO_PRELOAD_EXISTS=0
            if [ "${DEBUG:-0}" -eq 1 ]; then
                echo "[DEBUG] 文件存在但为空或只包含注释（正常）"
            fi
        fi
    else
        if [ "${DEBUG:-0}" -eq 1 ]; then
            echo "[DEBUG] 文件不存在（正常）"
        fi
    fi
    
    {
        echo "--------------------------------------------------------------------------------"
        echo "完整数据列表（所有检测的进程，可疑项排在前面）"
        echo "--------------------------------------------------------------------------------"
        printf "| %-8s | %-10s | %-20s | %-60s |\n" "状态" "PID" "进程名" "LD_PRELOAD 值"
        print_separator "-" 110
    } >> "$LOG_LDPRELOAD"
    
    # 日志输出全部数据
    for proc_info in "${ALL_PROCESSES[@]}"; do
        IFS='|' read -r status pid name ldvar <<< "$proc_info"
        printf "| %-8s | %-10s | %-20s | %-60s |\n" "$status" "$pid" "${name:0:20}" "${ldvar:0:60}" >> "$LOG_LDPRELOAD"
    done
    
    {
        print_separator "=" 110
        echo ""
        echo "/etc/ld.so.preload 检查:"
        if [ -f "$LD_PRELOAD_FILE" ]; then
            if [ $LD_SO_PRELOAD_EXISTS -eq 1 ]; then
                echo "  状态: 存在且包含有效内容 (高度可疑!)"
                echo "  内容:"
                $CMD_ECHO "$LD_SO_CONTENT" | $CMD_SED 's/^/    /'
            else
                echo "  状态: 存在但为空或仅含注释 (正常)"
                if [ -n "$LD_SO_CONTENT" ]; then
                    echo "  原始内容:"
                    $CMD_ECHO "$LD_SO_CONTENT" | $CMD_SED 's/^/    /'
                fi
            fi
        else
            echo "  状态: 不存在 (正常)"
        fi
        echo ""
        echo "统计信息:"
        echo "  检查的进程数: $TOTAL_PROC_CHECKED"
        echo "  使用 LD_PRELOAD 的进程数: $LD_PRELOAD_COUNT"
        echo "  /etc/ld.so.preload 有效劫持: $([ $LD_SO_PRELOAD_EXISTS -eq 1 ] && echo '是' || echo '否')"
        echo ""
    } >> "$LOG_LDPRELOAD"
    
    echo ""
    if [ $LD_PRELOAD_COUNT -gt 0 ] || [ $LD_SO_PRELOAD_EXISTS -eq 1 ]; then
        echo "发现动态库劫持:"
        echo ""
        
        if [ $LD_PRELOAD_COUNT -gt 0 ]; then
            printf "%-26s  %-8s  %-85s\n" "进程名" "PID" "LD_PRELOAD 值"
            print_separator "-" 125
            
            for proc_info in "${LD_PRELOAD_PROCESSES[@]}"; do
                IFS='|' read -r status pid name ldvar <<< "$proc_info"
                printf "%-26s  %-8s  %-85s\n" "${name:0:26}" "$pid" "${ldvar:0:85}"
            done
            echo ""
        fi
        
        if [ $LD_SO_PRELOAD_EXISTS -eq 1 ]; then
            echo "发现 /etc/ld.so.preload 文件包含有效劫持内容 (高度可疑!)"
            echo "内容:"
            $CMD_ECHO "$LD_SO_CONTENT" | $CMD_SED 's/^/  /'
        fi
    else
        echo "未发现动态库劫持"
    fi
    
    print_statistics "$TOTAL_PROC_CHECKED" "$((LD_PRELOAD_COUNT + LD_SO_PRELOAD_EXISTS))" "LD_PRELOAD进程=${LD_PRELOAD_COUNT}, ld.so.preload=$([ $LD_SO_PRELOAD_EXISTS -eq 1 ] && echo '有效劫持' || echo '正常')"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_LDPRELOAD")
    if [ $LD_PRELOAD_COUNT -gt 0 ] || [ $LD_SO_PRELOAD_EXISTS -eq 1 ]; then
        print_result "CRITICAL" "发现动态库劫持 (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 4: 发现动态库劫持"
        echo "Result: Critical" >> "$LOG_LDPRELOAD"
    else
        print_result "OK" "正常，无库劫持"
        add_detection "INFO" "检测 4: 无库劫持"
        echo "Result: Normal" >> "$LOG_LDPRELOAD"
    fi
}

# ============================================================================
# 检测 5: 进程伪装检测
# ============================================================================
check_process_disguise() {
    print_check_title "5" "进程伪装与冒名检测" "进程分析" "高危" "命名分析"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH cat /proc/*/comm && $BUSYBOX_PATH readlink /proc/*/exe"
    else
        DISPLAY_CMD="cat /proc/*/comm && readlink /proc/*/exe"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "检查进程名是否与实际可执行文件路径匹配，识别伪装成系统进程的恶意程序"
    
    {
        echo "================================================================"
        echo "检测 5: 进程伪装检测"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测命令: cat /proc/*/comm && readlink /proc/*/exe"
        echo "检测策略: 检查进程名与实际路径是否匹配"
        echo ""
    } > "$LOG_DISGUISE"
    
    declare -A SYSTEM_PROCESSES
    SYSTEM_PROCESSES["systemd"]="/usr/lib/systemd/systemd|/lib/systemd/systemd"
    SYSTEM_PROCESSES["init"]="/sbin/init|/usr/sbin/init|/init"
    SYSTEM_PROCESSES["sshd"]="/usr/sbin/sshd"
    SYSTEM_PROCESSES["cron"]="/usr/sbin/cron|/usr/sbin/crond"
    SYSTEM_PROCESSES["kworker"]="KERNEL"
    
    declare -a DISGUISED_PROCESSES
    declare -a ALL_SYSTEM_PROCESSES  # 新增：存储所有检查的系统进程
    DISGUISED_COUNT=0
    TOTAL_SYS_PROC=0
    
    for pid in $($CMD_LS /proc/ 2>/dev/null | $CMD_GREP -E '^[0-9]+$' | $CMD_SORT -n); do
        [ ! -d "/proc/$pid" ] && continue
        
        PROC_NAME=$($CMD_CAT "/proc/$pid/comm" 2>/dev/null | $CMD_TR -d '\n')
        CMDLINE=$($CMD_TR '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        CMDLINE_FIRST=$($CMD_ECHO "$CMDLINE" | $CMD_AWK '{print $1}')
        CMDLINE_FIRST=$($CMD_BASENAME "$CMDLINE_FIRST" 2>/dev/null)
        
        [ -z "$PROC_NAME" ] && continue
        
        # 跳过脚本自身
        [ $pid -eq $$ ] && continue
        [[ "$PROC_NAME" =~ ^process_scanner ]] && continue
        
        WSL_SPECIAL="SessionLeader|Relay"
        [[ "$PROC_NAME" =~ $WSL_SPECIAL ]] && continue
        
        IS_SUSPICIOUS=0
        EXPECTED_PATHS=""
        MATCHED_NAME=""
        
        for sys_name in "${!SYSTEM_PROCESSES[@]}"; do
            if [[ "$PROC_NAME" == "$sys_name" ]] || [[ "$PROC_NAME" =~ ^\[?$sys_name ]]; then
                IS_SUSPICIOUS=1
                EXPECTED_PATHS="${SYSTEM_PROCESSES[$sys_name]}"
                MATCHED_NAME="$sys_name"
                break
            fi
        done
        
        [ $IS_SUSPICIOUS -eq 0 ] && continue
        
        # 只有可能是系统进程的才计数
        ((TOTAL_SYS_PROC++))
        
        EXE=$($CMD_READLINK "/proc/$pid/exe" 2>/dev/null)
        
        # 如果是解释器，尝试获取实际脚本路径（与检测2相同的逻辑）
        SCRIPT_PATH_DISGUISE=""
        if [[ "$EXE" =~ (bash|sh|python|python2|python3|perl|ruby|php)$ ]]; then
            # 读取 cmdline，第二个参数通常是脚本路径
            CMDLINE_FULL=$($CMD_CAT "/proc/$pid/cmdline" 2>/dev/null | $CMD_TR '\0' ' ')
            # 尝试提取脚本路径（通常是第二个参数）
            SCRIPT_PATH_DISGUISE=$(echo "$CMDLINE_FULL" | $CMD_AWK '{print $2}' 2>/dev/null)
            # 如果脚本路径是绝对路径，使用它
            if [[ "$SCRIPT_PATH_DISGUISE" =~ ^/ ]]; then
                # 显示更有意义的信息：脚本路径（通过解释器）
                INTERPRETER_NAME=$($CMD_BASENAME "$EXE")
                EXE="$SCRIPT_PATH_DISGUISE (via $INTERPRETER_NAME)"
            else
                SCRIPT_PATH_DISGUISE=""
            fi
        fi
        
        IS_VALID=0
        
        if [[ "$EXPECTED_PATHS" == "KERNEL" ]]; then
            [ -z "$EXE" ] && [ -z "$CMDLINE" ] && IS_VALID=1
        else
            if [ -n "$EXE" ]; then
                IFS='|' read -ra PATHS <<< "$EXPECTED_PATHS"
                for valid_path in "${PATHS[@]}"; do
                    [[ "$EXE" =~ ^${valid_path} ]] && { IS_VALID=1; break; }
                done
            fi
        fi
        
        if [ $IS_VALID -eq 0 ]; then
            ((DISGUISED_COUNT++))
            DISGUISED_PROCESSES+=("可疑|$pid|$PROC_NAME|$EXE|$EXPECTED_PATHS")
            ALL_SYSTEM_PROCESSES+=("可疑|$pid|$PROC_NAME|$EXE|$EXPECTED_PATHS")
        else
            ALL_SYSTEM_PROCESSES+=("正常|$pid|$PROC_NAME|$EXE|$EXPECTED_PATHS")
        fi
    done
    
    # 输出完整数据列表（所有检查的系统进程）
    {
        echo "================================================================================"
        echo "完整数据列表：所有检查的系统进程（共 ${#ALL_SYSTEM_PROCESSES[@]} 个，可疑项排在前面）"
        echo "================================================================================"
        printf "| %-8s | %-10s | %-20s | %-45s | %-40s |\n" "状态" "PID" "进程名" "实际路径" "期望路径"
        print_separator "-" 130
    } >> "$LOG_DISGUISE"
    
    # 先输出可疑项
    for proc_info in "${DISGUISED_PROCESSES[@]}"; do
        IFS='|' read -r status pid name exe expected <<< "$proc_info"
        printf "| %-8s | %-10s | %-20s | %-45s | %-40s |\n" "$status" "$pid" "${name:0:20}" "${exe:0:45}" "${expected:0:40}" >> "$LOG_DISGUISE"
    done
    
    # 再输出正常项
    for proc_info in "${ALL_SYSTEM_PROCESSES[@]}"; do
        IFS='|' read -r status pid name exe expected <<< "$proc_info"
        if [ "$status" = "正常" ]; then
            printf "| %-8s | %-10s | %-20s | %-45s | %-40s |\n" "$status" "$pid" "${name:0:20}" "${exe:0:45}" "${expected:0:40}" >> "$LOG_DISGUISE"
        fi
    done
    
    {
        print_separator "=" 130
        echo ""
        echo "统计信息:"
        echo "  检查的进程数: $TOTAL_SYS_PROC"
        echo "  伪装的进程数: $DISGUISED_COUNT"
        echo ""
    } >> "$LOG_DISGUISE"
    
    echo ""
    if [ $DISGUISED_COUNT -gt 0 ]; then
        echo "发现伪装进程:"
        echo ""
        printf "%-20s %-6s %-50s %-45s\n" "进程名" "PID" "实际路径" "期望路径"
        print_separator "-" 126
        
        for proc_info in "${DISGUISED_PROCESSES[@]}"; do
            IFS='|' read -r status pid name exe expected <<< "$proc_info"
            printf "%-20s %-6s %-50s %-45s\n" "${name:0:20}" "$pid" "${exe:0:50}" "${expected:0:45}"
        done
    else
        echo "未发现伪装进程"
    fi
    
    print_statistics "$TOTAL_SYS_PROC" "$DISGUISED_COUNT" ""
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_DISGUISE")
    if [ $DISGUISED_COUNT -gt 0 ]; then
        print_result "CRITICAL" "发现 ${DISGUISED_COUNT} 个伪装进程 (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 5: 发现 ${DISGUISED_COUNT} 个伪装进程"
        echo "Result: Critical" >> "$LOG_DISGUISE"
    else
        print_result "OK" "正常，无伪装进程"
        add_detection "INFO" "检测 5: 无伪装"
        echo "Result: Normal" >> "$LOG_DISGUISE"
    fi
}

# ============================================================================
# 检测 6: 网络连接检查
# ============================================================================
check_network() {
    print_check_title "6" "隐藏网络连接检测" "网络监控" "高危" "内核vs用户态对比"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH cat /proc/net/tcp && ss -tnp (注: ss 不使用busybox)"
    else
        DISPLAY_CMD="cat /proc/net/tcp && ss -tnp"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "比对内核网络表与命令输出，检测隐藏的网络连接"
    
    {
        echo "================================================================"
        echo "检测 6: 网络连接检查"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测命令: cat /proc/net/tcp && ss -tnp"
        echo "检测策略: 比对内核网络表与命令输出"
        echo ""
        echo "内核 TCP 连接表 (/proc/net/tcp):"
        echo "----------------------------------------"
        $CMD_CAT /proc/net/tcp 2>/dev/null | $CMD_HEAD -20
        echo ""
        echo "SS 命令输出 (TCP):"
        echo "----------------------------------------"
        if command -v ss &> /dev/null; then
            ss -tnp 2>/dev/null | $CMD_HEAD -20
        else
            echo "ss 命令不可用"
        fi
        echo ""
    } > "$LOG_NETWORK"
    
    KERNEL_TCP_COUNT=$($CMD_AWK '$4 == "01"' /proc/net/tcp 2>/dev/null | $CMD_WC -l)
    KERNEL_TCP_COUNT=${KERNEL_TCP_COUNT//[^0-9]/}
    KERNEL_TCP_COUNT=${KERNEL_TCP_COUNT:-0}
    
    if [ -r /proc/net/tcp6 ]; then
        KERNEL_TCP6_COUNT=$($CMD_AWK '$4 == "01"' /proc/net/tcp6 2>/dev/null | $CMD_WC -l)
        KERNEL_TCP6_COUNT=${KERNEL_TCP6_COUNT//[^0-9]/}
        KERNEL_TCP6_COUNT=${KERNEL_TCP6_COUNT:-0}
        KERNEL_TCP_COUNT=$((KERNEL_TCP_COUNT + KERNEL_TCP6_COUNT))
    fi
    
    if command -v ss &> /dev/null; then
        CMD_TCP_COUNT=$(ss -tn 2>/dev/null | $CMD_GREP -c ESTAB 2>/dev/null)
        CMD_TCP_COUNT=${CMD_TCP_COUNT//[^0-9]/}
        CMD_TCP_COUNT=${CMD_TCP_COUNT:-0}
    else
        CMD_TCP_COUNT=0
    fi
    
    DIFF=$((KERNEL_TCP_COUNT - CMD_TCP_COUNT))
    
    {
        print_separator "=" 100
        echo ""
        echo "统计信息:"
        echo "  内核 TCP 连接数 (ESTABLISHED): $KERNEL_TCP_COUNT"
        echo "  SS 命令 TCP 连接数 (ESTABLISHED): $CMD_TCP_COUNT"
        echo "  差异: $DIFF"
        echo ""
    } >> "$LOG_NETWORK"
    
    echo ""
    echo "网络连接统计:"
    echo ""
    printf "%-25s %-20s %-20s %-15s\n" "类型" "内核计数" "SS 命令计数" "差异"
    print_separator "-" 85
    printf "%-25s %-20s %-20s %-15s\n" "TCP (ESTABLISHED)" "$KERNEL_TCP_COUNT" "$CMD_TCP_COUNT" "$DIFF"
    
    print_statistics "$KERNEL_TCP_COUNT" "$DIFF" "内核=${KERNEL_TCP_COUNT}, 命令=${CMD_TCP_COUNT}"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_NETWORK")
    if [ "$DIFF" -gt 5 ] 2>/dev/null; then
        print_result "CRITICAL" "TCP 差异=${DIFF}，可能存在隐藏连接 (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 6: TCP 连接差异=${DIFF}"
        echo "Result: Critical - TCP diff=${DIFF}" >> "$LOG_NETWORK"
    elif [ "$DIFF" -gt 2 ] 2>/dev/null; then
        print_result "WARN" "TCP 差异=${DIFF} (详见日志: ${LOG_BASENAME})"
        add_detection "MEDIUM" "检测 6: TCP 连接差异=${DIFF}"
        echo "Result: Warning - TCP diff=${DIFF}" >> "$LOG_NETWORK"
    else
        print_result "OK" "正常，网络连接正常"
        add_detection "INFO" "检测 6: 网络正常"
        echo "Result: Normal" >> "$LOG_NETWORK"
    fi
}

# ============================================================================
# 检测 7: 临时目录检查
# ============================================================================
check_tmpdir() {
    print_check_title "7" "临时目录可疑文件检测" "文件系统" "高危" "持久化检测"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH readlink /proc/*/exe && $BUSYBOX_PATH find /tmp /dev/shm /var/tmp -type f -perm"
    else
        DISPLAY_CMD="readlink /proc/*/exe && find /tmp /dev/shm /var/tmp -type f -executable"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "优先级检测: 1)伪造系统进程 2)可疑关键词 3)攻击工具命名 4)权限 5)软链接 6)高熵命名"
    
    {
        echo "================================================================"
        echo "检测 7: 临时目录检查"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测命令: readlink /proc/*/exe && find /tmp /dev/shm /var/tmp -type f -executable"
        echo "检测策略: 全面检查临时目录中的可疑特征"
        echo "检测维度: 路径/权限/命名熵值/软链接/伪造进程"
        echo ""
    } > "$LOG_TMPDIR"
    
    # 第一部分：检查运行中的进程
    declare -a TMPDIR_PROCESSES
    declare -a ALL_PROCESSES
    TMPDIR_PROC_COUNT=0
    PROC_ENTROPY_COUNT=0
    PROC_FAKE_COUNT=0
    TOTAL_PROC=0
    
    for pid in $($CMD_LS /proc/ 2>/dev/null | $CMD_GREP -E '^[0-9]+$'); do
        ((TOTAL_PROC++))
        EXE=$($CMD_READLINK "/proc/$pid/exe" 2>/dev/null)
        CWD=$($CMD_READLINK "/proc/$pid/cwd" 2>/dev/null)
        NAME=$($CMD_GREP "^Name:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
        [ -z "$NAME" ] && NAME="unknown"
        
        SUSPICIOUS_REASONS=()
        SUSPICIOUS_PATH=""
        
        # 检查临时目录
        if [[ "$EXE" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
            SUSPICIOUS_REASONS+=("临时目录执行")
            SUSPICIOUS_PATH="$EXE"
        elif [[ "$CWD" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
            SUSPICIOUS_REASONS+=("临时目录工作")
            SUSPICIOUS_PATH="$CWD"
        fi
        
        if [ -n "$SUSPICIOUS_PATH" ]; then
            # 白名单验证（临时目录中的白名单程序更可疑）
            IS_WHITELIST=0
            # 基础工具
            local WHITELIST_CHECK="sha1sum|sha224sum|sha256sum|sha384sum|sha512sum|md5sum|base64|base32"
            WHITELIST_CHECK="${WHITELIST_CHECK}|py3compile|py3clean|python2|python3"
            
            # ✨ 核心系统守护进程（在临时目录高度可疑！）
            WHITELIST_CHECK="${WHITELIST_CHECK}|systemd|init|systemctl|journalctl"
            WHITELIST_CHECK="${WHITELIST_CHECK}|sshd|crond|cron|atd"
            WHITELIST_CHECK="${WHITELIST_CHECK}|rsyslogd|syslogd|auditd|dbus-daemon"
            WHITELIST_CHECK="${WHITELIST_CHECK}|NetworkManager|polkitd|cupsd"
            
            # ✨ Web服务和数据库
            WHITELIST_CHECK="${WHITELIST_CHECK}|nginx|apache2|httpd"
            WHITELIST_CHECK="${WHITELIST_CHECK}|mysql|mysqld|postgres|postgresql"
            
            if [[ "$NAME" =~ ^(${WHITELIST_CHECK})$ ]] && [ -n "$EXE" ]; then
                IS_WHITELIST=1
                # 白名单程序在临时目录运行是高度可疑的
                whitelist_error=$(verify_whitelist_program "$NAME" "$EXE" "1" 2>&1)
                if [ $? -ne 0 ]; then
                    SUSPICIOUS_REASONS+=("白名单伪造:$whitelist_error")
                    ((PROC_FAKE_COUNT++))
                else
                    # 即使通过验证，在临时目录也可疑
                    SUSPICIOUS_REASONS+=("白名单程序异常位置")
                    ((PROC_FAKE_COUNT++))
                fi
            fi
            
            # 非白名单程序才进行常规检测
            if [ $IS_WHITELIST -eq 0 ]; then
                # 优先级1: 检查伪造系统进程名
                SYSTEM_PROC_NAMES="^(init|systemd|sshd|crond|cron|atd|rsyslogd|auditd|kworker|kthreadd)$"
                if [[ "$NAME" =~ $SYSTEM_PROC_NAMES ]]; then
                    SUSPICIOUS_REASONS+=("伪造系统进程")
                    ((PROC_FAKE_COUNT++))
                elif [[ "$NAME" =~ ^fake ]]; then
                    SUSPICIOUS_REASONS+=("伪造标识(fake)")
                    ((PROC_FAKE_COUNT++))
                fi
                
                # 优先级2: 检查可疑关键词
                local keywords=("hidden" "stealth" "suspicious" "malicious" "backdoor" "rootkit" "trojan" "payload" "exploit" "reverse" "shell")
                local matched_keywords=()
                for keyword in "${keywords[@]}"; do
                    if [[ "$NAME" =~ $keyword ]] || [[ "$EXE" =~ $keyword ]]; then
                        matched_keywords+=("$keyword")
                    fi
                done
                if [ ${#matched_keywords[@]} -gt 0 ]; then
                    local all_keywords=$(IFS=','; echo "${matched_keywords[*]}")
                    SUSPICIOUS_REASONS+=("可疑关键词($all_keywords)")
                    ((PROC_FAKE_COUNT++))
                fi
                
                # 优先级3: 检查攻击工具命名
                ATTACK_PATTERNS="(maker|delete|orphan|inject|spawn|hijack|daemon)"
                if [[ "$NAME" =~ $ATTACK_PATTERNS ]]; then
                    SUSPICIOUS_REASONS+=("攻击工具命名")
                    ((PROC_FAKE_COUNT++))
                fi
                
                # 优先级4: 检查伪造进程（路径验证）
                if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ] && [ -n "$EXE" ] && [ "$EXE" != "N/A" ]; then
                    if fake_reason=$(check_fake_system_process "$NAME" "$EXE"); then
                        SUSPICIOUS_REASONS+=("伪造:$fake_reason")
                        ((PROC_FAKE_COUNT++))
                    fi
                fi
                
                # 优先级5: 真正的高熵命名（随机字符，最低优先级）
                if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                    if [ "$(check_name_entropy "$NAME")" = "1" ]; then
                        SUSPICIOUS_REASONS+=("高熵命名")
                        ((PROC_ENTROPY_COUNT++))
                    fi
                fi
            fi
            
            # 计算命名熵值（用于显示）
            NAME_ENTROPY=$(calculate_shannon_entropy "$NAME")
            NAME_ENTROPY=$(printf "%.2f" $NAME_ENTROPY 2>/dev/null || echo "0.00")
            
            ((TMPDIR_PROC_COUNT++))
            ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
            TMPDIR_PROCESSES+=("进程|$pid|$NAME|$SUSPICIOUS_PATH|$NAME_ENTROPY|$ALL_REASONS")
            # 也添加到ALL_PROCESSES（可疑）
            ALL_PROCESSES+=("可疑|$pid|$NAME|$SUSPICIOUS_PATH|$NAME_ENTROPY|$ALL_REASONS")
        else
            # 正常进程（不在临时目录）
            NAME_ENTROPY=$(calculate_shannon_entropy "$NAME")
            NAME_ENTROPY=$(printf "%.2f" $NAME_ENTROPY 2>/dev/null || echo "0.00")
            DISPLAY_PATH="${EXE:-${CWD:-N/A}}"
            ALL_PROCESSES+=("正常|$pid|$NAME|$DISPLAY_PATH|$NAME_ENTROPY|-")
        fi
    done
    
    # 第二部分：扫描临时目录中的可执行文件
    declare -a TMPDIR_FILES
    TMPDIR_FILE_COUNT=0
    FILE_ENTROPY_COUNT=0
    FILE_PERM_COUNT=0
    FILE_SYMLINK_COUNT=0
    
    # 使用临时文件避免管道子shell问题
    TMPFILE="${TMP_DIR}/tmpdir_files_$$.tmp"
    
    TEMP_DIRS="/tmp /dev/shm /var/tmp"
    for temp_dir in $TEMP_DIRS; do
        if [ -d "$temp_dir" ]; then
            # 使用 -perm 替代 -executable 以提高兼容性
            # 查找有任何执行权限的文件 (user/group/other)
            find "$temp_dir" -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) 2>/dev/null >> "$TMPFILE"
        fi
    done
    
    # 读取临时文件并处理
    if [ -f "$TMPFILE" ]; then
        while IFS= read -r file; do
            if [ -f "$file" ] || [ -L "$file" ]; then
                FILE_NAME=$($CMD_BASENAME "$file")
                FILE_SIZE=$($CMD_STAT -c %s "$file" 2>/dev/null || echo 0)
                FILE_MTIME=$($CMD_STAT -c %y "$file" 2>/dev/null | $CMD_CUT -d'.' -f1 || echo "Unknown")
                FILE_PERM=$($CMD_STAT -c %a "$file" 2>/dev/null || echo "000")
                
                SUSPICIOUS_REASONS=()
                
                # 优先级1: 检查是否伪造系统进程名（临时目录中的系统进程名极度可疑）
                SYSTEM_PROC_NAMES="^(init|systemd|sshd|crond|cron|atd|rsyslogd|auditd|kworker|kthreadd|bash|sh|python|perl)$"
                if [[ "$FILE_NAME" =~ $SYSTEM_PROC_NAMES ]]; then
                    SUSPICIOUS_REASONS+=("伪造系统进程")
                    ((FILE_ENTROPY_COUNT++))
                elif [[ "$FILE_NAME" =~ ^fake ]]; then
                    SUSPICIOUS_REASONS+=("伪造标识(fake)")
                    ((FILE_ENTROPY_COUNT++))
                fi
                
                # 优先级2: 检查可疑关键词（明显的恶意命名）
                local keywords=("hidden" "stealth" "suspicious" "malicious" "backdoor" "rootkit" "trojan" "payload" "exploit" "reverse" "shell" "obfuscate")
                local matched_keywords=()
                for keyword in "${keywords[@]}"; do
                    if [[ "$FILE_NAME" =~ $keyword ]] || [[ "$file" =~ $keyword ]]; then
                        matched_keywords+=("$keyword")
                    fi
                done
                if [ ${#matched_keywords[@]} -gt 0 ]; then
                    local all_keywords=$(IFS=','; echo "${matched_keywords[*]}")
                    SUSPICIOUS_REASONS+=("可疑关键词($all_keywords)")
                    ((FILE_ENTROPY_COUNT++))
                fi
                
                # 优先级3: 检查攻击工具命名特征
                ATTACK_PATTERNS="(maker|delete|orphan|inject|spawn|hijack)"
                if [[ "$FILE_NAME" =~ $ATTACK_PATTERNS ]]; then
                    SUSPICIOUS_REASONS+=("攻击工具命名")
                    ((FILE_ENTROPY_COUNT++))
                fi
                
                # 优先级4: 检查权限
                if perm_reason=$(check_suspicious_permission "$FILE_PERM" "$file"); then
                    SUSPICIOUS_REASONS+=("权限:$perm_reason")
                    ((FILE_PERM_COUNT++))
                fi
                
                # 优先级5: 检查软链接
                if symlink_reason=$(check_suspicious_symlink "$file"); then
                    SUSPICIOUS_REASONS+=("软链接:$symlink_reason")
                    ((FILE_SYMLINK_COUNT++))
                fi
                
                # 优先级6: 检查真正的高熵命名（随机字符，最低优先级）
                if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                    if [ "$(check_name_entropy "$FILE_NAME")" = "1" ]; then
                        SUSPICIOUS_REASONS+=("高熵命名")
                        ((FILE_ENTROPY_COUNT++))
                    fi
                fi
                
                # 计算文件名熵值（用于显示）
                FILE_NAME_ENTROPY=$(calculate_shannon_entropy "$FILE_NAME")
                FILE_NAME_ENTROPY=$(printf "%.2f" $FILE_NAME_ENTROPY 2>/dev/null || echo "0.00")
                
                ((TMPDIR_FILE_COUNT++))
                ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
                [ -z "$ALL_REASONS" ] && ALL_REASONS="临时目录"
                TMPDIR_FILES+=("文件|-|$FILE_NAME|$file|${FILE_SIZE}字节|$FILE_MTIME|$FILE_PERM|$FILE_NAME_ENTROPY|$ALL_REASONS")
            fi
        done < "$TMPFILE"
        rm -f "$TMPFILE"
    fi
    
    # 输出完整进程列表（所有进程，供人工分析）
    {
        echo "--------------------------------------------------------------------------------"
        echo "完整数据列表：所有检测的进程（共 ${#ALL_PROCESSES[@]} 个，可疑项排在前面）"
        echo "--------------------------------------------------------------------------------"
        printf "| %-10s | %-10s | %-18s | %-50s | %-8s | %-40s |\n" "状态" "PID" "进程名" "路径" "熵值" "检测原因"
        print_separator "-" 155
    } >> "$LOG_TMPDIR"
    
    # 输出所有可疑进程（排在前面）
    for proc_info in "${ALL_PROCESSES[@]}"; do
        IFS='|' read -r status pid name path entropy reasons <<< "$proc_info"
        if [ "$status" = "可疑" ]; then
            printf "| %-10s | %-10s | %-18s | %-50s | %-8s | %-40s |\n" "$status" "$pid" "${name:0:18}" "${path:0:50}" "$entropy" "${reasons:0:40}" >> "$LOG_TMPDIR"
        fi
    done
    
    # 输出所有正常进程
    for proc_info in "${ALL_PROCESSES[@]}"; do
        IFS='|' read -r status pid name path entropy reasons <<< "$proc_info"
        if [ "$status" = "正常" ]; then
            printf "| %-10s | %-10s | %-18s | %-50s | %-8s | %-40s |\n" "$status" "$pid" "${name:0:18}" "${path:0:50}" "$entropy" "${reasons:0:40}" >> "$LOG_TMPDIR"
        fi
    done
    
    {
        print_separator "=" 155
        echo ""
    } >> "$LOG_TMPDIR"
    
    # 临时目录可疑进程汇总
    {
        echo "--------------------------------------------------------------------------------"
        echo "第1部分：临时目录中的运行进程（可疑项）"
        echo "--------------------------------------------------------------------------------"
    } >> "$LOG_TMPDIR"
    
    if [ $TMPDIR_PROC_COUNT -gt 0 ]; then
        {
            printf "| %-8s | %-10s | %-18s | %-48s | %-8s | %-40s |\n" "类型" "PID" "进程名" "路径" "熵值" "检测原因"
            print_separator "-" 145
        } >> "$LOG_TMPDIR"
        for proc_info in "${TMPDIR_PROCESSES[@]}"; do
            IFS='|' read -r type pid name path entropy reasons <<< "$proc_info"
            printf "| %-8s | %-10s | %-18s | %-48s | %-8s | %-40s |\n" "$type" "$pid" "${name:0:18}" "${path:0:48}" "$entropy" "${reasons:0:40}" >> "$LOG_TMPDIR"
        done
    else
        echo "| (无运行进程)" >> "$LOG_TMPDIR"
    fi
    
    # 输出文件数据
    {
        echo ""
        echo "--------------------------------------------------------------------------------"
        echo "第2部分：临时目录中的可执行文件"
        echo "--------------------------------------------------------------------------------"
        printf "| %-8s | %-23s | %-38s | %-13s | %-18s | %-6s | %-8s | %-25s |\n" "类型" "文件名" "完整路径" "大小" "修改时间" "权限" "熵值" "检测原因"
        print_separator "-" 155
    } >> "$LOG_TMPDIR"
    
    if [ $TMPDIR_FILE_COUNT -gt 0 ]; then
        for file_info in "${TMPDIR_FILES[@]}"; do
            IFS='|' read -r type pid name path size mtime perm entropy reasons <<< "$file_info"
            printf "| %-8s | %-23s | %-38s | %-13s | %-18s | %-6s | %-8s | %-25s |\n" "$type" "${name:0:23}" "${path:0:38}" "$size" "$mtime" "$perm" "$entropy" "${reasons:0:25}" >> "$LOG_TMPDIR"
        done
    else
        echo "| (无可执行文件)" >> "$LOG_TMPDIR"
    fi
    
    {
        print_separator "=" 155
        echo ""
        echo "统计信息:"
        echo "  检查的进程数: $TOTAL_PROC"
        echo "  临时目录运行进程数: $TMPDIR_PROC_COUNT"
        echo "    - 高熵命名进程: $PROC_ENTROPY_COUNT"
        echo "    - 伪造进程: $PROC_FAKE_COUNT"
        echo "  临时目录可执行文件数: $TMPDIR_FILE_COUNT"
        echo "    - 可疑权限: $FILE_PERM_COUNT"
        echo "    - 高熵命名: $FILE_ENTROPY_COUNT"
        echo "    - 可疑软链接: $FILE_SYMLINK_COUNT"
        echo "  总可疑项: $((TMPDIR_PROC_COUNT + TMPDIR_FILE_COUNT))"
        echo ""
    } >> "$LOG_TMPDIR"
    
    # 控制台输出
    echo ""
    TMPDIR_TOTAL=$((TMPDIR_PROC_COUNT + TMPDIR_FILE_COUNT))
    CRITICAL_ITEMS=$((PROC_FAKE_COUNT + FILE_PERM_COUNT + FILE_SYMLINK_COUNT + PROC_ENTROPY_COUNT + FILE_ENTROPY_COUNT))
    
    if [ $TMPDIR_TOTAL -gt 0 ]; then
        echo "发现临时目录可疑项 (进程: $TMPDIR_PROC_COUNT, 文件: $TMPDIR_FILE_COUNT):"
        echo ""
        
        if [ $TMPDIR_PROC_COUNT -gt 0 ]; then
            echo "[运行进程]"
            printf "%-26s  %-8s  %-8s  %-60s  %-42s\n" "进程名" "PID" "熵值" "路径" "检测原因"
            print_separator "-" 150
        for proc_info in "${TMPDIR_PROCESSES[@]}"; do
                IFS='|' read -r type pid name path entropy reasons <<< "$proc_info"
                printf "%-26s  %-8s  %-8s  %-60s  %-42s\n" "${name:0:26}" "$pid" "$entropy" "${path:0:60}" "${reasons:0:42}"
            done
            echo ""
        fi
        
        if [ $TMPDIR_FILE_COUNT -gt 0 ]; then
            echo "[可执行文件]"
            printf "%-21s  %-7s  %-10s %-43s %-10s  %-15s  %-30s\n" "文件名" "权限" "熵值" "路径" "大小" "修改时间" "检测原因"
            print_separator "-" 150
            for file_info in "${TMPDIR_FILES[@]}"; do
                IFS='|' read -r type pid name path size mtime perm entropy reasons <<< "$file_info"
                printf "%-21s  %-7s  %-10s %-43s %-10s  %-15s  %-30s\n" "${name:0:21}" "$perm" "$entropy" "${path:0:43}" "$size" "$mtime" "${reasons:0:30}"
            done
        fi
    else
        echo "未发现临时目录可疑项"
    fi
    
    print_statistics "$TOTAL_PROC" "$TMPDIR_TOTAL" "进程=$TMPDIR_PROC_COUNT(熵$PROC_ENTROPY_COUNT/伪造$PROC_FAKE_COUNT), 文件=$TMPDIR_FILE_COUNT(权限$FILE_PERM_COUNT/熵$FILE_ENTROPY_COUNT/软链接$FILE_SYMLINK_COUNT)"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_TMPDIR")
    if [ $TMPDIR_TOTAL -gt 0 ]; then
        print_result "CRITICAL" "发现 ${TMPDIR_TOTAL} 个临时目录可疑项 (严重特征=${CRITICAL_ITEMS}) (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 7: 发现 ${TMPDIR_TOTAL} 个临时目录可疑项"
        echo "Result: Critical - Found ${TMPDIR_TOTAL} suspicious items in temp directories" >> "$LOG_TMPDIR"
    else
        print_result "OK" "正常，临时目录正常"
        add_detection "INFO" "检测 7: 临时目录正常"
        echo "Result: Normal" >> "$LOG_TMPDIR"
    fi
}

# ============================================================================
# 检测 8: 反向 Shell 检测
# ============================================================================
check_reverse_shell() {
    print_check_title "8" "反向Shell与后门命令检测" "命令分析" "高危" "后门检测"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH cat /proc/*/cmdline"
    else
        DISPLAY_CMD="cat /proc/*/cmdline"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "检测命令行中的反向 Shell 特征（bash -i、nc -e、/dev/tcp/ 等）"
    
    {
        echo "================================================================"
        echo "检测 8: 反向 Shell 和可疑命令检测"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测命令: cat /proc/*/cmdline"
        echo "检测策略: 检测命令行中的反向 Shell 特征"
        echo ""
    } > "$LOG_SHELL"
    
    declare -a SUSPICIOUS_COMMANDS
    declare -a ALL_COMMANDS
    SHELL_COUNT=0
    SUSPICIOUS_CMD_COUNT=0
    TOTAL_CMD_CHECKED=0
    
    for pid in $($CMD_LS /proc/ 2>/dev/null | $CMD_GREP -E '^[0-9]+$' | $CMD_SORT -n); do
        [ ! -f "/proc/$pid/cmdline" ] && continue
        
        # 跳过脚本自身
        [ $pid -eq $$ ] && continue
        
        NAME=$($CMD_GREP "^Name:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
        
        # 跳过WSL特殊进程和脚本自身
        if [[ "$NAME" =~ ^(init\(|SessionLeader|Relay\(|process_scanner) ]]; then
            continue
        fi
        
        # 跳过WSL的/init进程
        if [ "$NAME" = "init" ]; then
            EXE=$($CMD_READLINK "/proc/$pid/exe" 2>/dev/null)
            [ "$EXE" = "/init" ] && continue
        fi
        
        # 只计算有效进程
        ((TOTAL_CMD_CHECKED++))
        
        CMDLINE=$($CMD_TR '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        
        MARK=""
        SUSPICIOUS=0
        
        if [[ "$CMDLINE" =~ bash.*-i.*tcp ]] || \
           [[ "$CMDLINE" =~ nc.*-e.*/bin/bash ]] || \
           [[ "$CMDLINE" =~ nc.*-e.*/bin/sh ]] || \
           [[ "$CMDLINE" =~ nc.*-l.*-p ]] || \
           [[ "$CMDLINE" =~ python.*socket ]] || \
           [[ "$CMDLINE" =~ perl.*socket ]] || \
           [[ "$CMDLINE" =~ /dev/tcp/ ]]; then
            MARK="反向Shell"
            SUSPICIOUS=1
            ((SHELL_COUNT++))
        elif [[ "$CMDLINE" =~ base64.*-d ]] || \
             [[ "$CMDLINE" =~ curl.*\|.*bash ]] || \
             [[ "$CMDLINE" =~ wget.*\|.*sh ]]; then
            MARK="可疑命令"
            SUSPICIOUS=1
            ((SUSPICIOUS_CMD_COUNT++))
        fi
        
        if [ $SUSPICIOUS -eq 1 ]; then
            SUSPICIOUS_COMMANDS+=("可疑|$pid|$NAME|$CMDLINE|$MARK")
            ALL_COMMANDS+=("可疑|$pid|$NAME|$CMDLINE|$MARK")
        else
            ALL_COMMANDS+=("正常|$pid|$NAME|$CMDLINE|-")
        fi
    done
    
    {
        echo "--------------------------------------------------------------------------------"
        echo "完整数据列表（所有检测的命令，可疑项排在前面）"
        echo "--------------------------------------------------------------------------------"
        printf "| %-8s | %-10s | %-20s | %-70s | %-15s |\n" "状态" "PID" "进程名" "命令行" "类型"
        print_separator "-" 130
    } >> "$LOG_SHELL"
    
    # 日志输出全部数据
    for cmd_info in "${ALL_COMMANDS[@]}"; do
        IFS='|' read -r status pid name cmdline mark <<< "$cmd_info"
        printf "| %-8s | %-10s | %-20s | %-70s | %-15s |\n" "$status" "$pid" "${name:0:20}" "${cmdline:0:70}" "$mark" >> "$LOG_SHELL"
    done
    
    {
        print_separator "=" 130
        echo ""
        echo "统计信息:"
        echo "  检查的进程数: $TOTAL_CMD_CHECKED"
        echo "  反向 Shell 数: $SHELL_COUNT"
        echo "  可疑命令数: $SUSPICIOUS_CMD_COUNT"
        echo ""
    } >> "$LOG_SHELL"
    
    echo ""
    TOTAL_SUSPICIOUS=$((SHELL_COUNT + SUSPICIOUS_CMD_COUNT))
    if [ $TOTAL_SUSPICIOUS -gt 0 ]; then
        echo "发现可疑命令:"
        echo ""
        printf "%-25s  %-8s  %-85s  %-22s\n" "进程名" "PID" "命令行" "类型"
        print_separator "-" 145
        
        for cmd_info in "${SUSPICIOUS_COMMANDS[@]}"; do
            IFS='|' read -r status pid name cmdline mark <<< "$cmd_info"
            printf "%-25s  %-8s  %-85s  %-22s\n" "${name:0:25}" "$pid" "${cmdline:0:85}" "$mark"
        done
    else
        echo "未发现可疑命令"
    fi
    
    print_statistics "$TOTAL_CMD_CHECKED" "$TOTAL_SUSPICIOUS" "反向Shell=${SHELL_COUNT}, 可疑命令=${SUSPICIOUS_CMD_COUNT}"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_SHELL")
    if [ $SHELL_COUNT -gt 0 ]; then
        print_result "CRITICAL" "发现 ${SHELL_COUNT} 个反向 Shell (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 8: 发现 ${SHELL_COUNT} 个反向 Shell"
        echo "Result: Critical" >> "$LOG_SHELL"
    elif [ $SUSPICIOUS_CMD_COUNT -gt 0 ]; then
        print_result "WARN" "发现 ${SUSPICIOUS_CMD_COUNT} 个可疑命令 (详见日志: ${LOG_BASENAME})"
        add_detection "MEDIUM" "检测 8: 发现 ${SUSPICIOUS_CMD_COUNT} 个可疑命令"
        echo "Result: Warning" >> "$LOG_SHELL"
    else
        print_result "OK" "正常，无可疑命令"
        add_detection "INFO" "检测 8: 无可疑命令"
        echo "Result: Normal" >> "$LOG_SHELL"
    fi
}

# ============================================================================
# 检测 9: Systemd 服务检测（简化版）
# ============================================================================
check_systemd() {
    print_check_title "9" "Systemd服务后门检测" "持久化" "高危" "服务分析"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -name '*.service'"
    else
        DISPLAY_CMD="find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system -name '*.service'"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "优先级: 1)可疑路径 2)伪造系统服务 3)可疑关键词 4)路径匹配 5)软链接 6)权限 7)高熵命名 8)最近修改"
    
    {
        echo "================================================================"
        echo "检测 9: Systemd 服务检测"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "时间范围: ${TIME_DESC}"
        echo "检测维度: 路径/权限/命名熵值/软链接/伪造服务"
        echo ""
    } > "$LOG_SYSTEMD"
    
    SYSTEMD_DIRS="/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system"
    SERVICE_FILES=""
    
    for dir in $SYSTEMD_DIRS; do
        [ -d "$dir" ] && SERVICE_FILES="$SERVICE_FILES $(find "$dir" -type f -name '*.service' 2>/dev/null)"
    done
    
    declare -a SUSPICIOUS_SERVICES
    declare -a ALL_SERVICES  # 新增：存储所有服务
    SUSPICIOUS_PATH_COUNT=0
    RECENT_MODIFIED_COUNT=0
    SUSPICIOUS_NAME_COUNT=0
    SUSPICIOUS_PERM_COUNT=0
    SUSPICIOUS_SYMLINK_COUNT=0
    TOTAL_SERVICE_COUNT=0
    
    for service_file in $SERVICE_FILES; do
        [ ! -f "$service_file" ] && [ ! -L "$service_file" ] && continue
        
        ((TOTAL_SERVICE_COUNT++))
        
        SERVICE_NAME=$($CMD_BASENAME "$service_file" .service)
        SERVICE_FILE_NAME=$($CMD_BASENAME "$service_file")
        FILE_MTIME=$($CMD_STAT -c %Y "$service_file" 2>/dev/null || echo 0)
        FILE_MTIME_STR=$($CMD_STAT -c %y "$service_file" 2>/dev/null | $CMD_CUT -d'.' -f1 || echo "unknown")
        FILE_PERM=$($CMD_STAT -c %a "$service_file" 2>/dev/null || echo "000")
        
        EXEC_PATHS=$($CMD_GREP -E "^(ExecStart|ExecStartPre|ExecStartPost)=" "$service_file" 2>/dev/null | $CMD_CUT -d'=' -f2- | $CMD_AWK '{print $1}' | $CMD_TR '\n' ' ')
        EXEC_START=$($CMD_ECHO "$EXEC_PATHS" | $CMD_AWK '{print $1}')
        [ -z "$EXEC_START" ] && EXEC_START="N/A"
        
        SUSPICIOUS_REASONS=()
        IS_SUSPICIOUS=0
        IS_WHITELIST=0
        
        # 白名单系统服务检查
        local SYSTEM_SERVICES="sshd|cron|crond|atd|rsyslog|syslog|systemd-|dbus|NetworkManager|polkit|auditd|cups|apache2|nginx|mysql|postgresql"
        if [[ "$SERVICE_NAME" =~ ^($SYSTEM_SERVICES) ]]; then
            IS_WHITELIST=1
            
            # 白名单服务进行验证（检查执行路径是否正常）
            if [ -n "$EXEC_START" ] && [ "$EXEC_START" != "N/A" ]; then
                # 白名单服务的执行路径不应该在临时目录
                if [[ "$EXEC_START" =~ ^/tmp/|^/dev/shm/|^/var/tmp/|^/home/|^/root/ ]]; then
                    SUSPICIOUS_REASONS+=("白名单伪造:异常路径")
                    ((SUSPICIOUS_PATH_COUNT++))
                    IS_SUSPICIOUS=1
                fi
                
                # 白名单服务不应该最近被修改（除非系统更新）
                if [ "$FILE_MTIME" -gt "$BASELINE_TIMESTAMP" ] 2>/dev/null; then
                    SUSPICIOUS_REASONS+=("白名单服务最近修改")
                    ((RECENT_MODIFIED_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
        fi
        
        # 非白名单服务进行常规检测
        if [ $IS_WHITELIST -eq 0 ]; then
            # === 优先级检测策略 ===
            
            # 优先级1：可疑执行路径（临时目录）
        if $CMD_ECHO "$EXEC_PATHS" | $CMD_GREP -qE '(/tmp/|/dev/shm/|/var/tmp/)'; then
                SUSPICIOUS_REASONS+=("可疑路径")
            ((SUSPICIOUS_PATH_COUNT++))
                IS_SUSPICIOUS=1
            fi
            
            # 优先级2: 检查伪造系统服务名（与路径不匹配）
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                # 服务名看起来是系统服务，但路径异常
                SYSTEM_SERVICE_NAMES="^(systemd|cron|rsyslog|audit|network|ssh|dbus).*\.service$"
                if [[ "$SERVICE_FILE_NAME" =~ $SYSTEM_SERVICE_NAMES ]]; then
                    # 检查路径是否合法
                    if [[ ! "$EXEC_PATHS" =~ ^/(usr/)?(s)?bin/ ]] && [[ ! "$EXEC_PATHS" =~ ^/lib/ ]]; then
                        SUSPICIOUS_REASONS+=("伪造系统服务")
                        ((SUSPICIOUS_NAME_COUNT++))
                        IS_SUSPICIOUS=1
                    fi
                fi
            fi
            
            # 优先级3: 检查高危关键词（单独触发）和可疑关键词（需配合其他特征）
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                # 高危关键词：单独触发
                local critical_keywords=("rootkit" "backdoor" "trojan" "malware" "exploit" "payload")
                # 可疑关键词：需配合其他特征
                local suspicious_keywords=("hidden" "stealth" "miner" "scanner" "reverse" "nc" "netcat" "exec" "daemon" "suspicious" "malicious" "crypto")
                
                # 先检查高危关键词
                local matched_critical=()
                for keyword in "${critical_keywords[@]}"; do
                    if [[ "$SERVICE_NAME" =~ $keyword ]] || [[ "$EXEC_PATHS" =~ $keyword ]]; then
                        matched_critical+=("$keyword")
                    fi
                done
                
                if [ ${#matched_critical[@]} -gt 0 ]; then
                    # 高危关键词：直接报警
                    local all_keywords=$(IFS=','; echo "${matched_critical[*]}")
                    SUSPICIOUS_REASONS+=("高危关键词($all_keywords)")
                    ((SUSPICIOUS_NAME_COUNT++))
                    IS_SUSPICIOUS=1
                else
                    # 检查可疑关键词（包括shell）
                    local matched_suspicious=()
                    for keyword in "${suspicious_keywords[@]}"; do
                        if [[ "$SERVICE_NAME" =~ $keyword ]] || [[ "$EXEC_PATHS" =~ $keyword ]]; then
                            matched_suspicious+=("$keyword")
                        fi
                    done
                    
                    # 检查shell关键词，排除合法工具
                    if [[ "$SERVICE_NAME" =~ shell ]] || [[ "$EXEC_PATHS" =~ shell ]]; then
                        # 合法shell工具白名单
                        if [[ ! "$EXEC_PATHS" =~ (git|bash|dash|ksh|zsh|tcsh|fish|byobu)-shell ]] \
                        && [[ ! "$EXEC_PATHS" =~ /bin/(ba)?sh$ ]]; then
                            matched_suspicious+=("shell")
                        fi
                    fi
                    
                    # 暂存可疑关键词，稍后配合其他特征判断
                    local pending_keywords=""
                    if [ ${#matched_suspicious[@]} -gt 0 ]; then
                        pending_keywords=$(IFS=','; echo "${matched_suspicious[*]}")
                    fi
                fi
            fi
            
            # 优先级4: 检查攻击工具命名
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                ATTACK_PATTERNS="(backup|update).*service"
                # 通用的服务名称但路径在临时目录
                if [[ "$SERVICE_FILE_NAME" =~ $ATTACK_PATTERNS ]]; then
                    if [[ "$EXEC_PATHS" =~ /tmp/|/dev/shm/|/home/ ]]; then
                        SUSPICIOUS_REASONS+=("通用服务名+可疑路径")
                        # 如果有可疑关键词，配合通用服务名+可疑路径一起报警
                        [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                        ((SUSPICIOUS_PATH_COUNT++))
                        IS_SUSPICIOUS=1
                    fi
                fi
            fi
            
            # 优先级5：可疑软链接
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if symlink_reason=$(check_suspicious_symlink "$service_file"); then
                    SUSPICIOUS_REASONS+=("软链接:$symlink_reason")
                    # 如果有可疑关键词，配合可疑软链接一起报警
                    [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                    ((SUSPICIOUS_SYMLINK_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 优先级6：可疑权限
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if perm_reason=$(check_suspicious_permission "$FILE_PERM" "$service_file"); then
                    SUSPICIOUS_REASONS+=("权限:$perm_reason")
                    # 如果有可疑关键词，配合可疑权限一起报警
                    [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                    ((SUSPICIOUS_PERM_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 优先级7：高熵命名（最低优先级，只有在没有其他检测结果时才使用）
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if [ "$(check_service_name_suspicious "$SERVICE_NAME")" = "1" ]; then
                    SUSPICIOUS_REASONS+=("高熵命名")
                    # 如果有可疑关键词，配合高熵命名一起报警
                    [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                    ((SUSPICIOUS_NAME_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 优先级8：最近修改（最低优先级）
            if [ $IS_SUSPICIOUS -eq 0 ] && [ "$FILE_MTIME" -gt "$BASELINE_TIMESTAMP" ] 2>/dev/null; then
                SUSPICIOUS_REASONS+=("最近修改")
                # 如果有可疑关键词，配合最近修改一起报警
                [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                ((RECENT_MODIFIED_COUNT++))
                IS_SUSPICIOUS=1
            fi
        fi
        
        # 计算服务名熵值（用于显示）
        SERVICE_NAME_ENTROPY=$(calculate_shannon_entropy "$SERVICE_NAME")
        SERVICE_NAME_ENTROPY=$(printf "%.2f" $SERVICE_NAME_ENTROPY 2>/dev/null || echo "0.00")
        
        if [ $IS_SUSPICIOUS -eq 1 ]; then
            ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
            SUSPICIOUS_SERVICES+=("可疑|$SERVICE_FILE_NAME|$FILE_MTIME_STR|$FILE_PERM|$EXEC_START|$SERVICE_NAME_ENTROPY|$ALL_REASONS")
            # 注意：可疑项不添加到ALL_SERVICES，因为SUSPICIOUS_SERVICES已经包含了
        else
            ALL_SERVICES+=("正常|$SERVICE_FILE_NAME|$FILE_MTIME_STR|$FILE_PERM|$EXEC_START|$SERVICE_NAME_ENTROPY|-")
        fi
    done
    
    # 输出完整数据列表（所有服务）
    {
        echo "================================================================================"
        echo "完整数据列表：所有检测的服务（共 $TOTAL_SERVICE_COUNT 个，可疑项排在前面）"
        echo "================================================================================"
        printf "| %-6s | %-30s | %-19s | %-4s | %-35s | %-6s | %-35s |\n" "状态" "服务名" "修改时间" "权限" "执行路径" "熵值" "检测原因"
        print_separator "-" 145
    } >> "$LOG_SYSTEMD"
    
    # 先输出可疑项
    for svc_info in "${SUSPICIOUS_SERVICES[@]}"; do
        IFS='|' read -r status name mtime perm exec entropy reasons <<< "$svc_info"
        printf "| %-6s | %-30s | %-19s | %-4s | %-35s | %-6s | %-35s |\n" "$status" "${name:0:30}" "$mtime" "$perm" "${exec:0:35}" "$entropy" "${reasons:0:35}" >> "$LOG_SYSTEMD"
    done
    
    # 再输出正常项（ALL_SERVICES现在只包含正常项）
    for svc_info in "${ALL_SERVICES[@]}"; do
        IFS='|' read -r status name mtime perm exec entropy reasons <<< "$svc_info"
        printf "| %-6s | %-30s | %-19s | %-4s | %-35s | %-6s | %-35s |\n" "$status" "${name:0:30}" "$mtime" "$perm" "${exec:0:35}" "$entropy" "${reasons:0:35}" >> "$LOG_SYSTEMD"
    done
    
    {
        print_separator "=" 145
        echo ""
        echo "统计信息:"
        echo "  总服务数: $TOTAL_SERVICE_COUNT"
        echo "  可疑路径服务: $SUSPICIOUS_PATH_COUNT"
        echo "  可疑权限: $SUSPICIOUS_PERM_COUNT"
        echo "  可疑命名: $SUSPICIOUS_NAME_COUNT"
        echo "  可疑软链接: $SUSPICIOUS_SYMLINK_COUNT"
        echo "  最近修改服务: $RECENT_MODIFIED_COUNT"
        echo ""
    } >> "$LOG_SYSTEMD"
    
    echo ""
    # 使用数组长度统计真实的可疑服务数量（避免同一服务多个原因导致重复计数）
    SUSPICIOUS_TOTAL=${#SUSPICIOUS_SERVICES[@]}
    if [ $SUSPICIOUS_TOTAL -gt 0 ]; then
        echo "发现可疑服务:"
        echo ""
        printf "%-28s %-5s %-6s %-18s %-38s %-28s\n" "服务名" "权限" "熵值" "修改时间" "执行路径" "检测原因"
        print_separator "-" 130
        
        for svc_info in "${SUSPICIOUS_SERVICES[@]}"; do
            IFS='|' read -r status name mtime perm exec entropy reasons <<< "$svc_info"
            printf "%-28s %-5s %-6s %-18s %-38s %-28s\n" "${name:0:28}" "$perm" "$entropy" "$mtime" "${exec:0:38}" "${reasons:0:28}"
        done
    else
        echo "未发现可疑服务"
    fi
    
    # 计算严重级别的数量（排除仅"最近修改"的）
    # 方法：遍历数组，统计不含"最近修改"或含其他原因的服务
    CRITICAL_COUNT=0
    for svc_info in "${SUSPICIOUS_SERVICES[@]}"; do
        IFS='|' read -r status name mtime perm exec reasons <<< "$svc_info"
        # 如果原因不是单纯的"最近修改"或"白名单服务最近修改"，则计入严重
        if [[ ! "$reasons" =~ ^(最近修改|白名单服务最近修改)$ ]]; then
            ((CRITICAL_COUNT++))
        fi
    done
    
    print_statistics "$TOTAL_SERVICE_COUNT" "$SUSPICIOUS_TOTAL" "可疑路径=$SUSPICIOUS_PATH_COUNT, 权限=$SUSPICIOUS_PERM_COUNT, 高熵命名=$SUSPICIOUS_NAME_COUNT, 软链接=$SUSPICIOUS_SYMLINK_COUNT, 最近修改=$RECENT_MODIFIED_COUNT"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_SYSTEMD")
    if [ $CRITICAL_COUNT -gt 0 ]; then
        print_result "CRITICAL" "发现 ${SUSPICIOUS_TOTAL} 个可疑服务 (严重=${CRITICAL_COUNT}) (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 9: 发现 ${SUSPICIOUS_TOTAL} 个可疑服务"
        echo "Result: Critical - Found ${SUSPICIOUS_TOTAL} suspicious services" >> "$LOG_SYSTEMD"
    elif [ $RECENT_MODIFIED_COUNT -gt 0 ]; then
        print_result "WARN" "发现 ${RECENT_MODIFIED_COUNT} 个最近修改的服务 (详见日志: ${LOG_BASENAME})"
        add_detection "MEDIUM" "检测 9: 发现 ${RECENT_MODIFIED_COUNT} 个最近修改的服务"
        echo "Result: Warning" >> "$LOG_SYSTEMD"
    else
        print_result "OK" "正常，服务检查通过"
        add_detection "INFO" "检测 9: 服务正常"
        echo "Result: Normal" >> "$LOG_SYSTEMD"
    fi
}

# ============================================================================
# 检测 10: 二进制程序扫描
# ============================================================================
check_binary() {
    print_check_title "10" "系统二进制程序完整性检查" "文件系统" "高危" "完整性检测"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f"
    else
        DISPLAY_CMD="find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "优先级: 1)可疑关键词 2)伪造系统进程 3)攻击工具命名 4)权限 5)软链接 6)高熵命名 7)最近修改"
    
    {
        echo "================================================================"
        echo "检测 10: 二进制程序扫描"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "时间范围: ${TIME_DESC}"
        echo "检测维度: 权限/命名熵值/软链接/路径合法性/伪造系统进程"
        echo "扫描目录: /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"
        echo ""
    } > "$LOG_BINARY"
    
    BINARY_DIRS="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin"
    BINARY_FILES=""
    
    for dir in $BINARY_DIRS; do
        [ -d "$dir" ] && BINARY_FILES="$BINARY_FILES $(find "$dir" -maxdepth 1 -type f 2>/dev/null)"
    done
    
    declare -a SUSPICIOUS_BINARIES
    declare -a ALL_BINARIES
    RECENT_MODIFIED_COUNT=0
    SUSPICIOUS_PERM_COUNT=0
    SUSPICIOUS_NAME_COUNT=0
    SUSPICIOUS_SYMLINK_COUNT=0
    SUSPICIOUS_PATH_COUNT=0
    FAKE_PROCESS_COUNT=0
    TOTAL_BINARY_COUNT=0
    
    for binary_file in $BINARY_FILES; do
        [ ! -f "$binary_file" ] && [ ! -L "$binary_file" ] && continue
        
        # 跳过脚本自身（如果在扫描目录中）
        BINARY_NAME=$($CMD_BASENAME "$binary_file")
        [[ "$BINARY_NAME" =~ ^process_scanner ]] && continue
        
        # 只计算有效的二进制文件
        ((TOTAL_BINARY_COUNT++))
        FILE_MTIME=$($CMD_STAT -c %Y "$binary_file" 2>/dev/null || echo 0)
        FILE_MTIME_STR=$($CMD_STAT -c %y "$binary_file" 2>/dev/null | $CMD_CUT -d'.' -f1 || echo "unknown")
        FILE_PERM=$($CMD_STAT -c %a "$binary_file" 2>/dev/null || echo "000")
        
        # 获取实际文件路径（如果是软链接）
        REAL_PATH="$binary_file"
        if [ -L "$binary_file" ]; then
            REAL_PATH=$(resolve_link "$binary_file")
            [ -z "$REAL_PATH" ] && REAL_PATH="$binary_file"
        fi
        
        SUSPICIOUS_REASONS=()
        IS_SUSPICIOUS=0
        IS_WHITELIST=0
        
        # 系统程序白名单验证（信任但验证）- 所有关键系统程序必须验证
        IS_WHITELIST=0
        # 基础工具
        local WHITELIST_CHECK="sha1sum|sha224sum|sha256sum|sha384sum|sha512sum|md5sum|base64|base32"
        WHITELIST_CHECK="${WHITELIST_CHECK}|e2fsck|e2label|e4crypt|e4defrag|e2freefrag|resize2fs|dumpe2fs|tune2fs|mke2fs"
        WHITELIST_CHECK="${WHITELIST_CHECK}|py3compile|py3clean|python2|python3|perl5"
        WHITELIST_CHECK="${WHITELIST_CHECK}|pod2html|pod2text|pod2usage|pod2man"
        WHITELIST_CHECK="${WHITELIST_CHECK}|fusermount|fusermount3|killall5|runlevel|telinit|ec2metadata"
        WHITELIST_CHECK="${WHITELIST_CHECK}|chage|chfn|chsh|chgpasswd|newgrp"
        
        # ✨ 核心系统守护进程（必须验证！）
        WHITELIST_CHECK="${WHITELIST_CHECK}|systemd|init|systemctl|journalctl"
        WHITELIST_CHECK="${WHITELIST_CHECK}|sshd|crond|cron|atd"
        WHITELIST_CHECK="${WHITELIST_CHECK}|rsyslogd|syslogd|auditd|dbus-daemon"
        WHITELIST_CHECK="${WHITELIST_CHECK}|NetworkManager|polkitd|cupsd"
        
        # ✨ Web服务和数据库（必须验证！）
        WHITELIST_CHECK="${WHITELIST_CHECK}|nginx|apache2|httpd"
        WHITELIST_CHECK="${WHITELIST_CHECK}|mysql|mysqld|postgres|postgresql"
        
        if [[ "$BINARY_NAME" =~ ^(${WHITELIST_CHECK})$ ]]; then
            IS_WHITELIST=1
            
            # 白名单程序进行深度验证（信任但验证，返回0=成功，1=失败）
            whitelist_error=$(verify_whitelist_program "$BINARY_NAME" "$REAL_PATH" "0" 2>&1)
            if [ $? -ne 0 ]; then
                # 验证失败，记录为高危伪造
                SUSPICIOUS_REASONS+=("白名单伪造:$whitelist_error")
                ((FAKE_PROCESS_COUNT++))
                IS_SUSPICIOUS=1
            fi
        fi
        
        # 非白名单程序才进行常规检测
        if [ $IS_WHITELIST -eq 0 ]; then
            # === 优先级检测策略 ===
            
            # 优先级1: 检查高危关键词（单独触发）和可疑关键词（需配合其他特征）
            # 高危关键词：单独出现即可触发报警
            local critical_keywords=("rootkit" "backdoor" "trojan" "malware" "exploit" "payload")
            # 可疑关键词：需要配合其他特征（路径/熵值/权限/时间）才触发
            local suspicious_keywords=("hidden" "stealth" "miner" "scanner" "reverse" "nc" "netcat" "exec" "daemon" "suspicious" "malicious" "crypto")
            
            # 先检查高危关键词（单独触发）
            local matched_critical=()
            for keyword in "${critical_keywords[@]}"; do
                if [[ "$BINARY_NAME" =~ $keyword ]] || [[ "$REAL_PATH" =~ $keyword ]]; then
                    matched_critical+=("$keyword")
                fi
            done
            
            if [ ${#matched_critical[@]} -gt 0 ]; then
                # 高危关键词：直接报警
                local all_keywords=$(IFS=','; echo "${matched_critical[*]}")
                SUSPICIOUS_REASONS+=("高危关键词($all_keywords)")
                ((SUSPICIOUS_NAME_COUNT++))
                IS_SUSPICIOUS=1
            else
                # 检查可疑关键词（包括shell）
                local matched_suspicious=()
                for keyword in "${suspicious_keywords[@]}"; do
                    if [[ "$BINARY_NAME" =~ $keyword ]] || [[ "$REAL_PATH" =~ $keyword ]]; then
                        matched_suspicious+=("$keyword")
                    fi
                done
                
                # 单独检查shell关键词，排除合法工具
                if [[ "$BINARY_NAME" =~ shell ]]; then
                    # 合法shell工具白名单
                    if [[ "$BINARY_NAME" =~ ^(git|add|remove|byobu|login|restrict|bash|dash|ksh|zsh|tcsh|fish)-shell$ ]] \
                    || [[ "$BINARY_NAME" =~ ^(update|valid|check)-shells?$ ]] \
                    || [[ "$BINARY_NAME" =~ ^(shells?|[a-z]sh)$ ]]; then
                        # 合法shell工具，不添加到可疑关键词
                        :
                    else
                        # 非合法shell工具，添加到可疑关键词列表
                        matched_suspicious+=("shell")
                    fi
                fi
                
                # 暂存可疑关键词，稍后配合其他特征判断
                local pending_keywords=""
                if [ ${#matched_suspicious[@]} -gt 0 ]; then
                    pending_keywords=$(IFS=','; echo "${matched_suspicious[*]}")
                fi
            fi
            
            # 优先级2: 检查伪造系统进程名（路径验证）
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if fake_reason=$(check_fake_system_process "$BINARY_NAME" "$REAL_PATH"); then
                    SUSPICIOUS_REASONS+=("伪造:$fake_reason")
                    # 如果有可疑关键词，配合伪造特征一起报警
                    [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                    ((FAKE_PROCESS_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 优先级3: 检查攻击工具命名
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                ATTACK_PATTERNS="(maker|delete|inject|spawn|hijack)"
                if [[ "$BINARY_NAME" =~ $ATTACK_PATTERNS ]]; then
                    SUSPICIOUS_REASONS+=("攻击工具命名")
                    # 如果有可疑关键词，配合攻击工具命名一起报警
                    [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                    ((SUSPICIOUS_NAME_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 优先级4：可疑权限
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if perm_reason=$(check_suspicious_permission "$FILE_PERM" "$binary_file"); then
                    SUSPICIOUS_REASONS+=("权限:$perm_reason")
                    # 如果有可疑关键词，配合可疑权限一起报警
                    [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                    ((SUSPICIOUS_PERM_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 优先级5：可疑软链接
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if symlink_reason=$(check_suspicious_symlink "$binary_file"); then
                    SUSPICIOUS_REASONS+=("软链接:$symlink_reason")
                    # 如果有可疑关键词，配合可疑软链接一起报警
                    [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                    ((SUSPICIOUS_SYMLINK_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 优先级6：通用白名单路径验证（针对不在WHITELIST_CHECK但在check_name_entropy白名单中的程序）
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                # 检查程序名是否在check_name_entropy的白名单中
                if [ "$(check_name_entropy "$BINARY_NAME")" = "0" ]; then
                    # 在白名单中，进行通用路径验证
                    generic_error=$(verify_whitelist_path_generic "$BINARY_NAME" "$REAL_PATH" 2>&1)
                    if [ $? -ne 0 ]; then
                        # 白名单程序但路径可疑
                        SUSPICIOUS_REASONS+=("白名单路径异常:$generic_error")
                        # 如果有可疑关键词，配合路径异常一起报警
                        [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                        ((SUSPICIOUS_PATH_COUNT++))
                        IS_SUSPICIOUS=1
                    fi
                fi
            fi
            
            # 优先级7：高熵命名（最低优先级，只有在没有其他检测结果时才使用）
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if [ "$(check_name_entropy "$BINARY_NAME")" = "1" ]; then
                    SUSPICIOUS_REASONS+=("高熵命名")
                    # 如果有可疑关键词，配合高熵命名一起报警
                    [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                    ((SUSPICIOUS_NAME_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
            
            # 优先级8：最近修改（最低优先级）
            if [ $IS_SUSPICIOUS -eq 0 ] && [ "$FILE_MTIME" -gt "$BASELINE_TIMESTAMP" ] 2>/dev/null; then
                SUSPICIOUS_REASONS+=("最近修改")
                # 如果有可疑关键词，配合最近修改一起报警
                [ -n "$pending_keywords" ] && SUSPICIOUS_REASONS+=("可疑关键词($pending_keywords)")
                ((RECENT_MODIFIED_COUNT++))
                IS_SUSPICIOUS=1
            fi
        fi
        
        # 计算二进制文件名熵值（用于显示）
        BINARY_NAME_ENTROPY=$(calculate_shannon_entropy "$BINARY_NAME")
        BINARY_NAME_ENTROPY=$(printf "%.2f" $BINARY_NAME_ENTROPY 2>/dev/null || echo "0.00")
        
        if [ $IS_SUSPICIOUS -eq 1 ]; then
            # 合并所有原因
            ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
            SUSPICIOUS_BINARIES+=("可疑|$BINARY_NAME|$FILE_MTIME_STR|$FILE_PERM|$binary_file|$BINARY_NAME_ENTROPY|$ALL_REASONS")
            # 注意：可疑项不添加到ALL_BINARIES，因为SUSPICIOUS_BINARIES已经包含了
        else
            ALL_BINARIES+=("正常|$BINARY_NAME|$FILE_MTIME_STR|$FILE_PERM|$binary_file|$BINARY_NAME_ENTROPY|-")
        fi
    done
    
    {
        echo "--------------------------------------------------------------------------------"
        echo "完整数据列表（所有检测的二进制程序，可疑项排在前面）"
        echo "--------------------------------------------------------------------------------"
        printf "| %-8s | %-23s | %-17s | %-6s | %-33s | %-8s | %-28s |\n" "状态" "程序名" "修改时间" "权限" "完整路径" "熵值" "检测原因"
        print_separator "-" 135
    } >> "$LOG_BINARY"
    
    # 先输出可疑项
    for bin_info in "${SUSPICIOUS_BINARIES[@]}"; do
        IFS='|' read -r status name mtime perm path entropy reason <<< "$bin_info"
        printf "| %-8s | %-23s | %-17s | %-6s | %-33s | %-8s | %-28s |\n" "$status" "${name:0:23}" "$mtime" "$perm" "${path:0:33}" "$entropy" "${reason:0:28}" >> "$LOG_BINARY"
    done
    
    # 再输出正常项（ALL_BINARIES现在只包含正常项）
    for bin_info in "${ALL_BINARIES[@]}"; do
        IFS='|' read -r status name mtime perm path entropy reason <<< "$bin_info"
        printf "| %-8s | %-23s | %-17s | %-6s | %-33s | %-8s | %-28s |\n" "$status" "${name:0:23}" "$mtime" "$perm" "${path:0:33}" "$entropy" "${reason:0:28}" >> "$LOG_BINARY"
    done
    
    {
        print_separator "=" 135
        echo ""
        echo "统计信息:"
        echo "  总程序数: $TOTAL_BINARY_COUNT"
        echo "  可疑权限程序: $SUSPICIOUS_PERM_COUNT"
        echo "  可疑软链接: $SUSPICIOUS_SYMLINK_COUNT"
        echo "  可疑命名程序: $SUSPICIOUS_NAME_COUNT"
        echo "  伪造系统进程: $FAKE_PROCESS_COUNT"
        echo "  最近修改程序: $RECENT_MODIFIED_COUNT"
        echo ""
    } >> "$LOG_BINARY"
    
    echo ""
    # 使用数组长度统计真实的可疑程序数量（避免同一程序多个原因导致重复计数）
    SUSPICIOUS_TOTAL=${#SUSPICIOUS_BINARIES[@]}
    if [ $SUSPICIOUS_TOTAL -gt 0 ]; then
        echo "发现可疑程序:"
        echo ""
        printf "%-30s  %-6s  %-8s  %-20s  %-45s  %-40s\n" "程序名" "权限" "熵值" "修改时间" "完整路径" "检测原因"
        print_separator "-" 160
        
        for bin_info in "${SUSPICIOUS_BINARIES[@]}"; do
            IFS='|' read -r status name mtime perm path entropy reason <<< "$bin_info"
            printf "%-30s  %-6s  %-8s  %-20s  %-45s  %-40s\n" "${name:0:30}" "$perm" "$entropy" "$mtime" "${path:0:45}" "${reason:0:40}"
        done
    else
        echo "未发现可疑程序"
    fi
    
    # 计算严重级别的数量（排除仅"最近修改"的）
    CRITICAL_COUNT=0
    for bin_info in "${SUSPICIOUS_BINARIES[@]}"; do
        IFS='|' read -r status name mtime perm path entropy reason <<< "$bin_info"
        # 如果原因不是单纯的"最近修改"，则计入严重
        if [[ ! "$reason" =~ ^最近修改$ ]]; then
            ((CRITICAL_COUNT++))
        fi
    done
    
    print_statistics "$TOTAL_BINARY_COUNT" "$SUSPICIOUS_TOTAL" "权限=$SUSPICIOUS_PERM_COUNT, 软链接=$SUSPICIOUS_SYMLINK_COUNT, 高熵命名=$SUSPICIOUS_NAME_COUNT, 伪造=$FAKE_PROCESS_COUNT, 最近修改=$RECENT_MODIFIED_COUNT"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_BINARY")
    if [ $CRITICAL_COUNT -gt 0 ]; then
        print_result "CRITICAL" "发现 ${SUSPICIOUS_TOTAL} 个可疑程序 (严重=${CRITICAL_COUNT}) (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 10: 发现 ${SUSPICIOUS_TOTAL} 个可疑程序"
        echo "Result: Critical - Found ${SUSPICIOUS_TOTAL} suspicious binaries" >> "$LOG_BINARY"
    elif [ $RECENT_MODIFIED_COUNT -gt 0 ]; then
        print_result "WARN" "发现 ${RECENT_MODIFIED_COUNT} 个最近修改的程序 (详见日志: ${LOG_BASENAME})"
        add_detection "MEDIUM" "检测 10: 发现 ${RECENT_MODIFIED_COUNT} 个最近修改的程序"
        echo "Result: Warning" >> "$LOG_BINARY"
    else
        print_result "OK" "正常，二进制程序检查通过"
        add_detection "INFO" "检测 10: 二进制程序正常"
        echo "Result: Normal" >> "$LOG_BINARY"
    fi
}

# ============================================================================
# 检测 11: Crontab 定时任务检查
# ============================================================================
check_crontab() {
    print_check_title "11" "定时任务持久化后门检测" "持久化" "高危" "定时任务分析"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="crontab -l (系统命令) && atq && $BUSYBOX_PATH ls /var/spool/cron/* && $BUSYBOX_PATH cat /etc/cron* /var/log/cron"
    else
        DISPLAY_CMD="crontab -l && atq && ls /var/spool/cron/* && cat /etc/cron* /var/log/cron"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "隐藏任务+恶意命令+at异步任务+软链接+执行日志分析"
    
    LOG_CRONTAB="$LOG_DIR/11_crontab_$(date +%Y%m%d_%H%M%S).log"
    
    {
        echo "================================================================"
        echo "检测 11: Crontab 定时任务检查"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测维度: 1)隐藏任务(控制字符/异常时间/转义字符/前导空格/@特殊标记)"
        echo "          2)恶意命令(反弹shell/下载执行/临时目录/base64/隐藏文件)"
        echo "          3)at/batch异步任务检测"
        echo "          4)cron脚本软链接检测"
        echo "          5)cron执行日志分析"
        echo ""
    } > "$LOG_CRONTAB"
    
    declare -a SUSPICIOUS_CRONS
    SUSPICIOUS_COUNT=0
    TOTAL_CRON_COUNT=0
    
    # 检查系统级crontab
    CRON_FILES="/etc/crontab"
    CRON_DIRS="/etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly"
    
    for cron_file in $CRON_FILES; do
        [ ! -f "$cron_file" ] && continue
        while IFS= read -r line; do
            # 注意：不跳过空行，可能包含隐藏字符
            ORIGINAL_LINE="$line"
            
            # 跳过真正的空行
            [ -z "$line" ] && continue
            
            # 跳过纯注释行（以#开头，包括单独的#）
            if [[ "$line" =~ ^[[:space:]]*# ]]; then
                # 注释行直接跳过，不检测控制字符（避免误报）
                continue
            fi
            
            # 跳过环境变量定义行（KEY=VALUE格式）
            # 常见的crontab变量：SHELL, PATH, MAILTO, HOME, LOGNAME等
            if [[ "$line" =~ ^[[:space:]]*[A-Z_][A-Z0-9_]*= ]]; then
                continue
            fi
            
            ((TOTAL_CRON_COUNT++))
            SUSPICIOUS_REASONS=()
            
            # === 隐藏任务检测（高优先级）===
            
            # 注意：移除NULL字符检测，因为在Busybox环境下误报率太高
            # 专注于检测实际的可疑命令模式
            
            # 检测2: 异常的时间格式（如 0* 或其他畸形格式）
            # 提取时间字段（前5个字段或@special）
            if [[ ! "$line" =~ ^@ ]]; then
                # 确保这一行看起来像cron任务（至少有5个字段）
                FIELD_COUNT=$($CMD_ECHO "$line" | $CMD_AWK '{print NF}')
                if [ "$FIELD_COUNT" -ge 5 ]; then
                    TIME_FIELDS=$($CMD_ECHO "$line" | $CMD_AWK '{print $1,$2,$3,$4,$5}')
                    
                    # 检测异常模式：连续的0和*（如 0* 或 *0）
                    if [[ "$TIME_FIELDS" =~ 0\*|\*0[[:space:]] ]]; then
                        SUSPICIOUS_REASONS+=("隐藏任务:异常时间格式")
                    fi
                    
                    # 检测时间字段包含非法字符（排除正常的cron字符）
                    # 合法字符：数字、空格、制表符、*、,、-、/
                    # 注意：- 必须放在字符类的最后或转义
                    if $CMD_ECHO "$TIME_FIELDS" | $CMD_GREP -qE '[^0-9 	\*,/-]'; then
                        SUSPICIOUS_REASONS+=("隐藏任务:时间字段包含特殊字符")
                    fi
                else
                    # 字段数不足5个，可能不是有效的cron行，跳过检测
                    continue
                fi
            fi
            
            # 检测3: 前导不可见字符或多余空格（隐藏技巧）
            if [[ "$line" =~ ^[[:space:]]{2,} ]]; then
                SUSPICIOUS_REASONS+=("隐藏任务:前导多余空格")
            fi
            
            # 检测4: @reboot等特殊时间标记（高风险持久化）
            if [[ "$line" =~ ^@(reboot|yearly|annually|monthly|weekly|daily|hourly) ]]; then
                # 注意：Busybox grep 不支持 -P，使用 sed 提取
                TIME_MARK=$($CMD_ECHO "$line" | $CMD_SED 's/^@\([a-zA-Z]*\).*/\1/')
                SUSPICIOUS_REASONS+=("特殊时间标记:@${TIME_MARK}")
            fi
            
            # 检测5: 混淆的用户字段（某些cron允许指定用户）
            if [[ "$cron_file" == "/etc/crontab" ]]; then
                USER_FIELD=$($CMD_ECHO "$line" | $CMD_AWK '{print $6}')
                if [[ "$USER_FIELD" =~ ^[0-9] ]] || [ ${#USER_FIELD} -gt 20 ]; then
                    SUSPICIOUS_REASONS+=("隐藏任务:异常用户字段")
                fi
            fi
            
            # 检测6: 使用十六进制或八进制转义的命令
            if $CMD_ECHO "$line" | $CMD_GREP -qE '\\x[0-9a-fA-F]{2}|\\[0-7]{3}'; then
                SUSPICIOUS_REASONS+=("隐藏任务:十六进制/八进制转义")
            fi
            
            # === 恶意命令检测 ===
            
            # 检测反弹shell特征
            if $CMD_ECHO "$line" | $CMD_GREP -qE '(bash -i|nc -e|/dev/tcp/|perl.*socket|python.*socket)'; then
                SUSPICIOUS_REASONS+=("反弹shell")
            fi
            
            # 检测下载并执行
            if $CMD_ECHO "$line" | $CMD_GREP -qE '(wget|curl).*\|.*(bash|sh|python|perl)'; then
                SUSPICIOUS_REASONS+=("下载执行")
            fi
            
            # 检测临时目录
            if $CMD_ECHO "$line" | $CMD_GREP -qE '/tmp/|/dev/shm/|/var/tmp/'; then
                SUSPICIOUS_REASONS+=("临时目录")
            fi
            
            # 检测base64编码
            if $CMD_ECHO "$line" | $CMD_GREP -qE 'base64.*-d|echo.*\|.*base64'; then
                SUSPICIOUS_REASONS+=("base64编码")
            fi
            
            # 检测隐藏文件
            if $CMD_ECHO "$line" | $CMD_GREP -qE '\./\.[a-zA-Z]|/\.[a-zA-Z][a-zA-Z0-9_-]+'; then
                SUSPICIOUS_REASONS+=("隐藏文件")
            fi
            
            if [ ${#SUSPICIOUS_REASONS[@]} -gt 0 ]; then
                ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
                # 显示原始行（保留特殊字符的可见表示）
                DISPLAY_LINE=$($CMD_ECHO "$ORIGINAL_LINE" | $CMD_CAT -v)
                SUSPICIOUS_CRONS+=("系统|$cron_file|${DISPLAY_LINE:0:60}|$ALL_REASONS")
                ((SUSPICIOUS_COUNT++))
            fi
        done < "$cron_file"
    done
    
    # 用于存储所有任务（供日志输出）
    declare -a ALL_CRON_TASKS
    
    # 检查cron目录
    for cron_dir in $CRON_DIRS; do
        [ ! -d "$cron_dir" ] && continue
        for cron_script in "$cron_dir"/*; do
            [ ! -f "$cron_script" ] && continue
            
            ((TOTAL_CRON_COUNT++))
            SCRIPT_NAME=$($CMD_BASENAME "$cron_script")
            SUSPICIOUS_REASONS=()
            
            # === 优先级检测策略 ===
            
            # 优先级1: 检查可疑内容（最高优先级）
            if grep -qE '(bash -i|nc -e|/dev/tcp/|wget.*\||curl.*\|)' "$cron_script" 2>/dev/null; then
                SUSPICIOUS_REASONS+=("可疑命令")
            fi
            
            # 优先级2: 检查可疑关键词
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                local keywords=("hidden" "stealth" "suspicious" "malicious" "backdoor" "rootkit")
                local matched_keywords=()
                for keyword in "${keywords[@]}"; do
                    if [[ "$SCRIPT_NAME" =~ $keyword ]]; then
                        matched_keywords+=("$keyword")
                    fi
                done
                if [ ${#matched_keywords[@]} -gt 0 ]; then
                    local all_keywords=$(IFS=','; echo "${matched_keywords[*]}")
                    SUSPICIOUS_REASONS+=("可疑关键词($all_keywords)")
                fi
            fi
            
            # 优先级3: 检查最近修改
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                FILE_MTIME=$($CMD_STAT -c %Y "$cron_script" 2>/dev/null || echo 0)
                if [ "$FILE_MTIME" -gt "$BASELINE_TIMESTAMP" ] 2>/dev/null; then
                    FILE_MTIME_STR=$($CMD_STAT -c %y "$cron_script" 2>/dev/null | $CMD_CUT -d'.' -f1)
                    SUSPICIOUS_REASONS+=("最近修改:$FILE_MTIME_STR")
                fi
            fi
            
            # 优先级4: 检查高熵命名（最低优先级）
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                # 标准cron脚本白名单
                local STANDARD_CRON_SCRIPTS="^(logrotate|man-db|mlocate|apt-compat|dpkg|update-notifier|bsdmainutils|popularity-contest|passwd)"
                STANDARD_CRON_SCRIPTS="${STANDARD_CRON_SCRIPTS}|^(e2scrub_all|locate|plocate|cracklib-runtime|samba|apache2|mysql|postgresql|nginx)"
                STANDARD_CRON_SCRIPTS="${STANDARD_CRON_SCRIPTS}|^(0anacron|update-ca-certificates|update-grub-legacy-ec2)"
                
                if [[ ! "$SCRIPT_NAME" =~ $STANDARD_CRON_SCRIPTS ]]; then
                    if [ "$(check_name_entropy "$SCRIPT_NAME")" = "1" ]; then
                        SUSPICIOUS_REASONS+=("高熵命名")
                    fi
                fi
            fi
            
            if [ ${#SUSPICIOUS_REASONS[@]} -gt 0 ]; then
                ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
                SUSPICIOUS_CRONS+=("系统|$cron_script|脚本内容检查|$ALL_REASONS")
                ALL_CRON_TASKS+=("可疑|系统|$cron_script|脚本|$ALL_REASONS")
                ((SUSPICIOUS_COUNT++))
            else
                ALL_CRON_TASKS+=("正常|系统|$cron_script|脚本|正常")
            fi
        done
    done
    
    # 检查用户crontab
    CRON_SPOOL_DIR="/var/spool/cron"
    if [ -d "$CRON_SPOOL_DIR" ]; then
        for user_cron in "$CRON_SPOOL_DIR"/*; do
            [ ! -f "$user_cron" ] && continue
            USERNAME=$($CMD_BASENAME "$user_cron")
            while IFS= read -r line; do
                ORIGINAL_LINE="$line"
                
                # 跳过真正的空行
                [ -z "$line" ] && continue
                
                # 跳过纯注释行（以#开头，包括单独的#）
                if [[ "$line" =~ ^[[:space:]]*# ]]; then
                    # 注释行直接跳过，不检测控制字符（避免误报）
                    continue
                fi
                
                # 跳过环境变量定义行
                if [[ "$line" =~ ^[[:space:]]*[A-Z_][A-Z0-9_]*= ]]; then
                    continue
                fi
                
                ((TOTAL_CRON_COUNT++))
                SUSPICIOUS_REASONS=()
                
                # === 隐藏任务检测 ===
                
                # 注意：移除NULL字符检测，因为在Busybox环境下误报率太高
                # 专注于检测实际的可疑命令模式
                
                # 检测异常时间格式
                if [[ ! "$line" =~ ^@ ]]; then
                    # 确保这一行看起来像cron任务（至少有5个字段）
                    FIELD_COUNT=$($CMD_ECHO "$line" | $CMD_AWK '{print NF}')
                    if [ "$FIELD_COUNT" -ge 5 ]; then
                        TIME_FIELDS=$($CMD_ECHO "$line" | $CMD_AWK '{print $1,$2,$3,$4,$5}')
                        
                        # 检测异常模式：连续的0和*（如 0* 或 *0）
                        if [[ "$TIME_FIELDS" =~ 0\*|\*0[[:space:]] ]]; then
                            SUSPICIOUS_REASONS+=("隐藏任务:异常时间格式")
                        fi
                        
                        # 检测时间字段包含非法字符
                        # 注意：- 必须放在字符类的最后或转义
                        if $CMD_ECHO "$TIME_FIELDS" | $CMD_GREP -qE '[^0-9 	\*,/-]'; then
                            SUSPICIOUS_REASONS+=("隐藏任务:时间字段特殊字符")
                        fi
                    else
                        # 字段数不足5个，可能不是有效的cron行，跳过
                        continue
                    fi
                fi
                
                # 检测前导多余空格
                if [[ "$line" =~ ^[[:space:]]{2,} ]]; then
                    SUSPICIOUS_REASONS+=("隐藏任务:前导多余空格")
                fi
                
                # 检测@特殊标记
                if [[ "$line" =~ ^@(reboot|yearly|annually|monthly|weekly|daily|hourly) ]]; then
                    # 注意：Busybox grep 不支持 -P，使用 sed 提取
                    TIME_MARK=$($CMD_ECHO "$line" | $CMD_SED 's/^@\([a-zA-Z]*\).*/\1/')
                    SUSPICIOUS_REASONS+=("特殊时间标记:@${TIME_MARK}")
                fi
                
                # 检测转义字符
                if $CMD_ECHO "$line" | $CMD_GREP -qE '\\x[0-9a-fA-F]{2}|\\[0-7]{3}'; then
                    SUSPICIOUS_REASONS+=("隐藏任务:转义字符")
                fi
                
                # === 恶意命令检测 ===
                
                if $CMD_ECHO "$line" | $CMD_GREP -qE '(bash -i|nc -e|/dev/tcp/)'; then
                    SUSPICIOUS_REASONS+=("反弹shell")
                fi
                if $CMD_ECHO "$line" | $CMD_GREP -qE '/tmp/|/dev/shm/'; then
                    SUSPICIOUS_REASONS+=("临时目录")
                fi
                if $CMD_ECHO "$line" | $CMD_GREP -qE 'base64.*-d|echo.*\|.*base64'; then
                    SUSPICIOUS_REASONS+=("base64编码")
                fi
                if $CMD_ECHO "$line" | $CMD_GREP -qE '\./\.[a-zA-Z]|/\.[a-zA-Z][a-zA-Z0-9_-]+'; then
                    SUSPICIOUS_REASONS+=("隐藏文件")
                fi
                
                if [ ${#SUSPICIOUS_REASONS[@]} -gt 0 ]; then
                    ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
                    DISPLAY_LINE=$($CMD_ECHO "$ORIGINAL_LINE" | $CMD_CAT -v)
                    SUSPICIOUS_CRONS+=("用户:$USERNAME|$user_cron|${DISPLAY_LINE:0:60}|$ALL_REASONS")
                    ALL_CRON_TASKS+=("可疑|用户:$USERNAME|$user_cron|${DISPLAY_LINE:0:60}|$ALL_REASONS")
                    ((SUSPICIOUS_COUNT++))
                else
                    ALL_CRON_TASKS+=("正常|用户:$USERNAME|$user_cron|${line:0:60}|正常")
                fi
            done < "$user_cron"
        done
    fi
    
    # 首先输出完整的定时任务列表
    {
        echo "================================================================================"
        echo "完整数据列表：所有检测到的定时任务（可疑项排在前面）"
        echo "================================================================================"
        printf "| %-8s | %-15s | %-40s | %-40s | %-25s |\n" "状态" "类型" "位置" "命令/脚本" "检测原因"
        print_separator "-" 140
    } >> "$LOG_CRONTAB"
    
    # 先输出可疑任务
    for task_info in "${ALL_CRON_TASKS[@]}"; do
        IFS='|' read -r status type location content reasons <<< "$task_info"
        if [ "$status" = "可疑" ]; then
            printf "| %-8s | %-15s | %-40s | %-40s | %-25s |\n" "$status" "${type:0:15}" "${location:0:40}" "${content:0:40}" "${reasons:0:25}" >> "$LOG_CRONTAB"
        fi
    done
    
    # 再输出正常任务
    for task_info in "${ALL_CRON_TASKS[@]}"; do
        IFS='|' read -r status type location content reasons <<< "$task_info"
        if [ "$status" = "正常" ]; then
            printf "| %-8s | %-15s | %-40s | %-40s | %-25s |\n" "$status" "${type:0:15}" "${location:0:40}" "${content:0:40}" "${reasons:0:25}" >> "$LOG_CRONTAB"
        fi
    done
    
    echo "" >> "$LOG_CRONTAB"
    
    # 然后输出可疑任务的详细列表
    {
        echo "================================================================================"
        echo "可疑的定时任务（详细）"
        echo "================================================================================"
        printf "| %-15s | %-40s | %-60s | %-30s |\n" "类型" "位置" "命令/内容" "检测原因"
        print_separator "-" 155
    } >> "$LOG_CRONTAB"
    
    if [ $SUSPICIOUS_COUNT -gt 0 ]; then
        for cron_info in "${SUSPICIOUS_CRONS[@]}"; do
            IFS='|' read -r type location cmd reasons <<< "$cron_info"
            printf "| %-15s | %-40s | %-60s | %-30s |\n" "$type" "${location:0:40}" "${cmd:0:60}" "${reasons:0:30}" >> "$LOG_CRONTAB"
        done
    else
        echo "| (未发现可疑定时任务)" >> "$LOG_CRONTAB"
    fi
    
    {
        print_separator "=" 155
        echo ""
        echo "统计信息:"
        echo "  总定时任务数: $TOTAL_CRON_COUNT"
        echo "  可疑任务数: $SUSPICIOUS_COUNT"
        echo ""
    } >> "$LOG_CRONTAB"
    
    echo ""
    if [ $SUSPICIOUS_COUNT -gt 0 ]; then
        echo "发现可疑定时任务:"
        echo ""
        printf "%-12s %-25s %-80s %-30s\n" "类型" "位置" "命令/内容" "检测原因"
        print_separator "-" 152
        for cron_info in "${SUSPICIOUS_CRONS[@]}"; do
            IFS='|' read -r type location cmd reasons <<< "$cron_info"
            # 简化类型显示
            TYPE_DISPLAY=$(echo "$type" | $CMD_CUT -d: -f1)
            # 显示完整命令
            printf "%-12s %-25s %-80s %-30s\n" "$TYPE_DISPLAY" "${location:0:25}" "${cmd:0:80}" "${reasons:0:30}"
        done
    else
        echo "未发现可疑定时任务"
    fi
    
    # ============================================================================
    # 扩展检测1: at/batch 异步任务检测
    # ============================================================================
    echo ""
    echo "================================================================================"
    echo "[扩展检测] at/batch 异步任务检测"
    echo "================================================================================"
    
    AT_COUNT=0
    AT_SUSPICIOUS_COUNT=0
    
    # 检查at队列
    if command -v atq &>/dev/null; then
        AT_QUEUE=$(atq 2>/dev/null)
        if [ -n "$AT_QUEUE" ]; then
            echo "发现at任务队列:"
            echo "$AT_QUEUE"
            
            {
                echo ""
                echo "--------------------------------------------------------------------------------"
                echo "at/batch 异步任务队列"
                echo "--------------------------------------------------------------------------------"
                echo "$AT_QUEUE"
                echo ""
            } >> "$LOG_CRONTAB"
            
            # 检查每个at任务
            while read -r job_id rest; do
                [ -z "$job_id" ] || [[ ! "$job_id" =~ ^[0-9]+$ ]] && continue
                ((AT_COUNT++))
                
                # 获取任务详情
                AT_JOB_CONTENT=$(at -c "$job_id" 2>/dev/null)
                
                if [ -n "$AT_JOB_CONTENT" ]; then
                    # 先输出完整内容到日志（供人工分析）
                    {
                        echo "--------------------------------------------------------------------------------"
                        echo "at任务ID: $job_id (完整内容)"
                        echo "--------------------------------------------------------------------------------"
                        echo "$AT_JOB_CONTENT"
                        echo ""
                    } >> "$LOG_CRONTAB"
                    
                    # 检测可疑内容
                    if echo "$AT_JOB_CONTENT" | grep -qE '(bash -i|nc -e|/dev/tcp/|/tmp/|/dev/shm/|wget.*\||curl.*\||base64.*-d)'; then
                        echo "  [可疑] at任务 $job_id: 包含可疑命令"
                        {
                            echo "[检测结果: 可疑]"
                            echo "匹配的可疑模式："
                            echo "$AT_JOB_CONTENT" | grep -E '(bash -i|nc -e|/dev/tcp/|/tmp/|/dev/shm/|wget|curl|base64)'
                            echo ""
                        } >> "$LOG_CRONTAB"
                        SUSPICIOUS_CRONS+=("at任务|job_id:$job_id|异步任务|可疑命令")
                        ((AT_SUSPICIOUS_COUNT++))
                        ((SUSPICIOUS_COUNT++))
                    else
                        {
                            echo "[检测结果: 正常]"
                            echo ""
                        } >> "$LOG_CRONTAB"
                    fi
                fi
            done <<< "$AT_QUEUE"
            
            echo "  at任务总数: $AT_COUNT, 可疑: $AT_SUSPICIOUS_COUNT"
            {
                echo "================================================================================"
                echo "at任务检测总结"
                echo "================================================================================"
                echo "  总任务数: $AT_COUNT"
                echo "  可疑任务: $AT_SUSPICIOUS_COUNT"
                echo ""
            } >> "$LOG_CRONTAB"
        else
            echo "  未发现at任务队列"
            {
                echo "at任务队列: 空"
                echo ""
            } >> "$LOG_CRONTAB"
        fi
    else
        echo "  at命令不可用"
        {
            echo "at命令: 不可用（系统未安装at）"
            echo ""
        } >> "$LOG_CRONTAB"
    fi
    
    # 检查at任务目录（某些系统会保存）
    AT_SPOOL_DIR="/var/spool/cron/atjobs"
    if [ -d "$AT_SPOOL_DIR" ]; then
        AT_JOB_FILES=$(ls "$AT_SPOOL_DIR" 2>/dev/null | wc -l)
        if [ "$AT_JOB_FILES" -gt 0 ]; then
            echo "  /var/spool/cron/atjobs: $AT_JOB_FILES 个任务文件"
            {
                echo "--------------------------------------------------------------------------------"
                echo "at任务文件列表: /var/spool/cron/atjobs"
                echo "--------------------------------------------------------------------------------"
                ls -lh "$AT_SPOOL_DIR" 2>/dev/null
                echo ""
            } >> "$LOG_CRONTAB"
        fi
    fi
    
    # ============================================================================
    # 扩展检测2: cron脚本软链接检测
    # ============================================================================
    echo ""
    echo "================================================================================"
    echo "[扩展检测] cron脚本软链接检测"
    echo "================================================================================"
    
    SYMLINK_COUNT=0
    SUSPICIOUS_SYMLINK_COUNT=0
    
    {
        echo "--------------------------------------------------------------------------------"
        echo "cron脚本软链接分析"
        echo "--------------------------------------------------------------------------------"
    } >> "$LOG_CRONTAB"
    
    for cron_dir in $CRON_DIRS; do
        [ ! -d "$cron_dir" ] && continue
        for cron_file in "$cron_dir"/*; do
            [ ! -e "$cron_file" ] && continue
            
            if [ -L "$cron_file" ]; then
                ((SYMLINK_COUNT++))
                LINK_TARGET=$(resolve_link "$cron_file")
                LINK_NAME=$($CMD_BASENAME "$cron_file")
                
                SYMLINK_REASONS=()
                
                # 检查软链接目标
                if [[ "$LINK_TARGET" =~ ^/tmp/|^/dev/shm/|^/var/tmp/ ]]; then
                    SYMLINK_REASONS+=("链接到临时目录")
                fi
                
                if [[ "$LINK_TARGET" =~ ^/home/|^/root/ ]]; then
                    SYMLINK_REASONS+=("链接到用户目录")
                fi
                
                if [ ! -e "$LINK_TARGET" ]; then
                    SYMLINK_REASONS+=("目标不存在")
                fi
                
                # 检查文件名不匹配
                TARGET_NAME=$($CMD_BASENAME "$LINK_TARGET")
                if [ "$LINK_NAME" != "$TARGET_NAME" ] && [[ ! "$TARGET_NAME" =~ ^(run-parts|cron\.) ]]; then
                    SYMLINK_REASONS+=("名称不匹配")
                fi
                
                if [ ${#SYMLINK_REASONS[@]} -gt 0 ]; then
                    ALL_REASONS=$(IFS=','; echo "${SYMLINK_REASONS[*]}")
                    echo "  [可疑] $cron_file -> $LINK_TARGET ($ALL_REASONS)"
                    {
                        printf "可疑软链接: %s -> %s\n原因: %s\n\n" "$cron_file" "$LINK_TARGET" "$ALL_REASONS"
                    } >> "$LOG_CRONTAB"
                    SUSPICIOUS_CRONS+=("软链接|$cron_file|$LINK_TARGET|$ALL_REASONS")
                    ((SUSPICIOUS_SYMLINK_COUNT++))
                    ((SUSPICIOUS_COUNT++))
                else
                    {
                        printf "正常软链接: %s -> %s\n" "$cron_file" "$LINK_TARGET"
                    } >> "$LOG_CRONTAB"
                fi
            fi
        done
    done
    
    if [ $SYMLINK_COUNT -eq 0 ]; then
        echo "  未发现cron脚本软链接"
        {
            echo "cron脚本软链接: 未发现"
            echo ""
        } >> "$LOG_CRONTAB"
    else
        echo "  软链接总数: $SYMLINK_COUNT, 可疑: $SUSPICIOUS_SYMLINK_COUNT"
        {
            echo ""
            echo "================================================================================"
            echo "软链接检测总结"
            echo "================================================================================"
            echo "  总软链接数: $SYMLINK_COUNT"
            echo "  可疑软链接: $SUSPICIOUS_SYMLINK_COUNT"
            echo ""
        } >> "$LOG_CRONTAB"
    fi
    
    # ============================================================================
    # 扩展检测3: cron执行日志分析
    # ============================================================================
    echo ""
    echo "================================================================================"
    echo "[扩展检测] cron执行日志分析"
    echo "================================================================================"
    
    LOG_SUSPICIOUS_COUNT=0
    CRON_LOG_FILES="/var/log/cron /var/log/cron.log /var/log/syslog"
    
    {
        echo "--------------------------------------------------------------------------------"
        echo "cron执行日志分析（最近100行）"
        echo "--------------------------------------------------------------------------------"
    } >> "$LOG_CRONTAB"
    
    for cron_log in $CRON_LOG_FILES; do
        if [ -f "$cron_log" ]; then
            echo "  分析日志: $cron_log"
            
            # 提取最近的cron执行记录
            RECENT_CRON=$($CMD_TAIL -n 100 "$cron_log" 2>/dev/null | $CMD_GREP -i "cron\|CRON" || true)
            
            if [ -n "$RECENT_CRON" ]; then
                {
                    echo "日志文件: $cron_log"
                    echo ""
                } >> "$LOG_CRONTAB"
                
                # 检测可疑模式
                # 1. 执行失败或错误
                CRON_ERRORS=$($CMD_ECHO "$RECENT_CRON" | $CMD_GREP -iE "error|fail|denied|permission" || true)
                if [ -n "$CRON_ERRORS" ]; then
                    echo "    [警告] 发现执行错误:"
                    $CMD_ECHO "$CRON_ERRORS" | $CMD_HEAD -n 5 | $CMD_SED 's/^/      /'
                    {
                        echo "[执行错误]"
                        $CMD_ECHO "$CRON_ERRORS" | $CMD_HEAD -n 10
                        echo ""
                    } >> "$LOG_CRONTAB"
                    ((LOG_SUSPICIOUS_COUNT++))
                fi
                
                # 2. 临时目录执行
                TEMP_EXEC=$($CMD_ECHO "$RECENT_CRON" | $CMD_GREP -E "/tmp/|/dev/shm/|/var/tmp/" || true)
                if [ -n "$TEMP_EXEC" ]; then
                    echo "    [可疑] 临时目录任务执行:"
                    $CMD_ECHO "$TEMP_EXEC" | $CMD_HEAD -n 5 | $CMD_SED 's/^/      /'
                    {
                        echo "[临时目录执行]"
                        $CMD_ECHO "$TEMP_EXEC" | $CMD_HEAD -n 10
                        echo ""
                    } >> "$LOG_CRONTAB"
                    SUSPICIOUS_CRONS+=("日志痕迹|$cron_log|临时目录执行|cron日志")
                    ((LOG_SUSPICIOUS_COUNT++))
                    ((SUSPICIOUS_COUNT++))
                fi
                
                # 3. root用户异常任务
                ROOT_TASKS=$($CMD_ECHO "$RECENT_CRON" | $CMD_GREP "root" | $CMD_GREP -vE "run-parts|logrotate|apt|dpkg|updatedb" || true)
                if [ -n "$ROOT_TASKS" ]; then
                    ROOT_COUNT=$($CMD_ECHO "$ROOT_TASKS" | $CMD_WC -l)
                    ROOT_COUNT=${ROOT_COUNT//[^0-9]/}; ROOT_COUNT=${ROOT_COUNT:-0}
                    if [ $ROOT_COUNT -gt 0 ]; then
                        echo "    [信息] root用户任务: $ROOT_COUNT 条"
                        {
                            echo "[root用户任务示例]"
                            $CMD_ECHO "$ROOT_TASKS" | $CMD_HEAD -n 5
                            echo ""
                        } >> "$LOG_CRONTAB"
                    fi
                fi
                
                # 4. 不常见的用户
                UNUSUAL_USERS=$($CMD_ECHO "$RECENT_CRON" | $CMD_GREP -vE "root|www-data|nobody|daemon|sys|sync|games|man|lp|mail|news|uucp|proxy|list|irc|gnats|backup" | $CMD_GREP "CMD" || true)
                if [ -n "$UNUSUAL_USERS" ]; then
                    echo "    [注意] 非常见用户任务:"
                    $CMD_ECHO "$UNUSUAL_USERS" | $CMD_HEAD -n 3 | $CMD_SED 's/^/      /'
                    {
                        echo "[非常见用户任务]"
                        $CMD_ECHO "$UNUSUAL_USERS" | $CMD_HEAD -n 5
                        echo ""
                    } >> "$LOG_CRONTAB"
                fi
            fi
            
            # 只分析第一个找到的日志
            break
        fi
    done
    
    if [ $LOG_SUSPICIOUS_COUNT -eq 0 ]; then
        echo "  未发现cron日志异常"
        {
            echo ""
            echo "================================================================================"
            echo "cron执行日志检测总结"
            echo "================================================================================"
            echo "  未发现cron日志异常"
            echo ""
        } >> "$LOG_CRONTAB"
    else
        echo "  日志异常项: $LOG_SUSPICIOUS_COUNT"
        {
            echo ""
            echo "================================================================================"
            echo "cron执行日志检测总结"
            echo "================================================================================"
            echo "  日志异常项数: $LOG_SUSPICIOUS_COUNT"
            echo ""
        } >> "$LOG_CRONTAB"
    fi
    
    # 输出最终扩展检测总结到日志
    {
        echo "================================================================================"
        echo "扩展检测总结"
        echo "================================================================================"
        echo "1. at/batch异步任务: 总数=$AT_COUNT, 可疑=$AT_SUSPICIOUS_COUNT"
        echo "2. cron脚本软链接: 总数=$SYMLINK_COUNT, 可疑=$SUSPICIOUS_SYMLINK_COUNT"
        echo "3. cron执行日志: 异常=$LOG_SUSPICIOUS_COUNT"
        echo ""
        echo "总可疑发现: $SUSPICIOUS_COUNT"
        echo "================================================================================"
        echo ""
    } >> "$LOG_CRONTAB"
    
    echo ""
    echo "================================================================================"
    
    print_statistics "$TOTAL_CRON_COUNT" "$SUSPICIOUS_COUNT" "定时任务=$SUSPICIOUS_COUNT (at=$AT_SUSPICIOUS_COUNT, 软链接=$SUSPICIOUS_SYMLINK_COUNT, 日志=$LOG_SUSPICIOUS_COUNT)"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_CRONTAB")
    if [ $SUSPICIOUS_COUNT -gt 0 ]; then
        print_result "CRITICAL" "发现 ${SUSPICIOUS_COUNT} 个可疑定时任务 (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 11: 发现 ${SUSPICIOUS_COUNT} 个可疑定时任务"
        echo "Result: Critical" >> "$LOG_CRONTAB"
    else
        print_result "OK" "正常，定时任务检查通过"
        add_detection "INFO" "检测 11: 定时任务正常"
        echo "Result: Normal" >> "$LOG_CRONTAB"
    fi
}

# ============================================================================
# 检测 12: 后台任务和守护进程检测
# ============================================================================
check_background_daemon() {
    print_check_title "12" "后台守护进程与孤儿进程检测" "进程分析" "高危" "守护进程检测"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH ps -eo pid,ppid,sid,pgid,comm,cmd (注: 部分选项可能不兼容)"
    else
        DISPLAY_CMD="ps -eo pid,ppid,sid,pgid,comm,cmd"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "孤儿进程+后台命令(nohup/setsid/disown/daemon/screen/tmux/&/at)+双fork守护+临时目录"
    
    LOG_DAEMON="$LOG_DIR/12_background_daemon_$(date +%Y%m%d_%H%M%S).log"
    
    {
        echo "================================================================"
        echo "检测 12: 后台任务和守护进程检测"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测维度: 1)孤儿进程检测"
        echo "          2)后台命令检测(nohup/setsid/disown/daemon/screen/tmux/&/at/batch/sh -c)"
        echo "          3)双fork守护进程检测"
        echo "          4)临时目录后台任务"
        echo "          5)高熵命名"
        echo ""
    } > "$LOG_DAEMON"
    
    declare -a SUSPICIOUS_DAEMONS
    declare -a ALL_DAEMONS  # 存储所有后台进程（含正常的）
    ORPHAN_COUNT=0
    SESSION_COUNT=0
    DAEMON_COUNT=0
    TMPDIR_DAEMON_COUNT=0
    NORMAL_DAEMON_COUNT=0
    
    for pid in $($CMD_LS /proc/ 2>/dev/null | $CMD_GREP -E '^[0-9]+$' | $CMD_SORT -n); do
        [ ! -f "/proc/$pid/stat" ] && continue
        
        NAME=$($CMD_GREP "^Name:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
        [ -z "$NAME" ] && continue
        
        # 跳过内核线程（真正的内核线程，进程名包含中括号[]）
        [[ "$NAME" =~ ^\[ ]] && continue
        
        # 跳过WSL特殊进程
        if [[ "$NAME" =~ ^(init\(|SessionLeader|Relay\() ]]; then
            continue
        fi
        
        # 跳过脚本自身进程
        if [ $pid -eq $$ ] || [[ "$NAME" =~ ^process_scanner ]]; then
            continue
        fi
        
        CMDLINE=$($CMD_TR '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | $CMD_SED 's/ *$//g')
        [ -z "$CMDLINE" ] && CMDLINE="[$NAME]"
        
        EXE=$($CMD_READLINK "/proc/$pid/exe" 2>/dev/null || echo "N/A")
        PARENT_PID=$($CMD_GREP "^PPid:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
        PROC_UID=$($CMD_GREP "^Uid:" "/proc/$pid/status" 2>/dev/null | $CMD_AWK '{print $2}')
        USER=$(get_username_by_uid "$PROC_UID")
        
        # 从stat中提取会话ID和进程组ID
        STAT_INFO=$($CMD_CAT "/proc/$pid/stat" 2>/dev/null)
        if [ -n "$STAT_INFO" ]; then
            SID=$($CMD_ECHO "$STAT_INFO" | $CMD_AWK '{print $6}')
            PGID=$($CMD_ECHO "$STAT_INFO" | $CMD_AWK '{print $5}')
        else
            SID="N/A"
            PGID="N/A"
        fi
        
        SUSPICIOUS_REASONS=()
        IS_SUSPICIOUS=0
        
        # 检查1: 孤儿进程（PPID=1且路径异常）
        if [ "$PARENT_PID" == "1" ]; then
            # 豁免WSL的/init进程
            if [ "$EXE" != "/init" ]; then
                VALID_SYSTEM_PATHS="^/(usr/)?(s)?bin/|^/lib/systemd/|^/snap/|^/opt/"
                if [[ ! "$EXE" =~ $VALID_SYSTEM_PATHS ]] && [[ "$EXE" != "N/A" ]]; then
                    SUSPICIOUS_REASONS+=("孤儿进程")
                    ((ORPHAN_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
        fi
        
        # 检查2: 后台任务命令检测（恶意后门常用手法）
        BACKGROUND_DETECTED=0
        BACKGROUND_TYPE=""
        
        # 2.1: nohup 命令（最常见的后门持久化手法）
        if [[ "$CMDLINE" =~ nohup[[:space:]] ]] || [[ "$CMDLINE" =~ ^nohup ]]; then
            BACKGROUND_TYPE="nohup后台"
            BACKGROUND_DETECTED=1
        fi
        
        # 2.2: setsid 命令（创建新会话，脱离终端）
        if [[ "$CMDLINE" =~ setsid[[:space:]] ]] || [[ "$CMDLINE" =~ ^setsid ]]; then
            BACKGROUND_TYPE="setsid分离会话"
            BACKGROUND_DETECTED=1
        fi
        
        # 2.3: disown 命令（从job表中移除，隐藏进程）
        if [[ "$CMDLINE" =~ disown ]]; then
            BACKGROUND_TYPE="disown隐藏"
            BACKGROUND_DETECTED=1
        fi
        
        # 2.4: daemon 命令（显式守护进程化）
        if [[ "$CMDLINE" =~ daemon[[:space:]] ]] || [[ "$CMDLINE" =~ ^daemon ]]; then
            BACKGROUND_TYPE="daemon守护化"
            BACKGROUND_DETECTED=1
        fi
        
        # 2.5: screen/tmux 分离会话（持久化后门常用）
        if [[ "$CMDLINE" =~ screen[[:space:]]-[dmS] ]] || [[ "$CMDLINE" =~ tmux[[:space:]]new[[:space:]]-d ]]; then
            BACKGROUND_TYPE="screen/tmux分离"
            BACKGROUND_DETECTED=1
        fi
        
        # 2.6: 后台运行符号 & 配合日志重定向（典型后门模式）
        if [[ "$CMDLINE" =~ [[:space:]]\&[[:space:]]*$ ]] || [[ "$CMDLINE" =~ \&\&[[:space:]]*$ ]]; then
            # 检查是否有日志重定向（后门常隐藏输出）
            if [[ "$CMDLINE" =~ \>\>.*2\>\&1 ]] || [[ "$CMDLINE" =~ 2\>\&1[[:space:]]*\& ]] || [[ "$CMDLINE" =~ \>[[:space:]]*/dev/null ]]; then
                BACKGROUND_TYPE="后台&+日志重定向"
                BACKGROUND_DETECTED=1
            fi
        fi
        
        # 2.7: at/batch 定时任务（另一种持久化方式）
        if [[ "$CMDLINE" =~ ^at[[:space:]] ]] || [[ "$CMDLINE" =~ ^batch[[:space:]] ]]; then
            BACKGROUND_TYPE="at/batch定时"
            BACKGROUND_DETECTED=1
        fi
        
        # 2.8: sh -c / bash -c 执行复杂命令（常用于混淆）
        if [[ "$CMDLINE" =~ (sh|bash)[[:space:]]+-c.*(nohup|setsid|disown|\&) ]]; then
            BACKGROUND_TYPE="shell -c后台"
            BACKGROUND_DETECTED=1
        fi
        
        if [ $BACKGROUND_DETECTED -eq 1 ]; then
            SUSPICIOUS_REASONS+=("$BACKGROUND_TYPE")
            ((SESSION_COUNT++))
            IS_SUSPICIOUS=1
        fi
        
        # 检查3: 双fork守护进程（PPID=1 且 SID!=PID）
        if [ "$PARENT_PID" == "1" ] && [ "$SID" != "$pid" ] && [ "$SID" != "N/A" ]; then
            # 豁免WSL的/init进程
            if [ "$EXE" != "/init" ]; then
                VALID_DAEMON_PATHS="^/(usr/)?(s)?bin/|^/lib/systemd/"
                if [[ ! "$EXE" =~ $VALID_DAEMON_PATHS ]] && [[ "$EXE" != "N/A" ]]; then
                    SUSPICIOUS_REASONS+=("双fork守护")
                    ((DAEMON_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            fi
        fi
        
        # 检查4: 临时目录后台任务
        if [[ "$EXE" =~ ^/tmp/ ]] || [[ "$EXE" =~ ^/dev/shm/ ]] || [[ "$EXE" =~ ^/var/tmp/ ]]; then
            SUSPICIOUS_REASONS+=("临时目录")
            ((TMPDIR_DAEMON_COUNT++))
            IS_SUSPICIOUS=1
        fi
        
        # 检查5: 高熵命名
        if [ "$(check_name_entropy "$NAME")" = "1" ] && [ $IS_SUSPICIOUS -eq 1 ]; then
            SUSPICIOUS_REASONS+=("高熵命名")
        fi
        
        if [ $IS_SUSPICIOUS -eq 1 ]; then
            ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
            SUSPICIOUS_DAEMONS+=("可疑|$pid|$NAME|$PARENT_PID|$USER|$SID|$PGID|$EXE|$CMDLINE|$ALL_REASONS")
            ALL_DAEMONS+=("可疑|$pid|$NAME|$PARENT_PID|$USER|$SID|$PGID|$EXE|$ALL_REASONS")
        else
            # 记录正常进程（仅记录符合后台/守护进程特征的）
            if [ "$PARENT_PID" == "1" ] || [ "$SID" == "$pid" ]; then
                ((NORMAL_DAEMON_COUNT++))
                ALL_DAEMONS+=("正常|$pid|$NAME|$PARENT_PID|$USER|$SID|$PGID|$EXE|正常守护进程")
            fi
        fi
    done
    
    # 首先输出完整的后台进程列表
    {
        echo "================================================================================"
        echo "完整数据列表：所有后台/守护进程（可疑项排在前面）"
        echo "================================================================================"
        printf "| %-8s | %-8s | %-15s | %-8s | %-10s | %-8s | %-8s | %-35s | %-35s |\n" "状态" "PID" "进程名" "PPID" "用户" "SID" "PGID" "可执行文件" "检测原因"
        print_separator "-" 155
    } >> "$LOG_DAEMON"
    
    # 先输出可疑进程
    for daemon_info in "${ALL_DAEMONS[@]}"; do
        IFS='|' read -r status pid name ppid user sid pgid exe reasons <<< "$daemon_info"
        if [ "$status" = "可疑" ]; then
            printf "| %-8s | %-8s | %-15s | %-8s | %-10s | %-8s | %-8s | %-35s | %-35s |\n" "$status" "$pid" "${name:0:15}" "$ppid" "${user:0:10}" "$sid" "$pgid" "${exe:0:35}" "${reasons:0:35}" >> "$LOG_DAEMON"
        fi
    done
    
    # 再输出正常进程
    for daemon_info in "${ALL_DAEMONS[@]}"; do
        IFS='|' read -r status pid name ppid user sid pgid exe reasons <<< "$daemon_info"
        if [ "$status" = "正常" ]; then
            printf "| %-8s | %-8s | %-15s | %-8s | %-10s | %-8s | %-8s | %-35s | %-35s |\n" "$status" "$pid" "${name:0:15}" "$ppid" "${user:0:10}" "$sid" "$pgid" "${exe:0:35}" "${reasons:0:35}" >> "$LOG_DAEMON"
        fi
    done
    
    echo "" >> "$LOG_DAEMON"
    
    # 然后输出可疑任务的详细列表
    {
        echo "================================================================================"
        echo "可疑的后台任务和守护进程（详细）"
        echo "================================================================================"
        printf "| %-8s | %-8s | %-15s | %-8s | %-10s | %-8s | %-8s | %-35s | %-35s |\n" "状态" "PID" "进程名" "PPID" "用户" "SID" "PGID" "可执行文件" "检测原因"
        print_separator "-" 155
    } >> "$LOG_DAEMON"
    
    SUSPICIOUS_DAEMON_COUNT_TMP=${#SUSPICIOUS_DAEMONS[@]}
    if [ $SUSPICIOUS_DAEMON_COUNT_TMP -gt 0 ]; then
        for daemon_info in "${SUSPICIOUS_DAEMONS[@]}"; do
            IFS='|' read -r status pid name ppid user sid pgid exe cmd reasons <<< "$daemon_info"
            printf "| %-8s | %-8s | %-15s | %-8s | %-10s | %-8s | %-8s | %-35s | %-35s |\n" "$status" "$pid" "${name:0:15}" "$ppid" "${user:0:10}" "$sid" "$pgid" "${exe:0:35}" "${reasons:0:35}" >> "$LOG_DAEMON"
        done
    else
        echo "| (未发现可疑后台任务)" >> "$LOG_DAEMON"
    fi
    
    {
        print_separator "=" 155
        echo ""
        echo "统计信息:"
        echo "  孤儿进程数: $ORPHAN_COUNT"
        echo "  分离会话数: $SESSION_COUNT"
        echo "  双fork守护: $DAEMON_COUNT"
        echo "  临时目录后台: $TMPDIR_DAEMON_COUNT"
        echo "  总可疑数: $SUSPICIOUS_DAEMON_COUNT_TMP"
        echo "  正常守护进程: $NORMAL_DAEMON_COUNT"
        echo ""
    } >> "$LOG_DAEMON"
    
    echo ""
    # 使用数组长度统计真实的可疑后台任务数量（避免同一任务多个原因导致重复计数）
    SUSPICIOUS_DAEMON_COUNT=${#SUSPICIOUS_DAEMONS[@]}
    TOTAL_CHECKED=$(( SUSPICIOUS_DAEMON_COUNT + NORMAL_DAEMON_COUNT ))
    
    if [ $SUSPICIOUS_DAEMON_COUNT -gt 0 ]; then
        echo "发现可疑后台任务:"
        echo ""
        printf "%-25s  %-8s  %-8s  %-8s  %-8s  %-12s  %-52s  %-42s\n" "进程名" "PID" "PPID" "SID" "PGID" "用户" "可执行文件" "检测原因"
        print_separator "-" 170
        
        for daemon_info in "${SUSPICIOUS_DAEMONS[@]}"; do
            IFS='|' read -r status pid name ppid user sid pgid exe cmd reasons <<< "$daemon_info"
            printf "%-25s  %-8s  %-8s  %-8s  %-8s  %-12s  %-52s  %-42s\n" "${name:0:25}" "$pid" "$ppid" "$sid" "$pgid" "${user:0:12}" "${exe:0:52}" "${reasons:0:42}"
        done
    else
        echo "未发现可疑后台任务"
    fi
    
    # 计算严重级别的数量（孤儿进程、临时目录为严重）
    CRITICAL_COUNT=0
    for daemon_info in "${SUSPICIOUS_DAEMONS[@]}"; do
        IFS='|' read -r status pid name ppid user sid pgid exe cmd reasons <<< "$daemon_info"
        # 如果包含孤儿或临时目录，则计入严重
        if [[ "$reasons" =~ (孤儿进程|临时目录) ]]; then
            ((CRITICAL_COUNT++))
        fi
    done
    
    print_statistics "$TOTAL_CHECKED" "$SUSPICIOUS_DAEMON_COUNT" "孤儿=$ORPHAN_COUNT, 分离会话=$SESSION_COUNT, 双fork=$DAEMON_COUNT, 临时目录=$TMPDIR_DAEMON_COUNT"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_DAEMON")
    if [ $CRITICAL_COUNT -gt 0 ]; then
        print_result "CRITICAL" "发现 ${SUSPICIOUS_DAEMON_COUNT} 个可疑后台任务 (严重=${CRITICAL_COUNT}) (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 12: 发现 ${SUSPICIOUS_DAEMON_COUNT} 个可疑后台任务"
        echo "Result: Critical" >> "$LOG_DAEMON"
    elif [ $SUSPICIOUS_DAEMON_COUNT -gt 0 ]; then
        print_result "WARN" "发现 ${SUSPICIOUS_DAEMON_COUNT} 个可疑后台任务 (详见日志: ${LOG_BASENAME})"
        add_detection "MEDIUM" "检测 12: 发现 ${SUSPICIOUS_DAEMON_COUNT} 个可疑后台任务"
        echo "Result: Warning" >> "$LOG_DAEMON"
    else
        print_result "OK" "正常，后台任务检查通过"
        add_detection "INFO" "检测 12: 后台任务正常"
        echo "Result: Normal" >> "$LOG_DAEMON"
    fi
}

# ============================================================================
# 检测 13: 内核模块和Rootkit检测
# ============================================================================
check_kernel_modules() {
    print_check_title "13" "内核模块Rootkit检测" "内核检测" "严重" "内核态Rootkit检测"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="lsmod (系统命令) vs $BUSYBOX_PATH cat /proc/modules vs $BUSYBOX_PATH ls /sys/module"
    else
        DISPLAY_CMD="lsmod vs cat /proc/modules vs ls /sys/module"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "隐藏模块检测、已知Rootkit特征、高熵命名模块"
    
    LOG_KMOD="$LOG_DIR/13_kernel_modules_$(date +%Y%m%d_%H%M%S).log"
    
    {
        echo "================================================================"
        echo "检测 13: 内核模块和Rootkit检测"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测维度: 隐藏模块/已知Rootkit/高熵命名/内置模块检测"
        echo ""
    } > "$LOG_KMOD"
    
    declare -a SUSPICIOUS_MODULES
    HIDDEN_COUNT=0
    ROOTKIT_COUNT=0
    ENTROPY_COUNT=0
    TOTAL_SUSPICIOUS=0
    
    # 获取lsmod输出
    LSMOD_OUTPUT=$(lsmod 2>/dev/null | $CMD_TAIL -n +2 | $CMD_AWK '{print $1}' | $CMD_SORT)
    LSMOD_COUNT=$($CMD_ECHO "$LSMOD_OUTPUT" | $CMD_WC -l)
    LSMOD_COUNT=${LSMOD_COUNT//[^0-9]/}
    LSMOD_COUNT=${LSMOD_COUNT:-0}
    
    # 获取/proc/modules输出
    PROC_MODULES=$($CMD_CAT /proc/modules 2>/dev/null | $CMD_AWK '{print $1}' | $CMD_SORT)
    PROC_COUNT=$($CMD_ECHO "$PROC_MODULES" | $CMD_WC -l)
    PROC_COUNT=${PROC_COUNT//[^0-9]/}
    PROC_COUNT=${PROC_COUNT:-0}
    
    {
        echo "模块统计:"
        echo "  lsmod模块数: $LSMOD_COUNT"
        echo "  /proc/modules模块数: $PROC_COUNT"
        echo ""
    } >> "$LOG_KMOD"
    
    # 输出完整的模块列表（供人工分析对比）
    {
        echo "================================================================================"
        echo "第1部分：lsmod输出的完整模块列表（共 $LSMOD_COUNT 个）"
        echo "================================================================================"
        echo "$LSMOD_OUTPUT" | nl
        echo ""
    } >> "$LOG_KMOD"
    
    {
        echo "================================================================================"
        echo "第2部分：/proc/modules完整模块列表（共 $PROC_COUNT 个）"
        echo "================================================================================"
        echo "$PROC_MODULES" | nl
        echo ""
    } >> "$LOG_KMOD"
    
    # 检查1: 隐藏模块（在/proc/modules但不在lsmod）
    while read -r module; do
        [ -z "$module" ] && continue
        if ! echo "$LSMOD_OUTPUT" | grep -qx "$module"; then
            SUSPICIOUS_MODULES+=("隐藏|$module|仅在/proc/modules|隐藏模块")
            ((HIDDEN_COUNT++))
            ((TOTAL_SUSPICIOUS++))
        fi
    done <<< "$PROC_MODULES"
    
    # 检查2: 已知Rootkit模块名
    KNOWN_ROOTKITS="diamorphine|reptile|suterusu|bdvl|azazel|vlany|kovid|rootkit|backdoor|trojan|maK_it|enyelkm|synaptic|override|fuckit"
    
    while read -r module; do
        [ -z "$module" ] && continue
        
        SUSPICIOUS_REASONS=()
        IS_SUSPICIOUS=0
        
        # === 优先级检测策略 ===
        
        # 优先级1: 检查已知Rootkit名称（最高优先级）
        if echo "$module" | grep -qiE "$KNOWN_ROOTKITS"; then
            SUSPICIOUS_REASONS+=("已知Rootkit")
            ((ROOTKIT_COUNT++))
            IS_SUSPICIOUS=1
        fi
        
        # 优先级2: 检查隐藏命名特征
        if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
            if [[ "$module" =~ ^_|^\. ]]; then
                SUSPICIOUS_REASONS+=("隐藏命名")
                ((ENTROPY_COUNT++))
                IS_SUSPICIOUS=1
            fi
        fi
        
        # 优先级3: 内核模块白名单检查 + 验证（Trust but Verify）
        if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
            # 合法内核模块白名单（常见的Linux内核模块）
            local KERNEL_MODULE_WHITELIST="^(br_netfilter|bridge|ip_tables|ip6_tables|iptable_filter|iptable_nat|iptable_mangle|iptable_raw"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|nf_conntrack|nf_nat|nf_defrag_ipv4|nf_defrag_ipv6|nf_tables|nft_"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|xt_|ipt_|ip6t_|ip6t_|ebtable_|arptable_"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|overlay|aufs|zfs|btrfs|ext4|xfs|vfat|ntfs"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|tcp_|udp_|ipv6|ip_vs|nf_log"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|dm_|md_|raid|scsi_|ata_|usb_|hid_"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|cfg80211|mac80211|iwl|ath|rt2800"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|vbox|vmware|kvm|virt|xen"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|nvidia|nouveau|amdgpu|radeon|i915"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|snd_|ac97|hda_|pcspkr"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|evdev|joydev|mousedev|input_"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|psmouse|serio|atkbd"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|thermal|acpi_|button|video"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|bluetooth|btusb|rfkill"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|veth|vxlan|tun|tap|macvlan|ipvlan"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|crc|sha|aes|crypto|des|md5"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}|loop|fuse|squashfs|cgroup|apparmor"
            KERNEL_MODULE_WHITELIST="${KERNEL_MODULE_WHITELIST}).*$"
            
            # 检查是否在白名单中
            if [[ "$module" =~ $KERNEL_MODULE_WHITELIST ]]; then
                # === Trust but Verify: 对白名单模块进行验证 ===
                local whitelist_error=""
                whitelist_error=$(verify_kernel_module_whitelist "$module" 2>&1)
                if [ $? -ne 0 ]; then
                    # 白名单模块验证失败
                    SUSPICIOUS_REASONS+=("白名单伪造:$whitelist_error")
                    ((ENTROPY_COUNT++))
                    IS_SUSPICIOUS=1
                fi
            else
                # 不在白名单中，进行高熵检测
                # 内核模块的高熵检测（与用户态不同）
                # 只检测明显的随机字符串（长度>10，包含数字字母混合，无下划线）
                local mod_len=${#module}
                if [ $mod_len -gt 10 ] && [[ ! "$module" =~ _ ]]; then
                    # 无下划线的长模块名才可疑
                    if [[ "$module" =~ [0-9] ]] && [[ "$module" =~ [a-zA-Z] ]]; then
                        # 包含数字和字母混合
                        local has_numbers=$(count_chars "$module" "[0-9]")
                        local num_ratio=$($CMD_AWK "BEGIN {printf \"%.2f\", $has_numbers/$mod_len}" 2>/dev/null || echo "0")
                        
                        # 数字占比在20%-80%之间（不是纯数字也不是纯字母）
                        if $CMD_AWK "BEGIN {exit !($num_ratio > 0.2 && $num_ratio < 0.8)}" 2>/dev/null; then
                            SUSPICIOUS_REASONS+=("高熵命名")
                            ((ENTROPY_COUNT++))
                            IS_SUSPICIOUS=1
                        fi
                    fi
                fi
            fi
        fi
        
        # 检查随机字符混合（仅作为补充检测，不单独标记）
        if [ $IS_SUSPICIOUS -eq 1 ]; then
            MODULE_LEN=${#module}
            if [ $MODULE_LEN -gt 8 ]; then
                HAS_NUMBERS=$(count_chars "$module" "[0-9]")
                HAS_LETTERS=$(count_chars "$module" "[a-zA-Z]")
                
                if [ $HAS_NUMBERS -gt 2 ] && [ $HAS_LETTERS -gt 2 ]; then
                    NUM_RATIO=$($CMD_AWK "BEGIN {printf \"%.2f\", $HAS_NUMBERS/$MODULE_LEN}")
                    if $CMD_AWK "BEGIN {exit !($NUM_RATIO > 0.2 && $NUM_RATIO < 0.8)}"; then
                        if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                            SUSPICIOUS_REASONS+=("随机混合")
                            IS_SUSPICIOUS=1
                        fi
                    fi
                fi
            fi
        fi
        
        if [ $IS_SUSPICIOUS -eq 1 ]; then
            ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
            # 避免重复计数
            if ! printf '%s\n' "${SUSPICIOUS_MODULES[@]}" | grep -q "^隐藏|$module|"; then
                SUSPICIOUS_MODULES+=("可疑|$module|lsmod可见|$ALL_REASONS")
                ((TOTAL_SUSPICIOUS++))
            fi
        fi
    done <<< "$LSMOD_OUTPUT"
    
    # 检查3: /sys/module目录（更底层检测）
    if [ -d /sys/module/ ]; then
        SYS_MODULES=$(ls /sys/module/ 2>/dev/null | sort)
        for sys_mod in $SYS_MODULES; do
            # 跳过明显的内核参数
            [[ "$sys_mod" =~ ^(kernel|apparmor|loop|fuse|cgroup|cpufreq) ]] && continue
            
            if ! echo "$LSMOD_OUTPUT" | grep -qx "$sys_mod"; then
                # 检查是否有holders目录（表示不是内置模块）
                if [ -d "/sys/module/$sys_mod/holders" ]; then
                    HOLDER_COUNT=$(ls "/sys/module/$sys_mod/holders" 2>/dev/null | wc -l)
                    if [ $HOLDER_COUNT -gt 0 ]; then
                        SUSPICIOUS_MODULES+=("sys隐藏|$sys_mod|/sys/module可见|lsmod不可见")
                        ((HIDDEN_COUNT++))
                        ((TOTAL_SUSPICIOUS++))
                    fi
                fi
            fi
        done
    fi
    
    {
        echo "================================================================================"
        echo "第3部分：对比结果和可疑模块检测"
        echo "================================================================================"
        printf "| %-15s | %-30s | %-30s | %-40s |\n" "类型" "模块名" "可见性" "检测原因"
        print_separator "-" 125
    } >> "$LOG_KMOD"
    
    if [ $TOTAL_SUSPICIOUS -gt 0 ]; then
        for mod_info in "${SUSPICIOUS_MODULES[@]}"; do
            IFS='|' read -r type name visibility reason <<< "$mod_info"
            printf "| %-15s | %-30s | %-30s | %-40s |\n" "$type" "${name:0:30}" "${visibility:0:30}" "${reason:0:40}" >> "$LOG_KMOD"
        done
    else
        echo "| (未发现可疑内核模块)" >> "$LOG_KMOD"
    fi
    
    {
        print_separator "=" 125
        echo ""
        echo "统计信息:"
        echo "  总模块数: $LSMOD_COUNT"
        echo "  隐藏模块: $HIDDEN_COUNT"
        echo "  已知Rootkit: $ROOTKIT_COUNT"
        echo "  高熵命名: $ENTROPY_COUNT"
        echo "  总可疑数: $TOTAL_SUSPICIOUS"
        echo ""
    } >> "$LOG_KMOD"
    
    echo ""
    if [ $TOTAL_SUSPICIOUS -gt 0 ]; then
        echo "发现可疑内核模块:"
        echo ""
        printf "%-18s  %-40s  %-40s  %-48s\n" "类型" "模块名" "可见性" "检测原因"
        print_separator "-" 155
        
        for mod_info in "${SUSPICIOUS_MODULES[@]}"; do
            IFS='|' read -r type name visibility reason <<< "$mod_info"
            printf "%-18s  %-40s  %-40s  %-48s\n" "$type" "${name:0:40}" "${visibility:0:40}" "${reason:0:48}"
        done
    else
        echo "未发现可疑内核模块"
    fi
    
    print_statistics "$LSMOD_COUNT" "$TOTAL_SUSPICIOUS" "隐藏=$HIDDEN_COUNT, Rootkit=$ROOTKIT_COUNT, 高熵=$ENTROPY_COUNT"
    
    LOG_BASENAME=$($CMD_BASENAME "$LOG_KMOD")
    if [ $TOTAL_SUSPICIOUS -gt 0 ]; then
        print_result "CRITICAL" "发现 ${TOTAL_SUSPICIOUS} 个可疑内核模块 (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 13: 发现 ${TOTAL_SUSPICIOUS} 个可疑模块"
        echo "Result: Critical" >> "$LOG_KMOD"
    else
        print_result "OK" "正常，内核模块检查通过"
        add_detection "INFO" "检测 13: 内核模块正常"
        echo "Result: Normal" >> "$LOG_KMOD"
    fi
}

# ============================================================================
# 检测 14: 启动项和持久化机制检测
# ============================================================================
check_startup_persistence() {
    print_check_title "14" "系统启动项持久化检测" "持久化" "高危" "启动项分析"
    
    # 根据是否使用 Busybox 显示实际命令
    if [ $USE_BUSYBOX -eq 1 ]; then
        DISPLAY_CMD="$BUSYBOX_PATH cat /etc/rc.local && $BUSYBOX_PATH ls /etc/init.d/ && profile检查"
    else
        DISPLAY_CMD="cat /etc/rc.local && ls /etc/init.d/ && profile检查"
    fi
    
    print_check_info "检测命令" "$DISPLAY_CMD"
    print_check_info "检测策略" "rc.local后门、init.d脚本、环境变量劫持、profile脚本后门"
    
    LOG_STARTUP="$LOG_DIR/14_startup_persistence_$(date +%Y%m%d_%H%M%S).log"
    
    {
        echo "================================================================"
        echo "检测 14: 启动项和持久化机制检测"
        echo "================================================================"
        echo "检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "检测维度: rc.local/init.d/profile/bashrc/定时任务/环境变量"
        echo ""
    } > "$LOG_STARTUP"
    
    declare -a SUSPICIOUS_STARTUP
    declare -a ALL_STARTUP
    RCLOCAL_COUNT=0
    INITD_COUNT=0
    PROFILE_COUNT=0
    ENV_COUNT=0
    TOTAL_STARTUP_COUNT=0
    TOTAL_CHECKED_FILES=0
    
    RC_LOCAL_FILES="/etc/rc.local /etc/rc.d/rc.local"
    
    # 首先列出所有待检查的启动项文件
    {
        echo "================================================================================"
        echo "完整数据列表：所有检测到的启动项文件"
        echo "================================================================================"
        echo ""
        echo "[rc.local 文件]"
    } >> "$LOG_STARTUP"
    
    for rc_file in $RC_LOCAL_FILES; do
        if [ -f "$rc_file" ]; then
            FILE_PERM=$($CMD_STAT -c %a "$rc_file" 2>/dev/null)
            FILE_MTIME_STR=$($CMD_STAT -c %y "$rc_file" 2>/dev/null | $CMD_CUT -d'.' -f1)
            echo "  - $rc_file (权限:$FILE_PERM, 修改:$FILE_MTIME_STR)" >> "$LOG_STARTUP"
        fi
    done
    
    {
        echo ""
        echo "[init.d 脚本列表]"
    } >> "$LOG_STARTUP"
    
    if [ -d "/etc/init.d" ]; then
        ls -lh /etc/init.d/ 2>/dev/null | tail -n +2 | head -n 20 >> "$LOG_STARTUP"
        INITD_TOTAL=$(ls /etc/init.d/ 2>/dev/null | wc -l)
        echo "  (共 $INITD_TOTAL 个init.d脚本)" >> "$LOG_STARTUP"
    fi
    
    {
        echo ""
        echo "[profile 文件列表]"
    } >> "$LOG_STARTUP"
    
    for prof_file in /etc/profile /etc/bash.bashrc /etc/bashrc; do
        if [ -f "$prof_file" ]; then
            FILE_MTIME_STR=$($CMD_STAT -c %y "$prof_file" 2>/dev/null | $CMD_CUT -d'.' -f1)
            echo "  - $prof_file (修改:$FILE_MTIME_STR)" >> "$LOG_STARTUP"
        fi
    done
    
    {
        echo ""
        echo "================================================================================"
        echo ""
    } >> "$LOG_STARTUP"
    
    # 检查1: /etc/rc.local
    {
        echo "--------------------------------------------------------------------------------"
        echo "检查 /etc/rc.local (详细)"
        echo "--------------------------------------------------------------------------------"
    } >> "$LOG_STARTUP"
    
    for rc_file in $RC_LOCAL_FILES; do
        if [ -f "$rc_file" ]; then
            FILE_PERM=$($CMD_STAT -c %a "$rc_file" 2>/dev/null)
            FILE_MTIME=$($CMD_STAT -c %Y "$rc_file" 2>/dev/null || echo 0)
            FILE_MTIME_STR=$($CMD_STAT -c %y "$rc_file" 2>/dev/null | $CMD_CUT -d'.' -f1)
            
            echo "文件: $rc_file (权限: $FILE_PERM, 修改时间: $FILE_MTIME_STR)" >> "$LOG_STARTUP"
            
            if [ -x "$rc_file" ]; then
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    [[ "$line" =~ ^[[:space:]]*# ]] && continue
                    [[ "$line" =~ ^[[:space:]]*exit ]] && continue
                    
                    SUSPICIOUS_REASONS=()
                    
                    # 反弹shell
                    if $CMD_ECHO "$line" | $CMD_GREP -qE '(bash -i|nc -e|/dev/tcp/)'; then
                        SUSPICIOUS_REASONS+=("反弹shell")
                    fi
                    
                    # 下载执行
                    if $CMD_ECHO "$line" | $CMD_GREP -qE '(wget|curl).*\|.*(bash|sh|python)'; then
                        SUSPICIOUS_REASONS+=("下载执行")
                    fi
                    
                    # 临时目录
                    if $CMD_ECHO "$line" | $CMD_GREP -qE '/tmp/|/dev/shm/|/var/tmp/'; then
                        SUSPICIOUS_REASONS+=("临时目录")
                    fi
                    
                    # base64编码
                    if $CMD_ECHO "$line" | $CMD_GREP -qE 'base64.*-d'; then
                        SUSPICIOUS_REASONS+=("base64")
                    fi
                    
                    if [ ${#SUSPICIOUS_REASONS[@]} -gt 0 ]; then
                        ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
                        FILE_MTIME_STR=$($CMD_STAT -c %y "$rc_file" 2>/dev/null | $CMD_CUT -d'.' -f1 || echo "unknown")
                        echo "  [可疑] $line" >> "$LOG_STARTUP"
                        echo "  原因: $ALL_REASONS" >> "$LOG_STARTUP"
                        SUSPICIOUS_STARTUP+=("rc.local|$rc_file|$FILE_MTIME_STR|${line:0:50}|$ALL_REASONS")
                        ((RCLOCAL_COUNT++))
                        ((TOTAL_STARTUP_COUNT++))
                    fi
                done < "$rc_file"
                
                if [ $RCLOCAL_COUNT -eq 0 ]; then
                    echo "  未发现可疑内容" >> "$LOG_STARTUP"
                fi
            else
                echo "  文件不可执行（正常）" >> "$LOG_STARTUP"
            fi
        fi
    done
    echo "" >> "$LOG_STARTUP"
    
    # 检查2: /etc/init.d/ 脚本
    {
        echo "--------------------------------------------------------------------------------"
        echo "检查 /etc/init.d/ 启动脚本"
        echo "--------------------------------------------------------------------------------"
    } >> "$LOG_STARTUP"
    
    INIT_D_DIR="/etc/init.d"
    if [ -d "$INIT_D_DIR" ]; then
        for init_script in "$INIT_D_DIR"/*; do
            [ ! -f "$init_script" ] && continue
            
            SCRIPT_NAME=$($CMD_BASENAME "$init_script")
            FILE_MTIME=$($CMD_STAT -c %Y "$init_script" 2>/dev/null || echo 0)
            FILE_MTIME_STR=$($CMD_STAT -c %y "$init_script" 2>/dev/null | $CMD_CUT -d'.' -f1)
            
            SUSPICIOUS_REASONS=()
            
            # === 优先级检测策略 ===
            
            # 优先级1: 可疑内容（最高优先级）
            if $CMD_GREP -qE '(bash -i|nc -e|/dev/tcp/|wget.*\||curl.*\|)' "$init_script" 2>/dev/null; then
                SUSPICIOUS_REASONS+=("可疑命令")
            fi
            
            # 优先级2: 可疑关键词
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                local keywords=("hidden" "stealth" "suspicious" "malicious" "backdoor" "rootkit")
                local matched_keywords=()
                for keyword in "${keywords[@]}"; do
                    if [[ "$SCRIPT_NAME" =~ $keyword ]]; then
                        matched_keywords+=("$keyword")
                    fi
                done
                if [ ${#matched_keywords[@]} -gt 0 ]; then
                    local all_keywords=$(IFS=','; echo "${matched_keywords[*]}")
                    SUSPICIOUS_REASONS+=("可疑关键词($all_keywords)")
                fi
            fi
            
            # 优先级3: 最近修改
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if [ "$FILE_MTIME" -gt "$BASELINE_TIMESTAMP" ] 2>/dev/null; then
                    SUSPICIOUS_REASONS+=("最近修改:$FILE_MTIME_STR")
                fi
            fi
            
            # 优先级4: 高熵命名（最低优先级）
            if [ ${#SUSPICIOUS_REASONS[@]} -eq 0 ]; then
                if [ "$(check_name_entropy "$SCRIPT_NAME")" = "1" ]; then
                    SUSPICIOUS_REASONS+=("高熵命名")
                fi
            fi
            
            if [ ${#SUSPICIOUS_REASONS[@]} -gt 0 ]; then
                ALL_REASONS=$(IFS=','; echo "${SUSPICIOUS_REASONS[*]}")
                # 提取可疑内容的关键部分作为特征
                CONTENT_FEATURE="脚本:$SCRIPT_NAME"
                if $CMD_GREP -qE '(bash -i|nc -e|/dev/tcp/)' "$init_script" 2>/dev/null; then
                    SUSPICIOUS_CMD=$($CMD_GREP -E '(bash -i|nc -e|/dev/tcp/)' "$init_script" 2>/dev/null | $CMD_HEAD -1 | $CMD_SED 's/^[[:space:]]*//' | $CMD_CUT -c1-40)
                    CONTENT_FEATURE="$SUSPICIOUS_CMD..."
                fi
                echo "  [可疑] $init_script" >> "$LOG_STARTUP"
                echo "  原因: $ALL_REASONS" >> "$LOG_STARTUP"
                SUSPICIOUS_STARTUP+=("init.d|$init_script|$FILE_MTIME_STR|$CONTENT_FEATURE|$ALL_REASONS")
                ((INITD_COUNT++))
                ((TOTAL_STARTUP_COUNT++))
            fi
        done
        
        if [ $INITD_COUNT -eq 0 ]; then
            echo "  未发现可疑init.d脚本" >> "$LOG_STARTUP"
        fi
    else
        echo "  /etc/init.d 目录不存在" >> "$LOG_STARTUP"
    fi
    echo "" >> "$LOG_STARTUP"
    
    # 检查3: Profile和Bashrc
    {
        echo "--------------------------------------------------------------------------------"
        echo "检查 Profile和Bashrc文件"
        echo "--------------------------------------------------------------------------------"
    } >> "$LOG_STARTUP"
    
    PROFILE_FILES="/etc/profile /etc/bash.bashrc /etc/bashrc"
    for prof_file in $PROFILE_FILES; do
        if [ -f "$prof_file" ]; then
            ((TOTAL_CHECKED_FILES++))
            FILE_MTIME=$($CMD_STAT -c %Y "$prof_file" 2>/dev/null || echo 0)
            FILE_MTIME_STR=$($CMD_STAT -c %y "$prof_file" 2>/dev/null | $CMD_CUT -d'.' -f1)
            
            echo "检查: $prof_file (修改: $FILE_MTIME_STR)" >> "$LOG_STARTUP"
            
            IS_SUSPICIOUS=0
            STATUS="正常"
            REASON="-"
            
            # 检查最近修改
            if [ "$FILE_MTIME" -gt "$BASELINE_TIMESTAMP" ] 2>/dev/null; then
                # 尝试提取可疑内容
                CONTENT_FEATURE="文件最近被修改"
                
                # 检查是否包含可疑命令
                if $CMD_GREP -qE '(bash -i|nc -e|/dev/tcp/|wget.*\||curl.*\||base64.*-d|LD_PRELOAD|LD_LIBRARY_PATH|/tmp/|/dev/shm/)' "$prof_file" 2>/dev/null; then
                    SUSPICIOUS_LINE=$($CMD_GREP -E '(bash -i|nc -e|/dev/tcp/|wget.*\||curl.*\||base64.*-d|LD_PRELOAD|LD_LIBRARY_PATH|/tmp/|/dev/shm/)' "$prof_file" 2>/dev/null | $CMD_HEAD -1 | $CMD_SED 's/^[[:space:]]*//' | $CMD_CUT -c1-40)
                    if [ -n "$SUSPICIOUS_LINE" ]; then
                        CONTENT_FEATURE="${SUSPICIOUS_LINE}..."
                    fi
                else
                    # 没有明显可疑内容，显示最后几行非注释内容
                    RECENT_LINES=$($CMD_GREP -v '^[[:space:]]*#' "$prof_file" 2>/dev/null | $CMD_GREP -v '^[[:space:]]*$' | $CMD_TAIL -3 | $CMD_HEAD -1 | $CMD_SED 's/^[[:space:]]*//' | $CMD_CUT -c1-35)
                    if [ -n "$RECENT_LINES" ]; then
                        CONTENT_FEATURE="${RECENT_LINES}..."
                    fi
                fi
                
                echo "  [警告] 最近被修改" >> "$LOG_STARTUP"
                echo "  内容预览: $CONTENT_FEATURE" >> "$LOG_STARTUP"
                STATUS="可疑"
                REASON="最近修改"
                SUSPICIOUS_STARTUP+=("profile|$prof_file|$FILE_MTIME_STR|$CONTENT_FEATURE|$REASON")
                ((PROFILE_COUNT++))
                ((TOTAL_STARTUP_COUNT++))
                IS_SUSPICIOUS=1
            fi
            
            # 检查可疑内容
            if $CMD_GREP -qE '(wget|curl).*\||base64.*-d|/tmp/|/dev/shm/' "$prof_file" 2>/dev/null; then
                SUSPICIOUS_CMD=$($CMD_GREP -E '(wget|curl).*\||base64.*-d|/tmp/|/dev/shm/' "$prof_file" 2>/dev/null | $CMD_HEAD -1 | $CMD_SED 's/^[[:space:]]*//' | $CMD_CUT -c1-40)
                echo "  [可疑] 包含可疑命令: $SUSPICIOUS_CMD" >> "$LOG_STARTUP"
                STATUS="可疑"
                REASON="包含下载或临时目录"
                CONTENT_FEATURE="${SUSPICIOUS_CMD}..."
                SUSPICIOUS_STARTUP+=("profile|$prof_file|$FILE_MTIME_STR|$CONTENT_FEATURE|$REASON")
                ((PROFILE_COUNT++))
                ((TOTAL_STARTUP_COUNT++))
                IS_SUSPICIOUS=1
            fi
            
            # 如果是正常文件，记录到ALL_STARTUP
            if [ $IS_SUSPICIOUS -eq 0 ]; then
                # 提取正常内容预览
                NORMAL_CONTENT=$($CMD_GREP -v '^[[:space:]]*#' "$prof_file" 2>/dev/null | $CMD_GREP -v '^[[:space:]]*$' | $CMD_TAIL -1 | $CMD_SED 's/^[[:space:]]*//' | $CMD_CUT -c1-35)
                [ -z "$NORMAL_CONTENT" ] && NORMAL_CONTENT="配置文件"
                ALL_STARTUP+=("profile|$prof_file|$FILE_MTIME_STR|${NORMAL_CONTENT}...|-")
            fi
            # 注意：可疑项不添加到ALL_STARTUP，因为SUSPICIOUS_STARTUP已经包含了
        fi
    done
    
    # 检查用户profile
    for user_home in /home/* /root; do
        [ ! -d "$user_home" ] && continue
        
        for user_rc in "$user_home/.bashrc" "$user_home/.bash_profile" "$user_home/.profile"; do
            if [ -f "$user_rc" ]; then
                ((TOTAL_CHECKED_FILES++))
                FILE_MTIME=$($CMD_STAT -c %Y "$user_rc" 2>/dev/null || echo 0)
                FILE_MTIME_STR=$($CMD_STAT -c %y "$user_rc" 2>/dev/null | $CMD_CUT -d'.' -f1)
                
                IS_SUSPICIOUS=0
                
                if [ "$FILE_MTIME" -gt "$BASELINE_TIMESTAMP" ] 2>/dev/null; then
                    # 尝试提取可疑内容
                    CONTENT_FEATURE="文件最近被修改"
                    
                    # 检查是否包含可疑命令
                    if $CMD_GREP -qE '(bash -i|nc -e|/dev/tcp/|wget.*\||curl.*\||base64.*-d|LD_PRELOAD|LD_LIBRARY_PATH|/tmp/|/dev/shm/)' "$user_rc" 2>/dev/null; then
                        # 提取第一个可疑命令片段
                        SUSPICIOUS_LINE=$($CMD_GREP -E '(bash -i|nc -e|/dev/tcp/|wget.*\||curl.*\||base64.*-d|LD_PRELOAD|LD_LIBRARY_PATH|/tmp/|/dev/shm/)' "$user_rc" 2>/dev/null | $CMD_HEAD -1 | $CMD_SED 's/^[[:space:]]*//' | $CMD_CUT -c1-40)
                        if [ -n "$SUSPICIOUS_LINE" ]; then
                            CONTENT_FEATURE="${SUSPICIOUS_LINE}..."
                        fi
                    else
                        # 没有明显可疑内容，显示最后修改的几行（排除注释）
                        RECENT_LINES=$($CMD_GREP -v '^[[:space:]]*#' "$user_rc" 2>/dev/null | $CMD_GREP -v '^[[:space:]]*$' | $CMD_TAIL -3 | $CMD_HEAD -1 | $CMD_SED 's/^[[:space:]]*//' | $CMD_CUT -c1-35)
                        if [ -n "$RECENT_LINES" ]; then
                            CONTENT_FEATURE="${RECENT_LINES}..."
                        fi
                    fi
                    
                    echo "  [警告] 用户RC文件最近修改: $user_rc ($FILE_MTIME_STR)" >> "$LOG_STARTUP"
                    echo "  内容预览: $CONTENT_FEATURE" >> "$LOG_STARTUP"
                    SUSPICIOUS_STARTUP+=("user_rc|$user_rc|$FILE_MTIME_STR|$CONTENT_FEATURE|最近修改")
                    # 注意：可疑项不添加到ALL_STARTUP，因为SUSPICIOUS_STARTUP已经包含了
                    ((PROFILE_COUNT++))
                    ((TOTAL_STARTUP_COUNT++))
                    IS_SUSPICIOUS=1
                else
                    # 正常文件，记录到ALL_STARTUP
                    NORMAL_CONTENT=$($CMD_GREP -v '^[[:space:]]*#' "$user_rc" 2>/dev/null | $CMD_GREP -v '^[[:space:]]*$' | $CMD_TAIL -1 | $CMD_SED 's/^[[:space:]]*//' | $CMD_CUT -c1-35)
                    [ -z "$NORMAL_CONTENT" ] && NORMAL_CONTENT="用户配置文件"
                    ALL_STARTUP+=("user_rc|$user_rc|$FILE_MTIME_STR|${NORMAL_CONTENT}...|-")
                fi
            fi
        done
    done
    
    if [ $PROFILE_COUNT -eq 0 ]; then
        echo "  未发现可疑profile文件" >> "$LOG_STARTUP"
    fi
    echo "" >> "$LOG_STARTUP"
    
    # 检查4: 环境变量持久化
    {
        echo "--------------------------------------------------------------------------------"
        echo "检查环境变量持久化"
        echo "--------------------------------------------------------------------------------"
    } >> "$LOG_STARTUP"
    
    ENV_FILES="/etc/environment /etc/profile.d/*"
    for env_file in $ENV_FILES; do
        if [ -f "$env_file" ]; then
            if $CMD_GREP -qE 'LD_PRELOAD|LD_LIBRARY_PATH' "$env_file" 2>/dev/null; then
                FILE_MTIME_STR=$($CMD_STAT -c %y "$env_file" 2>/dev/null | $CMD_CUT -d'.' -f1 || echo "unknown")
                LD_VAR=$($CMD_GREP -E 'LD_PRELOAD|LD_LIBRARY_PATH' "$env_file" 2>/dev/null | $CMD_HEAD -1 | $CMD_CUT -c1-40)
                echo "  [警告] $env_file 包含 LD_PRELOAD/LD_LIBRARY_PATH" >> "$LOG_STARTUP"
                SUSPICIOUS_STARTUP+=("env|$env_file|$FILE_MTIME_STR|${LD_VAR}...|环境变量劫持")
                ((ENV_COUNT++))
                ((TOTAL_STARTUP_COUNT++))
            fi
        fi
    done
    
    if [ $ENV_COUNT -eq 0 ]; then
        echo "  未发现可疑环境变量" >> "$LOG_STARTUP"
    fi
    echo "" >> "$LOG_STARTUP"
    
    # 汇总输出 - 首先输出完整数据列表（所有文件）
    {
        echo "--------------------------------------------------------------------------------"
        echo "完整数据列表：所有检测的启动项文件（共 ${#ALL_STARTUP[@]} 个，可疑项排在前面）"
        echo "--------------------------------------------------------------------------------"
        printf "| %-10s | %-15s | %-40s | %-18s | %-28s | %-28s |\n" "状态" "类型" "位置" "修改时间" "内容/特征" "检测原因"
        print_separator "-" 155
    } >> "$LOG_STARTUP"
    
    # 输出所有可疑项（排在前面）
    for startup_info in "${SUSPICIOUS_STARTUP[@]}"; do
        IFS='|' read -r type location mtime content reason <<< "$startup_info"
        printf "| %-10s | %-15s | %-40s | %-18s | %-28s | %-28s |\n" "可疑" "$type" "${location:0:40}" "$mtime" "${content:0:28}" "${reason:0:28}" >> "$LOG_STARTUP"
    done
    
    # 输出所有正常项（ALL_STARTUP现在只包含正常项）
    for startup_info in "${ALL_STARTUP[@]}"; do
        IFS='|' read -r type location mtime content reason <<< "$startup_info"
        printf "| %-10s | %-15s | %-40s | %-18s | %-28s | %-28s |\n" "正常" "$type" "${location:0:40}" "$mtime" "${content:0:28}" "${reason:0:28}" >> "$LOG_STARTUP"
    done
    
    {
        print_separator "=" 155
        echo ""
    } >> "$LOG_STARTUP"
    
    # 可疑项汇总
    {
        echo "--------------------------------------------------------------------------------"
        echo "可疑启动项汇总"
        echo "--------------------------------------------------------------------------------"
    } >> "$LOG_STARTUP"
    
    if [ $TOTAL_STARTUP_COUNT -gt 0 ]; then
        {
            printf "| %-15s | %-40s | %-18s | %-28s | %-28s |\n" "类型" "位置" "修改时间" "内容/特征" "检测原因"
            print_separator "-" 145
        } >> "$LOG_STARTUP"
        for startup_info in "${SUSPICIOUS_STARTUP[@]}"; do
            IFS='|' read -r type location mtime content reason <<< "$startup_info"
            printf "| %-15s | %-40s | %-18s | %-28s | %-28s |\n" "$type" "${location:0:40}" "$mtime" "${content:0:28}" "${reason:0:28}" >> "$LOG_STARTUP"
        done
    else
        echo "| (未发现可疑启动项)" >> "$LOG_STARTUP"
    fi
    
    {
        print_separator "=" 145
        echo ""
        echo "统计信息:"
        echo "  总检测文件数: $TOTAL_CHECKED_FILES"
        echo "  rc.local可疑项: $RCLOCAL_COUNT"
        echo "  init.d可疑脚本: $INITD_COUNT"
        echo "  profile可疑项: $PROFILE_COUNT"
        echo "  环境变量可疑项: $ENV_COUNT"
        echo "  总可疑数: $TOTAL_STARTUP_COUNT"
        echo ""
    } >> "$LOG_STARTUP"
    
    echo ""
    if [ $TOTAL_STARTUP_COUNT -gt 0 ]; then
        echo "发现可疑启动项:"
        echo ""
        printf "%-18s  %-45s  %-20s  %-32s  %-35s\n" "类型" "位置" "修改时间" "内容/特征" "检测原因"
        print_separator "-" 160
        
        for startup_info in "${SUSPICIOUS_STARTUP[@]}"; do
            IFS='|' read -r type location mtime content reason <<< "$startup_info"
            printf "%-18s  %-45s  %-20s  %-32s  %-35s\n" "$type" "${location:0:45}" "$mtime" "${content:0:32}" "${reason:0:35}"
        done
    else
        echo "未发现可疑启动项"
    fi
    
    print_statistics "$TOTAL_CHECKED_FILES" "$TOTAL_STARTUP_COUNT" "rc.local=$RCLOCAL_COUNT, init.d=$INITD_COUNT, profile=$PROFILE_COUNT, env=$ENV_COUNT"
    
    if [ $TOTAL_STARTUP_COUNT -gt 0 ]; then
        LOG_BASENAME=$($CMD_BASENAME "$LOG_STARTUP")
        print_result "CRITICAL" "发现 ${TOTAL_STARTUP_COUNT} 个可疑启动项 (详见日志: ${LOG_BASENAME})"
        add_detection "HIGH" "检测 14: 发现 ${TOTAL_STARTUP_COUNT} 个可疑启动项"
        echo "Result: Critical" >> "$LOG_STARTUP"
    else
        print_result "OK" "正常，启动项检查通过"
        add_detection "INFO" "检测 14: 启动项正常"
        echo "Result: Normal" >> "$LOG_STARTUP"
    fi
}

# ============================================================================
# 执行所有检测
# ============================================================================
check_ps_proc_diff
check_process_workdir
check_file_mtime
check_ld_preload
check_process_disguise
check_network
check_tmpdir
check_reverse_shell
check_systemd
check_binary
check_crontab
check_background_daemon
check_kernel_modules
check_startup_persistence

# ============================================================================
# 威胁关联分析
# ============================================================================
perform_threat_correlation

# ============================================================================
# 生成最终报告
# ============================================================================
echo ""
echo "============================================================================"
echo "  最终检测报告"
echo "============================================================================"
echo ""

{
    echo "================================================================"
    echo "                  最终检测报告"
    echo "================================================================"
    echo ""
    echo "扫描完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "主机名: $(hostname)"
    echo "时间范围: ${TIME_DESC} (基准日期: ${BASELINE_DATE_STR})"
    echo ""
} > "$LOG_SUMMARY"

if [ ${#DETECTION_RESULTS[@]} -eq 0 ]; then
    HIGH_COUNT=0
    MEDIUM_COUNT=0
else
    HIGH_COUNT=$(printf '%s\n' "${DETECTION_RESULTS[@]}" | grep -c "^\[HIGH\]" 2>/dev/null)
    MEDIUM_COUNT=$(printf '%s\n' "${DETECTION_RESULTS[@]}" | grep -c "^\[MEDIUM\]" 2>/dev/null)
    # 清理变量，确保是纯数字
    HIGH_COUNT=${HIGH_COUNT//[^0-9]/}
    MEDIUM_COUNT=${MEDIUM_COUNT//[^0-9]/}
    # 如果为空则设为0
    HIGH_COUNT=${HIGH_COUNT:-0}
    MEDIUM_COUNT=${MEDIUM_COUNT:-0}
fi

echo "检测统计:"
echo "  总检测项: ${#DETECTION_RESULTS[@]}"
echo "  高风险发现: ${HIGH_COUNT}"
echo "  中风险发现: ${MEDIUM_COUNT}"
echo ""

{
    echo "检测统计:"
    echo "  总检测项: ${#DETECTION_RESULTS[@]}"
    echo "  高风险发现: $HIGH_COUNT"
    echo "  中风险发现: $MEDIUM_COUNT"
    echo ""
} >> "$LOG_SUMMARY"

if [ "$HIGH_COUNT" -gt 0 ]; then
    echo "[高风险问题]"
    echo "高风险问题列表:" >> "$LOG_SUMMARY"
    for result in "${DETECTION_RESULTS[@]}"; do
        if [[ "$result" =~ ^\[HIGH\] ]]; then
            echo "  * ${result#\[HIGH\] }"
            echo "  ${result#\[HIGH\] }" >> "$LOG_SUMMARY"
        fi
    done
    echo ""
    echo "" >> "$LOG_SUMMARY"
fi

if [ "$MEDIUM_COUNT" -gt 0 ]; then
    echo "[中风险问题]"
    echo "中风险问题列表:" >> "$LOG_SUMMARY"
    for result in "${DETECTION_RESULTS[@]}"; do
        if [[ "$result" =~ ^\[MEDIUM\] ]]; then
            echo "  * ${result#\[MEDIUM\] }"
            echo "  ${result#\[MEDIUM\] }" >> "$LOG_SUMMARY"
        fi
    done
    echo ""
    echo "" >> "$LOG_SUMMARY"
fi

{
    echo "结论:"
    echo "----------------------------------------"
} >> "$LOG_SUMMARY"

if [ "$HIGH_COUNT" -eq 0 ] && [ "$MEDIUM_COUNT" -eq 0 ]; then
    echo "[OK] 结论: 未发现明显的恶意进程或异常"
    echo "系统检查完成，未发现明显的恶意进程或异常" >> "$LOG_SUMMARY"
else
    TOTAL_ISSUES=$((HIGH_COUNT + MEDIUM_COUNT))
    echo "[!!] 结论: 发现 $TOTAL_ISSUES 个需要关注的问题，请检查详细日志"
    echo "警告: 发现 $TOTAL_ISSUES 个需要关注的问题" >> "$LOG_SUMMARY"
fi
echo ""

{
    echo ""
    echo "详细日志文件:"
    echo "----------------------------------------"
    echo "00. 总结报告: $(basename "$LOG_SUMMARY")"
    echo "01. PS 差异检测: $(basename "$LOG_PS_PROC")"
    echo "02. 工作目录检查: $(basename "$LOG_WORKDIR")"
    echo "03. 文件修改时间: $(basename "$LOG_MTIME")"
    echo "04. LD_PRELOAD 劫持: $(basename "$LOG_LDPRELOAD")"
    echo "05. 进程伪装: $(basename "$LOG_DISGUISE")"
    echo "06. 网络连接: $(basename "$LOG_NETWORK")"
    echo "07. 临时目录: $(basename "$LOG_TMPDIR")"
    echo "08. 反向 Shell: $(basename "$LOG_SHELL")"
    echo "09. Systemd 服务: $(basename "$LOG_SYSTEMD")"
    echo "10. 二进制扫描: $(basename "$LOG_BINARY")"
    echo "11. Crontab 任务: $(basename "$LOG_CRONTAB")"
    echo "12. 后台守护进程: $(basename "$LOG_DAEMON")"
    echo "13. 内核模块: $(basename "$LOG_KMOD")"
    echo "14. 启动持久化: $(basename "$LOG_STARTUP")"
    echo "15. 威胁关联分析: $(basename "$LOG_CORRELATION")"
} >> "$LOG_SUMMARY"

# 生成清理建议
{
    echo "================================================================"
    echo "                清理建议和命令"
    echo "================================================================"
    echo ""
    echo "生成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "警告: 这些命令会修改系统，执行前请确认!"
    echo ""
    echo "================================================================"
    echo ""
    echo "[一般安全建议]"
    echo "================================================================"
    echo ""
    echo "1. 系统日志分析:"
    echo "   sudo tail -100 /var/log/auth.log"
    echo "   sudo journalctl -xe --since today"
    echo ""
    echo "2. 检查持久化机制:"
    echo "   crontab -l; sudo crontab -l"
    echo "   ls -la /etc/cron.d/"
    echo "   systemctl list-units --type=service"
    echo ""
    echo "3. 网络连接:"
    echo "   sudo netstat -antp"
    echo "   sudo ss -antp"
    echo ""
    echo "4. 安全加固:"
    echo "   sudo apt update && sudo apt upgrade -y"
    echo "   sudo apt install -y rkhunter chkrootkit"
    echo ""
    echo "注意: 根据实际情况调整所有命令!"
    echo ""
} > "$LOG_SUGGESTIONS"

echo "============================================================================"
echo "  日志目录: ${LOG_DIR}"
echo "============================================================================"
echo ""
echo "  00. 总结报告:    $(basename "$LOG_SUMMARY")"
echo "  01. PS 差异:      $(basename "$LOG_PS_PROC")"
echo "  02. 工作目录:    $(basename "$LOG_WORKDIR")"
echo "  03. 修改时间:    $(basename "$LOG_MTIME")"
echo "  04. LD_PRELOAD:  $(basename "$LOG_LDPRELOAD")"
echo "  05. 进程伪装:    $(basename "$LOG_DISGUISE")"
echo "  06. 网络连接:    $(basename "$LOG_NETWORK")"
echo "  07. 临时目录:    $(basename "$LOG_TMPDIR")"
echo "  08. 反向 Shell:  $(basename "$LOG_SHELL")"
echo "  09. Systemd:     $(basename "$LOG_SYSTEMD")"
echo "  10. 二进制扫描:  $(basename "$LOG_BINARY")"
echo "  11. Crontab任务: $(basename "$LOG_CRONTAB")"
echo "  12. 后台守护:    $(basename "$LOG_DAEMON")"
echo "  13. 内核模块:    $(basename "$LOG_KMOD")"
echo "  14. 启动持久化:  $(basename "$LOG_STARTUP")"
echo "  15. 威胁关联分析: $(basename "$LOG_CORRELATION")"
echo "  16. 清理建议:    $(basename "$LOG_SUGGESTIONS")"
echo ""

echo "============================================================================"
echo "  扫描完成！"
echo "============================================================================"
echo ""

# 清理临时文件（保留目录，只清理内容）
if [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"/* 2>/dev/null || true
fi

exit 0

