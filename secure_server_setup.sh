#!/bin/bash
set -euo pipefail

# ================== НАСТРАИВАЕМЫЕ ПАРАМЕТРЫ ==================
SSH_PORT=""   # Значения по умолчанию нет — запрашивается интерактивно на Шаге 2
# ============================================================

# ---------- Цвета и стили ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TOTAL_STEPS=9
STEP=0

# ---------- Вспомогательные функции вывода ----------

hr() {
    printf "${DIM}%s${NC}\n" "────────────────────────────────────────────────────"
}

box() {
    # Рисует рамку вокруг переданного текста (по одной строке на аргумент)
    local color="$1"; shift
    local max=0
    local line
    for line in "$@"; do
        (( ${#line} > max )) && max=${#line}
    done
    local border
    border=$(printf '─%.0s' $(seq 1 $((max + 2))))
    echo -e "${color}┌${border}┐${NC}"
    for line in "$@"; do
        printf "${color}│ %-*s │${NC}\n" "$max" "$line"
    done
    echo -e "${color}└${border}┘${NC}"
}

step() {
    STEP=$((STEP + 1))
    echo
    hr
    echo -e "${BLUE}${BOLD}[Шаг ${STEP}/${TOTAL_STEPS}]${NC} ${BOLD}$1${NC}"
    hr
}

ok()    { echo -e "  ${GREEN}✔${NC} $1"; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail()  { echo -e "  ${RED}✘${NC} $1"; }
info()  { echo -e "  ${DIM}→${NC} $1"; }

confirm() {
    # confirm "Вопрос" -> возвращает 0 (да) или 1 (нет)
    local prompt="$1"
    local answer
    read -r -p "$(echo -e "${YELLOW}?${NC} ${prompt} [y/N]: ")" answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

ask_ssh_port() {
    # Без интерактивного терминала спросить порт невозможно — явно
    # останавливаемся, а не выбираем что-то за пользователя.
    if [[ ! -t 0 ]]; then
        fail "Нет интерактивного терминала — порт нужно ввести вручную."
        info "Запустите скрипт напрямую в SSH-сессии (не через pipe и не из cron)."
        exit 1
    fi

    local input
    while true; do
        read -r -p "$(echo -e "${YELLOW}?${NC} Введите порт для SSH: ")" input

        if [[ -z "$input" ]]; then
            fail "Порт нельзя оставить пустым. Введите число от 1 до 65535."
            continue
        fi

        if ! [[ "$input" =~ ^[0-9]+$ ]]; then
            fail "Порт должен быть целым числом. Попробуйте ещё раз."
            continue
        fi

        if (( input < 1 || input > 65535 )); then
            fail "Порт должен быть в диапазоне 1-65535. Попробуйте ещё раз."
            continue
        fi

        if (( input == 22 )); then
            warn "Порт 22 — стандартный порт SSH, смена порта теряет смысл как доп. защита от сканеров."
            confirm "Всё равно использовать порт 22?" || continue
        elif (( input < 1024 )); then
            warn "Порт $input — из диапазона привилегированных (<1024); для SSH обычно берут 1024-65535."
            confirm "Всё равно использовать порт $input?" || continue
        fi

        if command -v ss &>/dev/null && ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE ":${input}\$"; then
            warn "Похоже, порт $input уже занят другим процессом на этом сервере."
            confirm "Всё равно использовать порт $input?" || continue
        fi

        SSH_PORT="$input"
        break
    done
}

# ---------- Заголовок ----------
clear 2>/dev/null || true
box "$BOLD$GREEN" "Автоматическая настройка SSH и Fail2ban"
echo

# ---------- Шаг 1: проверка прав ----------
step "Проверка прав доступа"
if [[ $EUID -ne 0 ]]; then
    fail "Скрипт должен запускаться с правами root (используйте sudo)."
    exit 1
fi
ok "Скрипт запущен с правами root."

# ---------- Шаг 2: выбор порта SSH ----------
step "Выбор порта SSH"
ask_ssh_port
ok "Будет использован порт: $SSH_PORT"

# ---------- Шаг 3: проверка SSH-ключей (защита от блокировки доступа) ----------
step "Проверка наличия SSH-ключей"
KEY_FOUND=false
for authfile in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    if [[ -s "$authfile" ]]; then
        KEY_FOUND=true
        ok "Найден файл с ключами: $authfile"
    fi
done

if [[ "$KEY_FOUND" == false ]]; then
    warn "Не найдено ни одного authorized_keys с ключами."
    box "$RED" \
        "ВНИМАНИЕ: пароль будет отключён, а SSH-ключи не найдены!" \
        "Если продолжить сейчас, вы можете потерять доступ к серверу."
    if ! confirm "Всё равно продолжить настройку?"; then
        info "Настройка отменена пользователем. Ничего не изменено."
        exit 1
    fi
else
    ok "SSH-ключи найдены — отключение входа по паролю безопасно."
fi

# ---------- Шаг 4: обновление и установка пакетов ----------
step "Обновление системы и установка пакетов (mc, fail2ban, python3-systemd)"
info "Обновление списка пакетов и системы..."
apt update -qq && DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq
ok "Система обновлена."
# python3-systemd нужен fail2ban для backend = systemd, на минимальных образах его нет.
info "Установка mc, fail2ban и python3-systemd..."
apt install -y -qq mc fail2ban python3-systemd
ok "Пакеты установлены."

# ---------- Шаг 5: резервное копирование конфигов ----------
step "Резервное копирование конфигурации SSH"
SSHD_MAIN="/etc/ssh/sshd_config"
SSHD_DROPIN="/etc/ssh/sshd_config.d/00-secure-setup.conf"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d%H%M%S)"

# Режим применения параметров определяем заранее (по наличию Include
# sshd_config.d в основном конфиге) и бэкапим только то, что изменит шаг 7.
if grep -qE '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$SSHD_MAIN" 2>/dev/null; then
    SSH_USE_DROPIN=true
else
    SSH_USE_DROPIN=false
fi

if [[ "$SSH_USE_DROPIN" == true ]]; then
    if [[ -f "$SSHD_DROPIN" ]]; then
        cp "$SSHD_DROPIN" "${SSHD_DROPIN}${BACKUP_SUFFIX}"
        ok "Резервная копия: $SSHD_DROPIN → $(basename "$SSHD_DROPIN")${BACKUP_SUFFIX}"
    else
        info "Drop-in $SSHD_DROPIN ещё не существует — будет создан на шаге 7."
    fi
else
    if [[ -f "$SSHD_MAIN" ]]; then
        cp "$SSHD_MAIN" "${SSHD_MAIN}${BACKUP_SUFFIX}"
        ok "Резервная копия: $SSHD_MAIN → $(basename "$SSHD_MAIN")${BACKUP_SUFFIX}"
    else
        info "Файл $SSHD_MAIN не найден, пропуск."
    fi
fi

# ---------- Шаг 6: отключение socket-активации SSH ----------
# На Ubuntu 22.10+ (включая 24.04) sshd по умолчанию запускается через
# systemd socket-активацию: слушающий сокет держит юнит ssh.socket,
# а не сам процесс sshd. Из-за этого директива Port в sshd_config
# применяется только после ПОЛНОЙ перезагрузки — "systemctl restart ssh"
# перезапускает лишь обработчик соединений, а не сам сокет, поэтому
# порт молча остаётся старым.
# Официальное решение из README.Debian пакета openssh-server —
# отключить socket-активацию и вернуться к обычному режиму сервиса,
# при котором sshd сам слушает порт и honour'ит sshd_config при restart.
step "Отключение socket-активации SSH (чтобы порт применялся без ребута)"
if systemctl cat ssh.socket &>/dev/null; then
    if systemctl is-active --quiet ssh.socket 2>/dev/null || systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
        info "Обнаружена socket-активация ssh.socket — с ней смена порта требует перезагрузки."
        systemctl disable --now ssh.socket
        systemctl enable --now ssh.service
        ok "ssh.socket отключён, ssh.service переведён в обычный режим (без socket-активации)."
    else
        ok "ssh.socket присутствует, но не используется — менять нечего."
    fi
else
    ok "Юнит ssh.socket в этой системе отсутствует — не актуально."
fi

# ---------- Функции настройки SSH ----------
# Fallback для старых систем без Include: правим параметры прямо в sshd_config.
replace_or_add_in_main() {
    local param=$1 value=$2
    if grep -qE "^#?${param}[[:space:]]+" "$SSHD_MAIN"; then
        sed -i "s/^#\{0,1\}${param}[[:space:]]\+.*/${param} ${value}/" "$SSHD_MAIN"
    else
        echo "${param} ${value}" >> "$SSHD_MAIN"
    fi
}

# ---------- Шаг 7: настройка параметров SSH и фаервола ----------
step "Настройка параметров SSH и фаервола"

if [[ "$SSH_USE_DROPIN" == true ]]; then
    # Include обрабатывается до основных директив sshd_config, и sshd применяет
    # первое вхождение параметра. Файл 00-secure-setup.conf сортируется раньше
    # 50-cloud-init.conf и любых других провайдерских .conf — его значения
    # побеждают, а основной sshd_config остаётся нетронутым.
    cat > "$SSHD_DROPIN" <<EOF
Port $SSH_PORT
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
EOF
    ok "Параметры записаны в drop-in: $SSHD_DROPIN"
else
    info "Include sshd_config.d не найден — правим $SSHD_MAIN напрямую (старая система)."
    replace_or_add_in_main "Port" "$SSH_PORT"
    ok "Port = $SSH_PORT  ${DIM}(в $(basename "$SSHD_MAIN"))${NC}"
    replace_or_add_in_main "PubkeyAuthentication" "yes"
    ok "PubkeyAuthentication = yes  ${DIM}(в $(basename "$SSHD_MAIN"))${NC}"
    replace_or_add_in_main "PasswordAuthentication" "no"
    ok "PasswordAuthentication = no  ${DIM}(в $(basename "$SSHD_MAIN"))${NC}"
    replace_or_add_in_main "PermitEmptyPasswords" "no"
    ok "PermitEmptyPasswords = no  ${DIM}(в $(basename "$SSHD_MAIN"))${NC}"
fi

info "Проверка синтаксиса конфигурации (sshd -t)..."
if sshd -t; then
    ok "Конфигурация SSH корректна."
else
    fail "Ошибка в конфигурации SSH! Перезапуск отменён, чтобы не потерять доступ."
    exit 1
fi

# Защита от lockout: разрешаем порт в ufw ДО рестарта. Для активного ufw
# правило добавится сразу, для неактивного — сохранится на будущее (идемпотентно).
if command -v ufw &>/dev/null; then
    info "Разрешаем порт $SSH_PORT/tcp в ufw..."
    ufw allow "${SSH_PORT}/tcp"
    ok "Правило ufw добавлено: allow ${SSH_PORT}/tcp."
else
    info "ufw не установлен — локальный фаервол настраивать нечего."
fi

info "Перезапуск службы SSH..."
systemctl restart ssh

# Подтверждаем, что sshd реально слушает новый порт, прежде чем отпустить
# пользователя: если нет — текущая сессия ещё жива, и есть время на диагностику.
if command -v ss &>/dev/null; then
    sleep 1
    if ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE ":${SSH_PORT}\$"; then
        ok "SSH перезапущен и слушает порт $SSH_PORT."
    else
        fail "SSH перезапущен, но порт $SSH_PORT не слушается!"
        info "Диагностика: ss -tlnp | grep sshd"
        exit 1
    fi
else
    warn "Утилита ss не найдена — проверьте порт вручную: ss -tlnp | grep sshd"
fi

# ---------- Шаг 8: настройка Fail2ban ----------
step "Настройка Fail2ban"
JAIL_LOCAL="/etc/fail2ban/jail.local"
if [[ -f "$JAIL_LOCAL" ]]; then
    cp "$JAIL_LOCAL" "${JAIL_LOCAL}${BACKUP_SUFFIX}"
    ok "Резервная копия: $JAIL_LOCAL → $(basename "$JAIL_LOCAL")${BACKUP_SUFFIX}"
fi

# IP текущей SSH-сессии добавляем в ignoreip — защита от самобана во время
# проверки доступа. SSH_CLIENT переживает tmux; fallback — who -m (последнее
# поле, скобки вокруг IPv6 убираем).
IPV4_RE='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
CLIENT_IP="${SSH_CLIENT:-}"
CLIENT_IP="${CLIENT_IP%% *}"
if ! [[ "$CLIENT_IP" =~ $IPV4_RE ]]; then
    CLIENT_IP="$(who -m 2>/dev/null | awk '{print $NF}' | tr -d '()' | tail -n 1)"
fi
# Валидация: строгий IPv4 либо строка с ':' (IPv6 — hostname содержать ':' не может).
if [[ "$CLIENT_IP" =~ $IPV4_RE ]] || [[ "$CLIENT_IP" == *:* ]]; then
    IGNOREIP="127.0.0.1/8 ::1 ${CLIENT_IP}"
    ok "В ignoreip добавлен IP текущей сессии: $CLIENT_IP"
else
    IGNOREIP="127.0.0.1/8 ::1"
    info "Не удалось определить IP текущей сессии — ignoreip останется дефолтным."
fi

cat > "$JAIL_LOCAL" <<EOF
[DEFAULT]
bantime = 30m
findtime = 10m
maxretry = 3
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 24h
backend = systemd
ignoreip = ${IGNOREIP}

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
EOF
ok "Конфигурация Fail2ban создана: $JAIL_LOCAL"

info "Перезапуск и включение Fail2ban..."
systemctl restart fail2ban
systemctl enable fail2ban -q
ok "Fail2ban активен и добавлен в автозагрузку."

# ---------- Шаг 9: проверка статуса ----------
step "Проверка состояния служб"
if systemctl is-active --quiet fail2ban; then
    ok "fail2ban: активен"
else
    fail "fail2ban: не запущен"
fi

if systemctl is-active --quiet ssh; then
    ok "ssh: активен"
else
    fail "ssh: не запущен"
fi

echo
info "Статус jail sshd:"
fail2ban-client status sshd 2>/dev/null | sed 's/^/    /' || warn "Не удалось получить статус jail sshd."

# ---------- Итоговая сводка ----------
echo
box "$BOLD$GREEN" \
    "Настройка завершена успешно!" \
    "" \
    "SSH-порт:            $SSH_PORT" \
    "Вход по паролю:      отключён" \
    "Вход по ключу:       разрешён" \
    "Fail2ban:             активен (jail sshd)" \
    "Резервные копии:     суффикс $BACKUP_SUFFIX"

echo
echo -e "${BOLD}Полезные команды:${NC}"
echo -e "  ${YELLOW}fail2ban-client status sshd${NC}            — список забаненных IP"
echo -e "  ${YELLOW}fail2ban-client set sshd unbanip <IP>${NC}  — разбанить IP"
echo
box "$RED" \
    "ВАЖНО: не закрывайте текущую SSH-сессию!" \
    "Откройте НОВОЕ окно терминала и проверьте вход:" \
    "  ssh -p $SSH_PORT user@server" \
    "Только убедившись, что новое подключение работает," \
    "закрывайте старую сессию." \
    "" \
    "ОБЛАЧНЫЙ ФАЕРВОЛ: если у сервера есть Hetzner Firewall," \
    "AWS Security Group и т.п. — откройте порт $SSH_PORT/tcp там."
