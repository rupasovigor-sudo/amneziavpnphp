#!/usr/bin/env bash
# Amnezia VPN Panel installer/updater.
#
# First install:
#   sudo bash install.sh install --domain panel.example.com --admin-email admin@example.com
#
# Update an existing installation:
#   sudo /opt/amnezia-panel/install.sh update

set -Eeuo pipefail

SCRIPT_VERSION="1.2.1"
DEFAULT_REPO="https://github.com/rupasovigor-sudo/amneziavpnphp.git"
DEFAULT_BRANCH="fix/awg2"
DEFAULT_INSTALL_DIR="/opt/amnezia-panel"

ACTION="install"
PANEL_REPO_URL="${PANEL_REPO_URL:-$DEFAULT_REPO}"
PANEL_BRANCH="${PANEL_BRANCH:-$DEFAULT_BRANCH}"
PANEL_INSTALL_DIR="${PANEL_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
PANEL_ADMIN_EMAIL="${PANEL_ADMIN_EMAIL:-}"
PANEL_ADMIN_PASSWORD="${PANEL_ADMIN_PASSWORD:-}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
WITH_FRONT=0
NO_HTTPS=0
EXISTING_PROXY=0
SKIP_BACKUP=0
PASSWORD_GENERATED=0

log() { printf '\033[1;34m[panel]\033[0m %s\n' "$*"; }
ok() { printf '\033[1;32m[panel]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[panel]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[panel] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

on_error() {
    local exit_code=$?
    printf '\033[1;31m[panel] ERROR:\033[0m команда завершилась с кодом %s (строка %s)\n' "$exit_code" "${BASH_LINENO[0]:-?}" >&2
    exit "$exit_code"
}
trap on_error ERR

usage() {
    cat <<'EOF'
Amnezia VPN Panel installer/updater

Usage:
  install.sh install --domain DOMAIN --admin-email EMAIL [options]
  install.sh install --existing-proxy --domain DOMAIN --admin-email EMAIL
  install.sh install --no-https --admin-email EMAIL [options]
  install.sh update [options]
  install.sh auto [options]

Actions:
  install       Install a new panel. Refuses to overwrite an existing install.
  update        Back up and update an existing panel from its current Git branch.
  auto          Install if the target is absent, otherwise update it.

Options:
  --domain DOMAIN          Public panel hostname, for example panel.example.com.
  --admin-email EMAIL      Initial panel administrator email.
  --admin-password PASS    Initial password. If omitted, a random password is saved
                           to /root/.amnezia-panel-initial-credentials.
  --certbot-email EMAIL    Let's Encrypt email; defaults to --admin-email.
  --repo URL               Git repository for a new install.
  --branch BRANCH          Git branch for a new install (default: fix/awg2).
  --install-dir PATH       Installation directory (default: /opt/amnezia-panel).
  --with-front             Prepare the same host to be used as an RU-front.
  --existing-proxy         Keep the existing HAProxy/Caddy/Apache on TCP 80/443.
                           The panel stays on 127.0.0.1:8082; HTTPS is terminated
                           by the existing proxy.
  --no-https               Do not request a certificate. Intended for a temporary
                           local/SSH-tunnel installation.
  --skip-backup            Update without the update.sh database backup.
  -h, --help               Show this help.

Environment variables with the PANEL_ prefix are also supported:
  PANEL_REPO_URL, PANEL_BRANCH, PANEL_INSTALL_DIR, PANEL_DOMAIN,
  PANEL_ADMIN_EMAIL, PANEL_ADMIN_PASSWORD, CERTBOT_EMAIL.
EOF
}

if [[ $# -gt 0 && "$1" != --* ]]; then
    ACTION="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain) PANEL_DOMAIN="${2:-}"; shift 2 ;;
        --admin-email) PANEL_ADMIN_EMAIL="${2:-}"; shift 2 ;;
        --admin-password) PANEL_ADMIN_PASSWORD="${2:-}"; shift 2 ;;
        --certbot-email) CERTBOT_EMAIL="${2:-}"; shift 2 ;;
        --repo) PANEL_REPO_URL="${2:-}"; shift 2 ;;
        --branch) PANEL_BRANCH="${2:-}"; shift 2 ;;
        --install-dir) PANEL_INSTALL_DIR="${2:-}"; shift 2 ;;
        --with-front) WITH_FRONT=1; shift ;;
        --existing-proxy) EXISTING_PROXY=1; shift ;;
        --no-https) NO_HTTPS=1; shift ;;
        --skip-backup) SKIP_BACKUP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "Неизвестный параметр: $1" ;;
    esac
done

[[ "$ACTION" =~ ^(install|update|auto)$ ]] || die "Неизвестное действие: $ACTION"
[[ "$EUID" -eq 0 ]] || die "Запустите скрипт через sudo или от root"
[[ "$PANEL_INSTALL_DIR" =~ ^/[A-Za-z0-9._/-]+$ && "$PANEL_INSTALL_DIR" != "/" ]] \
    || die "--install-dir должен быть безопасным абсолютным путем без пробелов"
[[ "$PANEL_INSTALL_DIR" != *"/../"* && "$PANEL_INSTALL_DIR" != */.. ]] || die "--install-dir не должен содержать .."
[[ "$PANEL_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Недопустимое имя Git-ветки"
[[ "$PANEL_REPO_URL" =~ ^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(\.git)?$ ]] || die "Поддерживается только HTTPS URL репозитория GitHub"
[[ "$EXISTING_PROXY" -eq 0 || "$NO_HTTPS" -eq 0 ]] || die "--existing-proxy и --no-https нельзя использовать одновременно"

if [[ "$ACTION" == "auto" ]]; then
    if [[ -d "$PANEL_INSTALL_DIR/.git" ]]; then ACTION="update"; else ACTION="install"; fi
fi

validate_no_newline() {
    local name="$1" value="$2"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "$name содержит перевод строки"
}

set_env_value() {
    local env_file="$1" key="$2" value="$3" tmp_file
    validate_no_newline "$key" "$value"
    tmp_file="$(mktemp "${env_file}.XXXXXX")"
    grep -v -E "^${key}=" "$env_file" > "$tmp_file" || true
    printf '%s=%s\n' "$key" "$value" >> "$tmp_file"
    chmod 640 "$tmp_file"
    mv "$tmp_file" "$env_file"
}

install_base_packages() {
    log "Устанавливаю системные зависимости"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl gnupg git jq openssl
}

reverse_proxy_preflight() {
    [[ -n "$PANEL_DOMAIN" ]] || return 0
    if [[ "$EXISTING_PROXY" -eq 1 ]]; then
        log "Сохраняю существующий reverse proxy; панель будет слушать только 127.0.0.1:8082"
        return 0
    fi
    command -v ss >/dev/null 2>&1 || die "Команда ss не найдена; установите iproute2 и повторите запуск"

    local port listener
    for port in 80 443; do
        listener="$(ss -H -ltnp "sport = :$port" 2>/dev/null || true)"
        [[ -z "$listener" ]] && continue
        # An already running nginx is reusable: configure_nginx adds a separate
        # server_name and reloads it. Apache/Caddy/docker-proxy must not be
        # stopped automatically because they may serve an existing site.
        if grep -q 'users:(("nginx"' <<<"$listener"; then
            log "TCP $port уже обслуживается nginx — использую существующий reverse proxy"
            continue
        fi
        die "TCP-порт $port уже занят и nginx не сможет запуститься. Освободите порт либо используйте существующий reverse proxy. Процесс: $listener"
    done
}

install_reverse_proxy_packages() {
    [[ -n "$PANEL_DOMAIN" ]] || return 0
    [[ "$EXISTING_PROXY" -eq 0 ]] || return 0
    log "Устанавливаю nginx$([[ "$NO_HTTPS" -eq 0 ]] && echo ' и Certbot' || true)"
    export DEBIAN_FRONTEND=noninteractive
    if [[ "$NO_HTTPS" -eq 0 ]]; then
        apt-get install -y nginx certbot python3-certbot-nginx
    else
        apt-get install -y nginx
    fi
}

install_docker() {
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        ok "Docker и Compose уже установлены"
        systemctl enable --now docker
        return
    fi

    [[ -r /etc/os-release ]] || die "/etc/os-release не найден"
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || die "Автоустановка Docker поддерживает Ubuntu 22.04/24.04"

    log "Устанавливаю Docker Engine из официального репозитория"
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n' \
        "$(dpkg --print-architecture)" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
}

prepare_front_host() {
    log "Подготавливаю Docker forwarding для совмещенного RU-фронта"
    install -m 0755 -d /etc/docker
    local daemon_file="/etc/docker/daemon.json" tmp_file
    tmp_file="$(mktemp /etc/docker/daemon.json.XXXXXX)"
    if [[ -s "$daemon_file" ]]; then
        jq '. + {"ip-forward-no-drop": true}' "$daemon_file" > "$tmp_file" \
            || die "$daemon_file содержит некорректный JSON"
    else
        printf '%s\n' '{"ip-forward-no-drop": true}' > "$tmp_file"
    fi
    chmod 644 "$tmp_file"
    mv "$tmp_file" "$daemon_file"
    dockerd --validate --config-file="$daemon_file"
    systemctl restart docker
    iptables -P FORWARD ACCEPT

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        warn "UFW активен: включаю routed forwarding и UDP 443/444"
        if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
            sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
        else
            printf '%s\n' 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
        fi
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 443/udp
        ufw allow 444/udp
        ufw reload
        iptables -P FORWARD ACCEPT
    fi

    if iptables -S FORWARD 2>/dev/null | grep -q '^-P FORWARD DROP'; then
        die "Политика FORWARD осталась DROP; RU-фронт не сможет пересылать пакеты"
    fi
    ok "Хост подготовлен для RU-фронта (TCP 443 панели не конфликтует с UDP 443/444)"
}

configure_env() {
    local env_file="$PANEL_INSTALL_DIR/.env"
    cp "$PANEL_INSTALL_DIR/.env.example" "$env_file"

    if [[ -z "$PANEL_ADMIN_PASSWORD" ]]; then
        PANEL_ADMIN_PASSWORD="$(openssl rand -hex 18)"
        PASSWORD_GENERATED=1
    fi
    validate_no_newline "ADMIN_PASSWORD" "$PANEL_ADMIN_PASSWORD"

    set_env_value "$env_file" APP_ENV production
    # Keep values shell-compatible too: update.sh sources .env when creating a backup.
    set_env_value "$env_file" APP_NAME '"Amnezia VPN Panel"'
    set_env_value "$env_file" APP_ENCRYPTION_KEY "$(openssl rand -hex 32)"
    set_env_value "$env_file" SESSION_COOKIE_SECURE "$([[ "$NO_HTTPS" -eq 1 ]] && echo 0 || echo 1)"
    set_env_value "$env_file" SESSION_COOKIE_SAMESITE Lax
    set_env_value "$env_file" TRUST_PROXY_HEADERS "$([[ -n "$PANEL_DOMAIN" ]] && echo 1 || echo 0)"
    set_env_value "$env_file" ALLOW_REGISTRATION 0
    set_env_value "$env_file" ENABLE_DEBUG_ROUTES 0
    set_env_value "$env_file" AMNEZIA_CSRF_ENABLED 1
    set_env_value "$env_file" DEFAULT_LOCALE ru
    set_env_value "$env_file" DB_HOST db
    set_env_value "$env_file" DB_PORT 3306
    set_env_value "$env_file" DB_DATABASE amnezia_panel
    set_env_value "$env_file" DB_USERNAME amnezia
    set_env_value "$env_file" DB_PASSWORD "$(openssl rand -hex 24)"
    set_env_value "$env_file" DB_ROOT_PASSWORD "$(openssl rand -hex 24)"
    set_env_value "$env_file" ADMIN_EMAIL "$PANEL_ADMIN_EMAIL"
    set_env_value "$env_file" ADMIN_PASSWORD "$PANEL_ADMIN_PASSWORD"
    set_env_value "$env_file" JWT_SECRET "$(openssl rand -hex 32)"
    chmod 640 "$env_file"
}

wait_for_database() {
    local attempt state
    for attempt in $(seq 1 90); do
        state="$(docker inspect -f '{{.State.Health.Status}}' amnezia-panel-db 2>/dev/null || true)"
        [[ "$state" == "healthy" ]] && return 0
        [[ "$state" == "unhealthy" ]] && break
        sleep 2
    done
    docker compose -f "$PANEL_INSTALL_DIR/docker-compose.yml" --project-directory "$PANEL_INSTALL_DIR" logs --tail=150 db || true
    die "База данных не перешла в состояние healthy"
}

configure_nginx() {
    [[ -n "$PANEL_DOMAIN" ]] || return 0
    [[ "$EXISTING_PROXY" -eq 0 ]] || return 0
    local nginx_file="/etc/nginx/sites-available/amnezia-panel"
    log "Настраиваю nginx для $PANEL_DOMAIN"
    cat > "$nginx_file" <<'NGINX'
server {
    listen 80;
    listen [::]:80;
    server_name __PANEL_DOMAIN__;

    client_max_body_size 25m;

    location / {
        proxy_pass http://127.0.0.1:8082;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 900s;
    }
}
NGINX
    sed -i "s/__PANEL_DOMAIN__/$PANEL_DOMAIN/g" "$nginx_file"
    ln -sfn "$nginx_file" /etc/nginx/sites-enabled/amnezia-panel
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx

    if [[ "$NO_HTTPS" -eq 0 ]]; then
        log "Запрашиваю сертификат Let's Encrypt"
        certbot --nginx --non-interactive --agree-tos --redirect \
            --email "$CERTBOT_EMAIL" -d "$PANEL_DOMAIN"
    fi
}

save_initial_credentials() {
    [[ "$PASSWORD_GENERATED" -eq 1 ]] || return 0
    local credentials_file="/root/.amnezia-panel-initial-credentials"
    umask 077
    {
        if [[ -n "$PANEL_DOMAIN" ]]; then
            printf 'URL=%s://%s\n' "$([[ "$NO_HTTPS" -eq 1 ]] && echo http || echo https)" "$PANEL_DOMAIN"
        else
            printf 'URL=http://127.0.0.1:8082\n'
        fi
        printf 'ADMIN_EMAIL=%s\n' "$PANEL_ADMIN_EMAIL"
        printf 'ADMIN_PASSWORD=%s\n' "$PANEL_ADMIN_PASSWORD"
        printf 'CREATED_AT=%s\n' "$(date -Is)"
    } > "$credentials_file"
    chmod 600 "$credentials_file"
    warn "Случайный пароль администратора сохранен в $credentials_file (root:root, 0600)"
}

check_existing_proxy_publication() {
    [[ "$EXISTING_PROXY" -eq 1 && -n "$PANEL_DOMAIN" ]] || return 0
    local public_url="https://$PANEL_DOMAIN/login" status_code
    status_code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 12 "$public_url" 2>/dev/null || true)"
    case "$status_code" in
        2??|3??) ok "Публичный HTTPS работает: $public_url (HTTP $status_code)" ;;
        *) warn "ПУБЛИКАЦИЯ НЕ ЗАВЕРШЕНА: настройте существующий proxy: $PANEL_DOMAIN → http://127.0.0.1:8082 (проверка HTTPS: ${status_code:-нет ответа})" ;;
    esac
}

install_reaper_cron() {
    cat > /etc/cron.d/amnezia-docker-reaper <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 3 * * 0 root /bin/bash $PANEL_INSTALL_DIR/bin/docker_reaper.sh >> /var/log/amnezia-docker-reaper.log 2>&1
EOF
    chmod 644 /etc/cron.d/amnezia-docker-reaper
}

install_panel() {
    [[ ! -e "$PANEL_INSTALL_DIR" || -z "$(ls -A "$PANEL_INSTALL_DIR" 2>/dev/null)" ]] \
        || die "$PANEL_INSTALL_DIR уже существует и не пуст. Используйте действие update"
    [[ -n "$PANEL_ADMIN_EMAIL" ]] || die "Для новой установки нужен --admin-email"
    [[ "$PANEL_ADMIN_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]] || die "Некорректный email администратора"
    if [[ -n "$PANEL_ADMIN_PASSWORD" ]]; then
        [[ ${#PANEL_ADMIN_PASSWORD} -ge 12 ]] || die "Пароль администратора должен содержать не менее 12 символов"
        [[ "$PANEL_ADMIN_PASSWORD" =~ ^[A-Za-z0-9._%+,.:=@/-]+$ ]] \
            || die "Для --admin-password используйте буквы, цифры и безопасные символы ._%+,:=@/- либо не указывайте пароль для автогенерации"
    fi
    if [[ "$NO_HTTPS" -eq 0 ]]; then
        [[ -n "$PANEL_DOMAIN" ]] || die "Для production нужен --domain; временно без HTTPS используйте --no-https"
        [[ "$PANEL_DOMAIN" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$ ]] || die "Некорректное DNS-имя панели"
    elif [[ -n "$PANEL_DOMAIN" && ! "$PANEL_DOMAIN" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$ ]]; then
        die "Некорректное DNS-имя панели"
    fi
    CERTBOT_EMAIL="${CERTBOT_EMAIL:-$PANEL_ADMIN_EMAIL}"
    if [[ "$EXISTING_PROXY" -eq 1 && -z "$PANEL_DOMAIN" ]]; then
        die "Для --existing-proxy нужен --domain панели"
    fi

    # Check before ANY apt invocation: after a failed nginx postinst, even an
    # unrelated apt-get install retries nginx configuration and fails again.
    reverse_proxy_preflight
    install_base_packages
    install_docker
    # Install the reverse proxy last. Even if its postinst fails because a new
    # listener appeared after preflight, Docker and the base tools are ready and
    # the panel can still be recovered with --no-https.
    install_reverse_proxy_packages
    [[ "$WITH_FRONT" -eq 1 ]] && prepare_front_host

    log "Клонирую $PANEL_REPO_URL, ветка $PANEL_BRANCH"
    mkdir -p "$(dirname "$PANEL_INSTALL_DIR")"
    git clone --branch "$PANEL_BRANCH" --single-branch "$PANEL_REPO_URL" "$PANEL_INSTALL_DIR"
    configure_env
    save_initial_credentials

    cd "$PANEL_INSTALL_DIR"
    log "Собираю и запускаю контейнеры"
    docker compose up -d --build
    wait_for_database
    docker compose exec -T web composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
    curl -fsS --retry 20 --retry-delay 2 http://127.0.0.1:8082/login >/dev/null

    configure_nginx
    install_reaper_cron

    docker compose ps
    ok "Панель установлена"
    if [[ -n "$PANEL_DOMAIN" ]]; then
        log "Адрес: $([[ "$NO_HTTPS" -eq 1 ]] && echo http || echo https)://$PANEL_DOMAIN"
        if [[ "$EXISTING_PROXY" -eq 1 ]]; then
            check_existing_proxy_publication
        fi
    else
        log "Панель доступна локально: http://127.0.0.1:8082"
        log "SSH-туннель: ssh -L 8082:127.0.0.1:8082 <user>@<server>"
    fi
    if [[ "$WITH_FRONT" -eq 1 ]]; then
        log "Следующий шаг: Пулы → RU-фронт → добавить публичный IP этого сервера"
    fi
}

update_panel() {
    [[ -d "$PANEL_INSTALL_DIR/.git" ]] || die "Git-установка не найдена в $PANEL_INSTALL_DIR"
    [[ -f "$PANEL_INSTALL_DIR/update.sh" ]] || die "$PANEL_INSTALL_DIR/update.sh не найден"
    command -v docker >/dev/null 2>&1 || die "Docker не установлен"
    docker compose version >/dev/null 2>&1 || die "Docker Compose v2 не установлен"

    if [[ "$EXISTING_PROXY" -eq 1 ]]; then
        [[ -n "$PANEL_DOMAIN" ]] || die "Для --existing-proxy нужен --domain панели"
        [[ "$PANEL_DOMAIN" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$ ]] || die "Некорректное DNS-имя панели"
        [[ -f "$PANEL_INSTALL_DIR/.env" ]] || die "$PANEL_INSTALL_DIR/.env не найден"
        set_env_value "$PANEL_INSTALL_DIR/.env" SESSION_COOKIE_SECURE 1
        set_env_value "$PANEL_INSTALL_DIR/.env" TRUST_PROXY_HEADERS 1
    fi

    if [[ "$WITH_FRONT" -eq 1 ]]; then
        command -v jq >/dev/null 2>&1 || { apt-get update; apt-get install -y jq; }
        prepare_front_host
    fi

    cd "$PANEL_INSTALL_DIR"
    log "Обновляю панель из $(git config --get remote.origin.url), ветка $(git branch --show-current)"
    local update_args=(--force)
    [[ "$SKIP_BACKUP" -eq 1 ]] && update_args+=(--skip-backup)
    bash ./update.sh "${update_args[@]}"
    docker compose ps
    curl -fsS --retry 10 --retry-delay 2 http://127.0.0.1:8082/login >/dev/null
    [[ -f /etc/systemd/system/amnezia-relay.service ]] && systemctl is-active --quiet amnezia-relay.service \
        && ok "RU-фронт активен" || true
    ok "Панель обновлена"
    if [[ "$EXISTING_PROXY" -eq 1 ]]; then
        check_existing_proxy_publication
    fi
}

log "Amnezia VPN Panel installer v$SCRIPT_VERSION — $ACTION"
case "$ACTION" in
    install) install_panel ;;
    update) update_panel ;;
esac
