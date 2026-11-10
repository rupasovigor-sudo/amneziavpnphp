# Развертывание Amnezia VPN Panel на новом сервере

Эта инструкция рассчитана на чистую Ubuntu 22.04/24.04 LTS и два варианта:

1. сервер используется только для панели;
2. этот же сервер одновременно является **RU-фронтом** (входным relay) одного из VPN-пулов.

Панель является control-plane: хранит серверы и клиентов, выполняет мониторинг, DNS-failover и бэкапы. Уже установленные VPN-серверы и RU-фронт продолжают обслуживать подключения при временной недоступности панели.

## 1. Что подготовить

- KVM/VDS с Ubuntu 22.04 или 24.04 LTS, не OpenVZ;
- от 2 vCPU, 2 ГБ RAM и 20 ГБ SSD;
- публичный статический IPv4;
- DNS-имя панели, например `panel.example.com`;
- SSH-доступ с `sudo` или под `root`;
- доступ панели по SSH к будущим VPN-серверам;
- для совмещенного сервера — отдельное DNS-имя пула, например `awg.example.com`. Оно может указывать на тот же IPv4, что и панель.

Перед началом создайте A-запись:

```text
panel.example.com -> PUBLIC_IPV4
```

DNS-имя VPN-пула переключайте на фронт только из интерфейса панели после успешной проверки relay.

## Автоматическая установка из GitHub

Рекомендуемый способ для чистого сервера — скачать скрипт, проверить его и запустить:

```bash
curl -fsSL https://raw.githubusercontent.com/rupasovigor-sudo/amneziavpnphp/fix/awg2/install.sh \
  -o /tmp/amnezia-panel-install.sh
less /tmp/amnezia-panel-install.sh
sudo bash /tmp/amnezia-panel-install.sh install \
  --domain panel.example.com \
  --admin-email admin@example.com
```

Скрипт установит Docker, Compose, nginx и Certbot, клонирует GitHub-репозиторий в `/opt/amnezia-panel`, создаст безопасный `.env`, запустит контейнеры и выпустит сертификат. Если пароль не передан через `--admin-password`, он будет сгенерирован и сохранен в `/root/.amnezia-panel-initial-credentials` с правами `0600`. После сохранения пароля в менеджере паролей удалите этот файл.

Если сервер панели одновременно должен быть RU-фронтом:

```bash
sudo bash /tmp/amnezia-panel-install.sh install \
  --domain panel.example.com \
  --admin-email admin@example.com \
  --with-front
```

Для установки конкретной ветки или другого fork используйте `--branch` и `--repo`. Временный запуск без публичного домена возможен с `--no-https`; панель останется на `127.0.0.1:8082` и будет доступна через SSH-туннель.

Обновление существующей установки с бэкапом БД:

```bash
sudo /opt/amnezia-panel/install.sh update
```

Идемпотентный вариант для автоматизации — установить панель, если ее еще нет, либо обновить существующую:

```bash
sudo bash /tmp/amnezia-panel-install.sh auto \
  --domain panel.example.com \
  --admin-email admin@example.com
```

Полный список параметров: `bash install.sh --help`. Ручная установка описана ниже и остается полезной для нестандартной инфраструктуры.

### Если nginx не запускается: порт 80 уже занят

Ошибка `bind() to 0.0.0.0:80 failed (98: Address already in use)` означает, что на хосте уже работает другой HTTP-сервер или Docker-контейнер. Это не конфликт с панелью: контейнер панели публикуется только на `127.0.0.1:8082`.

Узнайте владельца TCP 80 и 443:

```bash
sudo ss -ltnp '( sport = :80 or sport = :443 )'
sudo docker ps --format 'table {{.Names}}\t{{.Ports}}'
```

Если это неиспользуемый Apache:

```bash
sudo systemctl disable --now apache2
sudo dpkg --configure -a
sudo apt-get -f install
```

Если порт занимает нужный HAProxy, Caddy, Apache или Docker-сервис, не удаляйте его. Поскольку предыдущий запуск уже оставил nginx недонастроенным, сначала удалите только неудавшуюся установку nginx и завершите настройку пакетов:

```bash
sudo apt-get remove -y nginx nginx-common
sudo dpkg --configure -a
sudo apt-get -f install
```

Затем установите панель в режиме существующего reverse proxy. Панель останется на `127.0.0.1:8082`, а secure-cookie и proxy-заголовки будут настроены для внешнего HTTPS:

```bash
sudo bash /tmp/amnezia-panel-install.sh auto \
  --existing-proxy \
  --domain panel.example.com \
  --admin-email admin@example.com
```

Добавьте в существующий reverse proxy маршрут `panel.example.com → http://127.0.0.1:8082`. Не копируйте готовый пример HAProxy вслепую: правило зависит от того, завершается ли TLS в HAProxy (`mode http`) или используется TCP/SNI passthrough (`mode tcp`). Для безопасной диагностики покажите только структуру frontend/backend:

```bash
sudo grep -nE '^[[:space:]]*(frontend|listen|backend|bind|mode|acl|use_backend|default_backend|server)[[:space:]]' /etc/haproxy/haproxy.cfg
```

#### HAProxy в `mode tcp`: Element и панель на одном IP

Если HAProxy передает TLS Element-серверу без расшифровки, нельзя направлять внешний TCP 443 прямо на HTTP панели `127.0.0.1:8082`. Используйте SNI-маршрут и второй локальный frontend HAProxy:

```text
443/TCP → HAProxy SNI → 127.0.0.1:8443 (TLS termination) → 127.0.0.1:8082 (панель)
                    ↘ прежний Element backend для остальных доменов
```

Сначала добавьте обработку HTTP и backend панели, заменив `panel.example.com`:

```haproxy
frontend ess_http
    bind *:80
    mode http
    acl panel_host hdr(host) -i panel.example.com
    acl panel_acme path_beg /.well-known/acme-challenge/
    use_backend panel_app if panel_host panel_acme
    http-request redirect scheme https code 301 if panel_host !panel_acme
    default_backend ess_http_origin

backend ess_http_origin
    mode http
    server origin 10.254.88.1:80 check inter 3s fall 3 rise 2

backend panel_app
    mode http
    option httpchk GET /login
    server panel 127.0.0.1:8082 check
```

Проверьте конфиг, перезагрузите HAProxy и выпустите сертификат через webroot панели:

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl reload haproxy
sudo apt-get install -y certbot
sudo certbot certonly --webroot -w /opt/amnezia-panel/public \
  -d panel.example.com -m admin@example.com --agree-tos --non-interactive
sudo install -m 0700 -d /etc/haproxy/certs
sudo sh -c 'cat /etc/letsencrypt/live/panel.example.com/fullchain.pem /etc/letsencrypt/live/panel.example.com/privkey.pem > /etc/haproxy/certs/panel.example.com.pem'
sudo chmod 600 /etc/haproxy/certs/panel.example.com.pem
```

В HTTPS frontend добавьте SNI ACL, сохранив прежний backend Element по умолчанию:

```haproxy
frontend ess_https
    bind *:443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    acl panel_sni req.ssl_sni -i panel.example.com
    use_backend panel_tls_loop if panel_sni
    default_backend ess_https_origin

backend ess_https_origin
    mode tcp
    server origin 10.254.88.1:443 check inter 3s fall 3 rise 2

backend panel_tls_loop
    mode tcp
    server panel_tls 127.0.0.1:8443 check

frontend panel_https_local
    bind 127.0.0.1:8443 ssl crt /etc/haproxy/certs/panel.example.com.pem alpn h2,http/1.1
    mode http
    option forwardfor
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Port 443
    default_backend panel_app
```

Перед reload всегда выполняйте `haproxy -c -f /etc/haproxy/haproxy.cfg`. Для продления сертификата нужен deploy-hook, который заново объединяет `fullchain.pem` и `privkey.pem`, проверяет конфиг и перезагружает HAProxy.

После освобождения порта повторите обычную установку безопасным режимом `auto`:

```bash
sudo bash /tmp/amnezia-panel-install.sh auto \
  --domain panel.example.com \
  --admin-email admin@example.com
```

Новая версия установщика проверяет TCP 80/443 заранее и выводит конфликтующий процесс до запуска `apt`.

## 2. Сетевые порты

### Сервер только с панелью

| Направление | Порт | Назначение |
|---|---:|---|
| входящий TCP | SSH-порт | администрирование |
| входящий TCP | 80 | выпуск/обновление сертификата Let's Encrypt |
| входящий TCP | 443 | HTTPS панели |
| исходящий TCP | SSH-порты серверов | установка, мониторинг и обновление VPN-серверов |
| исходящий TCP/UDP | 53; TCP 80/443 | DNS, пакеты, API, S3 и обновления |

Порт `8082` наружу открывать не нужно: Docker публикует его только на `127.0.0.1`.

### Панель и RU-фронт на одном сервере

Дополнительно разрешите:

| Направление | Порт | Назначение |
|---|---:|---|
| входящий UDP | 443 | AWG 2.0 через RU-фронт |
| входящий UDP | 444 | AWG 3.1 через RU-фронт |
| исходящий UDP | порты членов пула | relay до выходных серверов |

Конфликта нет: nginx использует **TCP 443**, а VPN relay — **UDP 443/444**.

> Не включайте HTTP/3/QUIC на UDP 443. Рекомендуемый ниже nginx слушает только TCP. Если используется Caddy, отключите HTTP/3 (`protocols h1 h2`), иначе он займет UDP 443 и AWG 2.0 не заработает.

Ограничьте SSH по исходным IP в облачном firewall, если это возможно. UDP 443/444 фронта должен быть доступен всем VPN-клиентам.

## 3. Подготовка Ubuntu

Выполните под пользователем с `sudo`:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git nginx certbot python3-certbot-nginx

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker nginx
sudo docker version
sudo docker compose version
```

Для дальнейших команд можно либо оставлять `sudo` перед `docker`, либо добавить администратора в группу Docker и заново войти по SSH:

```bash
sudo usermod -aG docker "$USER"
```

Членство в группе `docker` фактически дает root-доступ к серверу.

## 4. Установка панели

```bash
sudo git clone --branch fix/awg2 --single-branch https://github.com/rupasovigor-sudo/amneziavpnphp.git /opt/amnezia-panel
sudo chown -R "$USER":"$USER" /opt/amnezia-panel
cd /opt/amnezia-panel
cp .env.example .env
```

Сгенерируйте отдельные значения для каждого секрета:

```bash
openssl rand -hex 32
openssl rand -base64 36
openssl rand -base64 36
openssl rand -hex 32
```

Отредактируйте `.env`:

```dotenv
APP_ENV=production
APP_NAME="Amnezia VPN Panel"
APP_ENCRYPTION_KEY=<64 hex-символа из первой команды>

SESSION_COOKIE_SECURE=1
SESSION_COOKIE_SAMESITE=Lax
TRUST_PROXY_HEADERS=1
ALLOW_REGISTRATION=0
ENABLE_DEBUG_ROUTES=0
AMNEZIA_CSRF_ENABLED=1
DEFAULT_LOCALE=ru

DB_HOST=db
DB_PORT=3306
DB_DATABASE=amnezia_panel
DB_USERNAME=amnezia
DB_PASSWORD=<второй случайный секрет>
DB_ROOT_PASSWORD=<третий случайный секрет>

ADMIN_EMAIL=<ваша почта>
ADMIN_PASSWORD=<сильный пароль для первого входа>
JWT_SECRET=<четвертый случайный секрет>
```

Дополнительно рекомендуется зафиксировать проверенную версию AWG 3.1, уже указанную в `.env.example`:

```dotenv
AWG2_PIN_REF=b5928efb6ca19f0153958460c3d141f04abc5c2e
AWG_RELEASE_VERSION=3.1.20260828
```

`APP_ENCRYPTION_KEY` шифрует SSH-реквизиты, ключи клиентов и токены в БД. Сохраните его отдельно в менеджере паролей: одной резервной копии БД без этого ключа недостаточно.

Защитите файл и запустите стек:

```bash
chown root:www-data .env
chmod 660 .env
docker compose up -d --build
docker compose exec -T web composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
docker compose ps
```

На новой пустой БД SQL-файлы из `migrations/` применяются MySQL автоматически. Не запускайте их циклом вручную: для последующих обновлений используется `update.sh`, который ведет таблицу примененных миграций.

Проверьте локальный ответ панели:

```bash
curl -I http://127.0.0.1:8082/login
docker compose logs --tail=100 web db
```

Ожидаемый результат — HTTP-ответ панели и состояние `healthy` у БД. Администратор из `ADMIN_EMAIL`/`ADMIN_PASSWORD` создается при первом HTTP-запросе. Поэтому задайте окончательный сильный пароль до первого открытия панели.

## 5. HTTPS через nginx

Создайте `/etc/nginx/sites-available/amnezia-panel`:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name panel.example.com;

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
```

Включите сайт и выпустите сертификат:

```bash
sudo ln -s /etc/nginx/sites-available/amnezia-panel /etc/nginx/sites-enabled/amnezia-panel
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d panel.example.com --redirect
sudo certbot renew --dry-run
```

Замените `panel.example.com` на реальное имя. После этого войдите по адресу `https://panel.example.com` и смените пароль в **Настройки → Профиль**.

`TRUST_PROXY_HEADERS=1` безопасен здесь, поскольку `8082` доступен только с localhost, а nginx перезаписывает proxy-заголовки.

## 6. Первичная настройка панели

1. В **Настройки → Профиль** проверьте учетную запись и смените пароль администратора.
2. В **Настройки → API** добавьте токен DNS-провайдера для домена пула.
3. В **Бэкапы** настройте S3, отдельную passphrase и расписание.
4. Нажмите **Создать бэкап сейчас** и выполните тестовое восстановление на отдельном стенде.
5. Добавьте выходные VPN-серверы и создайте пул.
6. Создайте тестового клиента и проверьте подключение AWG 3.1 и совместимость старого AWG 2.0-конфига.

## 7. Как сделать этот же сервер RU-фронтом

RU-фронт — это прозрачный UDP relay. VPN-ключи на нем не хранятся, а интернет-трафик выходит через выбранный член пула/WARP. Саму панель переустанавливать или переносить не нужно.

### 7.1. Важные ограничения

- Сначала создайте пул с отдельными выходными серверами.
- Сервер панели добавляйте именно через блок **Пулы → RU-фронт**, а не через **Серверы → Добавить сервер**. Один IP нельзя зарегистрировать одновременно как обычный VPN-сервер и как фронт.
- Не размещайте на этом же IP еще и выходной член того же пула: панель + front совместимы, front + обычный VPN-сервер на одном IP этой схемой не поддерживаются.
- Панель должна уметь подключиться по SSH из контейнера `web` к публичному IPv4 собственного хоста.
- Для непривилегированного SSH-пользователя нужен passwordless sudo: `sudo -n true` должен завершаться успешно.

### 7.2. SSH-ключ для панели

На рабочем компьютере создайте отдельный ключ без passphrase для автоматизации панели:

```bash
ssh-keygen -t ed25519 -f amnezia-panel-front -C amnezia-panel-front
ssh-copy-id -i amnezia-panel-front.pub -p 22 <ssh-user>@<PUBLIC_IPV4>
```

Если используется не `root`, добавьте passwordless sudo согласно вашей политике. Установщик relay выполняет системные операции с nftables, systemd и sysctl, поэтому обычного пользователя без sudo недостаточно.

Проверьте доступ именно из контейнера панели:

```bash
docker compose exec -T web ssh-keyscan -p 22 -T 5 <PUBLIC_IPV4>
```

При использовании нестандартного SSH-порта замените `22`.

### 7.3. Firewall и Docker

Установщик фронта включает `net.ipv4.ip_forward=1` и создает systemd-службу `amnezia-relay`. Он специально останавливается, если политика `iptables FORWARD` равна `DROP`, потому что relay после DNAT иначе может молча не работать.

Docker также может автоматически менять политику `FORWARD` на `DROP`. На новом совмещенном сервере запретите Docker делать это:

```bash
sudo install -m 0755 -d /etc/docker
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "ip-forward-no-drop": true
}
EOF
sudo dockerd --validate --config-file=/etc/docker/daemon.json
sudo systemctl restart docker
sudo iptables -P FORWARD ACCEPT
```

Если `/etc/docker/daemon.json` уже существует, добавьте параметр в имеющийся JSON, не перезаписывая остальные настройки. После изменения убедитесь, что контейнеры панели снова запущены: `docker compose ps`.

Проверьте перед регистрацией фронта:

```bash
sudo iptables -S FORWARD | head
sudo sysctl net.ipv4.ip_forward
```

Если используется UFW, его стандартная routed policy часто задает `FORWARD DROP`. Для совмещенного хоста предпочтительнее облачный firewall без UFW. Если UFW необходим, осознанно разрешите маршрутизацию:

```bash
sudo sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
sudo ufw allow 444/udp
sudo ufw reload
sudo iptables -S FORWARD | head
```

Открытие forwarding — системное решение для хоста. Ограничивайте нежелательные маршруты правилами облачного firewall/nftables и перепроверяйте политику после обновлений Docker или UFW.

### 7.4. Регистрация в интерфейсе

1. Откройте **Пулы** и нужный пул.
2. В блоке **RU-фронт** укажите публичный IPv4 сервера панели, SSH-порт и пользователя.
3. Вставьте пароль **или приватный SSH-ключ**. Для production рекомендуется отдельный ключ.
4. Выберите основную страну выхода и нажмите **Подключить фронт**.
5. Дождитесь статуса **relay работает**.
6. Нажмите **Проверить сейчас** и убедитесь, что end-to-end проверка успешна.
7. Только после этого нажмите **Направить домен на фронт**.

Проверка на хосте:

```bash
sudo systemctl status amnezia-relay --no-pager
sudo sysctl net.ipv4.ip_forward
sudo nft list table ip amnezia_relay
```

`ss -lun` может не показывать UDP 443/444 — это нормально: nftables DNAT пересылает пакеты и не создает слушающий сокет.

После регистрации проверьте с внешней сети:

- новый клиент AWG 3.1 подключается по endpoint, выданному панелью;
- старый конфиг AWG 2.0 продолжает подключаться;
- внешний IP клиента соответствует выходному серверу/WARP, а не RU-фронту;
- перезапуск `docker` и перезагрузка хоста не ломают `amnezia-relay`.

> Порт AWG 3.1 внутри relay может отображаться как UDP 444, но клиентский endpoint определяется сгенерированным конфигом и настройкой домена/порта пула. Не исправляйте endpoint вручную без проверки параметров пула.

## 8. Бэкап и восстановление

Минимально сохраните вне сервера:

- `APP_ENCRYPTION_KEY`;
- passphrase резервной копии;
- доступ к S3;
- репозиторий/ветку и доменное имя панели.

Панель сохраняет БД и `.env` в зашифрованный S3-бэкап. В БД находятся серверы, зашифрованные SSH-реквизиты, пулы, клиенты и токены.

Для аварийного восстановления на новом хосте:

```bash
cd /opt/amnezia-panel
docker compose up -d --build
docker compose exec -T web composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader

docker compose exec -T \
  -e S3_ENDPOINT=... -e S3_REGION=... -e S3_BUCKET=... \
  -e S3_KEY=... -e S3_SECRET=... -e BACKUP_PASSPHRASE=... \
  web php bin/restore.php --latest --show-key

docker compose exec -T \
  -e S3_ENDPOINT=... -e S3_REGION=... -e S3_BUCKET=... \
  -e S3_KEY=... -e S3_SECRET=... -e BACKUP_PASSPHRASE=... \
  web php bin/restore.php --latest --restore-db --yes

docker compose restart web
```

Восстановленный `.env` должен содержать исходный `APP_ENCRYPTION_KEY`. Если публичный IP панели изменился, обновите A-запись панели и SSH/firewall allowlist на управляемых серверах.

## 9. Обновление панели

Перед обновлением проверьте рабочее дерево и создайте бэкап:

```bash
cd /opt/amnezia-panel
git status --short
./update.sh --force
```

Скрипт делает резервную копию БД, получает код, при необходимости пересобирает контейнер, устанавливает Composer-зависимости и применяет только новые миграции.

Никогда не выполняйте `docker compose down -v`: ключ `-v` удалит том БД.

После обновления:

```bash
docker compose ps
curl -I https://panel.example.com/login
docker compose exec -T web php tests/run.php
sudo systemctl is-active amnezia-relay 2>/dev/null || true
```

## 10. Эксплуатационные проверки

```bash
# Контейнеры и последние ошибки
docker compose ps
docker compose logs --tail=200 web db dind

# Свободное место
df -h / /var/lib/docker
docker system df

# HTTPS и сертификат
curl -I https://panel.example.com/login
sudo certbot renew --dry-run

# Только для совмещенного RU-фронта
sudo systemctl status amnezia-relay --no-pager
sudo nft list table ip amnezia_relay
```

Для еженедельной очистки неиспользуемого Docker build-cache установите хостовый cron:

```bash
sudo tee /etc/cron.d/amnezia-docker-reaper >/dev/null <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 3 * * 0 root /bin/bash /opt/amnezia-panel/bin/docker_reaper.sh >> /var/log/amnezia-docker-reaper.log 2>&1
EOF
```

Крон внутри контейнера выполняет проверки клиентов и лимитов, мониторинг/failover, S3-бэкапы и read-only аудит обновлений серверов.

## 11. Короткий чек-лист приемки

- [ ] `docker compose ps` показывает рабочие `web`, `db`, `dind`;
- [ ] `https://panel.example.com` открывается с валидным сертификатом;
- [ ] `8082` недоступен извне;
- [ ] регистрация пользователей и debug routes выключены;
- [ ] `APP_ENCRYPTION_KEY` и backup passphrase сохранены вне сервера;
- [ ] тестовый S3-бэкап создан и проверен;
- [ ] панель по SSH видит выходные серверы;
- [ ] для совмещенного хоста доступны UDP 443/444 и не занят UDP 443 HTTP/3;
- [ ] `FORWARD` не имеет политики `DROP` на RU-фронте;
- [ ] `amnezia-relay` активен после перезагрузки;
- [ ] AWG 3.1 и существующий AWG 2.0-клиент проходят end-to-end проверку.
