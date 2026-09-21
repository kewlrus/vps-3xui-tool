# Текущая конфигурация приложений

Снимок конфигураций и mounts: 20.09.2026. Это карта работающего стека,
а не замена backup: секреты и содержимое БД намеренно отсутствуют.

## Compose и образы

| Проект | Compose | Сервис / контейнер | Образ в Compose |
|---|---|---|---|
| llmproxy | /opt/llmproxy/docker-compose.yaml | litellm / litellm | ghcr.io/berriai/litellm@sha256:32c04b00bc1a720e6d5eeb56a7e72f4e1e7d1e538e779c59b990cbddfd5e27da |
| llmproxy | тот же | caddy / caddy | caddy:2 |
| panel | /root/panel/compose.yml | 3xui / 3xui_app | ghcr.io/mhsanaei/3x-ui:v3.7.0 |

Все три контейнера имеют restart: unless-stopped.
Через LiteLLM/Caddy работает также агент, обслуживающий эту VPS. При остановке
шлюза он теряет доступ к модели: backup должен завершаться и возвращать сервисы
автономно на VPS, без дальнейших команд агента.
LiteLLM: версия 1.101.0, команда --config /app/config.yaml --port 4000.
Caddy и LiteLLM соединены сетью llmproxy_backend; наружу опубликован только 443/tcp.
3x-ui: network_mode: host, tty: true, cap_add: NET_ADMIN и NET_RAW.
Его Compose задаёт XRAY_VMESS_AEAD_FORCED=false, XUI_ENABLE_FAIL2BAN=true.
Эти параметры не являются доказательством фактической работы банов.

Текущие RepoDigests для воспроизводимого скачивания (перепроверять при backup):
- Caddy: caddy@sha256:df7f1c2fb114453b951de51a98efc010db1655a92c2e86be6706714e2417a78d
- 3x-ui: ghcr.io/mhsanaei/3x-ui@sha256:3b3131f1876e6bf35063a9ec4dd1c594e4525180bfc2e1c477dcc8a3c9550ca1

Не совмещать перенос с обновлением образов. Сами образы в backup не включать:
сохранять только ссылки registry с RepoDigest и скачивать их на новой VPS.
Совместимость выбранных образов с целевым Docker проверять отдельно.

## Конфигурации и постоянные данные

| Источник на VPS | В контейнере | Режим / назначение |
|---|---|---|
| /opt/llmproxy/litellm-config.yaml | litellm:/app/config.yaml | ro; модели и авторизация шлюза |
| /opt/llmproxy/caddy/Caddyfile | caddy:/etc/caddy/Caddyfile | ro; оба HTTPS-сайта |
| llmproxy_chatgpt_auth | litellm:/var/lib/litellm/chatgpt | rw; auth.json ChatGPT |
| llmproxy_caddy_data | caddy:/data | rw; сертификаты/ключи и ACME-состояние |
| llmproxy_caddy_config | caddy:/config | rw; постоянное состояние Caddy |
| /root/panel/db | 3xui_app:/etc/x-ui | rw; база панели, клиенты, Xray/MTProto и метрики |
| /etc/letsencrypt | 3xui_app:/etc/letsencrypt | ro; сертификаты, используемые панелью/прокси |

В /root/panel/db есть x-ui.db, x-ui.db-wal и x-ui.db-shm.
Не копировать только x-ui.db из работающей панели. Для переноса брать весь
согласованно остановленный каталог. Сохранять также system_metrics.gob.

Дополнительное состояние внутри writable layer 3xui_app: /etc/fail2ban
(конфигурация) и /var/lib/fail2ban (SQLite состояния банов). Эти каталоги
не смонтированы: сохранять отдельно через docker cp после остановки и
восстанавливать в созданный, ещё не запущенный контейнер. Архив не переносит
правила ядра хоста и сам по себе не доказывает восстановление действующих банов.
/app/bin/config.json и /app/bin/mtproto формируются панелью из БД;
логи, PID/socket-файлы и Python-кэши не нужны для воспроизведения окружения.

В backup входят оба Compose-файла и /opt/llmproxy/.env (0600).
Переменные .env: DUCKDNS_DOMAIN, DUCKDNS_TOKEN, LITELLM_MASTER_KEY, ANTHROPIC_API_KEY.
Compose передаёт Caddy только DUCKDNS_DOMAIN; наличие DUCKDNS_TOKEN не означает
использование DNS challenge. Caddy использует готовый образ, без build.

LiteLLM получает ANTHROPIC_API_KEY, LITELLM_MASTER_KEY,
CHATGPT_TOKEN_DIR=/var/lib/litellm/chatgpt, PYTHONUNBUFFERED=1,
NO_DOCS=true, NO_REDOC=true, NO_OPENAPI=true.
БД LiteLLM/Redis в текущей конфигурации нет; маршруты хранятся в YAML.

Путь каждого тома на хосте получать через docker volume inspect --format '{{.Mountpoint}}'.
Не закреплять /var/lib/docker/volumes как обязательный data-root целевой машины.
Для ChatGPT сохранять права каталога 0700 и auth.json 0600, владельца root:root.
В /etc/letsencrypt сохранять всё дерево: live содержит ссылки на archive.
Для его автоматического продления на новой VPS установить Certbot и включить
таймер по [процедуре развёртывания](backup-restore.md#5-автоматическое-продление-сертификатов).

## Автоматическое продление HTTPS

- kewlllm.duckdns.org и kewlnotes.duckdns.org: автоматический TLS Caddy,
  сертификаты Let's Encrypt и ACME-состояние в llmproxy_caddy_data.
  Отдельный Certbot для этих доменов не требуется.
- kewlsub.duckdns.org: сертификат Let's Encrypt используется панелью :3164
  и подписками :2096; хранится в /etc/letsencrypt/live/kewlsub.duckdns.org.
  На хосте установлен Certbot 2.9.0, certbot.timer enabled/active.
- certbot.service запускает /usr/bin/certbot -q renew --no-random-sleep-on-renew.
  Таймер: OnCalendar=*-*-* 00,12:00:00, RandomizedDelaySec=43200, Persistent=true.
  Cron-запись Certbot при работающем systemd не исполняется; дублировать её не нужно.
- В renewal/kewlsub.duckdns.org.conf указан authenticator=standalone (HTTP-01).
  Нужен доступ к 80/tcp извне и свободный локальный порт во время проверки.
- Постоянного разрешения UFW для 80/tcp нет. На действующей VPS по разрешению
  владельца установлены hooks /usr/local/sbin/certbot-http01-guard:
  pre_hook=open, post_hook=close, renew_hook=deploy (имя deploy-hook в Certbot 2.9).
  Они привязаны только к renewal-конфигурации kewlsub.duckdns.org.
- open добавляет только помеченные certbot-http01-kewlsub runtime-правила TCP/80
  в ufw-user-input и ufw6-user-input через iptables/ip6tables. Файлы UFW не меняются,
  другие правила не удаляются. Правила не переживают перезагрузку.
- certbot-http01-cleanup.timer включён и проверяет срок каждые 30 секунд;
  максимальный срок разрешения 900 секунд плюс интервал проверки. post-hook
  закрывает доступ после попытки; drop-in certbot.service.d/http01-cleanup.conf
  дополнительно вызывает close через ExecStopPost. Состояние lease.json находится
  в /var/lib/certbot-http01-guard и не должно переноситься.
- deploy после успешного продления нужного сертификата перезапускает только
  уже работающий 3xui_app, затем проверяет новый сертификат на 3164/2096.
  Намеренно остановленный контейнер не запускается. Перезапуск прерывает Xray/MTProto.
- Разрешение /etc/certbot-http01-guard.enabled привязано к /etc/machine-id источника.
  Без него open/deploy отказываются работать. Файл входит в certbot-automation.tar
  как подтверждение разрешённой автоматизации. При восстановлении создать его
  с machine-id целевой VPS: значение старой машины буквально не копировать.
  Это разрешено владельцем и не требует повторного согласования для этих hooks.

Скрипт, cleanup.service, cleanup.timer, drop-in и разрешение сохраняются отдельным
архивом certbot-automation.tar. При восстановлении установить их, перепривязать
разрешение и включить cleanup-таймер до certbot.timer. Сохранить лимит 900 секунд
и проверку каждые 30 секунд. Правила из ufw-config.tar не применять;
runtime lease и временные правила с исходного сервера не переносить.
Проверены имитации сбоев, конфигурация systemd и состояние служб; активная
ACME-проверка и реальный перезапуск панели при установке не выполнялись.

Успешный запуск таймера может означать только отсутствие необходимости продления.
Доступность модели и работоспособность MTProto этой проверкой не подтверждаются.

## LLM и клиенты

В general_settings:
- master_key: os.environ/LITELLM_MASTER_KEY
- litellm_key_header_name: X-Litellm-Api-Key
- forward_llm_provider_auth_headers: true

| Имя маршрута | Провайдер / модель |
|---|---|
| claude-* | anthropic/claude-* |
| gpt-6-astra | chatgpt/gpt-6-astra |
| gpt-5.6-sol | chatgpt/gpt-5.6-sol |
| gpt-5.6-terra | chatgpt/gpt-5.6-terra |
| gpt-5.6-luna | chatgpt/gpt-5.6-luna |

У всех GPT-записей model_info.mode: responses и supports_native_streaming: true.
Это идентификаторы текущей конфигурации, не обещание доступности всех моделей.
Сохранять Responses/streaming; не предполагать совместимость с /chat/completions.

Claude Code: ~/.claude/settings.json, env.ANTHROPIC_BASE_URL =
https://kewlllm.duckdns.org, env.ANTHROPIC_CUSTOM_HEADERS =
X-Litellm-Api-Key: Bearer <существующий ключ шлюза>, model = opus.
OAuth берётся из локального входа Claude, не из тома ChatGPT.
Серверный ANTHROPIC_API_KEY остаётся доступен для платного API при отсутствии OAuth;
схема не запрещает API-биллинг. Не удалять ключ без оценки других клиентов.

Codex: ~/.codex/config.toml, model_provider = "litellm":

```toml
[model_providers.litellm]
name = "LiteLLM"
base_url = "https://kewlllm.duckdns.org"
wire_api = "responses"
env_http_headers = { "X-Litellm-Api-Key" = "LITELLM_AUTH_HEADER" }
requires_openai_auth = false
```

LITELLM_AUTH_HEADER содержит Bearer и ключ шлюза; клиентский requires_openai_auth=false
корректен, потому что подпиской ChatGPT пользуется LiteLLM на сервере.
При сохранении домена и ключа перенос VPS не требует изменения клиентов.

## HTTPS, Xray и MTProto

Caddy обслуживает два сайта из одного Caddyfile:
- kewlllm.duckdns.org -> reverse_proxy litellm:4000.
- kewlnotes.duckdns.org -> HTML-страница прикрытия, Content-Type text/html.

Порты приложений: 443/tcp Caddy; 3164/tcp панель; 2096/tcp подписки панели;
51881/tcp и 44288/tcp Xray; 14689/tcp SOCKS; 8443/tcp MTProto.
Существующий доступ к SOCKS ограничен адресами 91.223.93.254 и 91.223.93.255;
это требование доступа для переноса, не инструкция публиковать SOCKS всем.
На новой площадке пользователь обеспечивает доступность портов самостоятельно.
Конфигурация UFW включается в отдельный справочный backup, но при восстановлении
приложений не применяется. Политики firewall провайдера этим backup не сохраняются.

MTProto запускается 3x-ui отдельным процессом mtg-linux-amd64.
Рабочая схема: fakeTlsDomain=kewlnotes.duckdns.org,
domainFronting=127.0.0.1:443, входящий порт 8443.
Точные inbounds, клиенты, secrets и ограничения переносятся через БД панели;
не восстанавливать их догадками или публиковать в скилле.
Проверка HTTPS через порт 8443 проверяет прикрытие, не вход Telegram.

При переключении DuckDNS учитывать три домена: kewlllm.duckdns.org,
kewlnotes.duckdns.org и kewlsub.duckdns.org; последний нужен панели и Certbot.
Проверять адреса, закодированные в БД/ссылках клиентов: прямой старый IP сам
не изменится. Без смены домена можно сохранить сертификаты и клиентские secrets.

## UFW: состояние и справочная копия

Проверено чтением 20.09.2026: UFW 0.36.2, active, logging on (low).
Политики по умолчанию: deny incoming, allow outgoing, deny routed.

| Входящий доступ | Источник | Семейство |
|---|---|---|
| TCP 22, 443, 51881, 44288, 3164, 2096, 8443 | Любой адрес | IPv4 и IPv6 |
| TCP 14689 | Только 91.223.93.254 и 91.223.93.255 | IPv4 |

Это снимок правил UFW, не полное описание фильтрации трафика Docker.
Docker управляет собственными правилами; Fail2ban панели использует action 3x-ipl
через iptables. Их динамические правила не входят в архив конфигурации UFW.

Сохранять /etc/ufw целиком (IPv4/IPv6, before/after rules, профили и hooks)
и /etc/default/ufw, отдельно от binds.tar. Вместе с архивом сохранять дату,
версию и вывод ufw status verbose, ufw status numbered, ufw show added.
Файлы предназначены пользователю для ручного решения о правилах новой VPS;
не устанавливать их в системные пути и не исполнять сохранённые команды.

## Неиспользуемое

telemt остановлен; его /root/docker-compose.yml и /root/telemt.toml не нужны
работающим приложениям. Он использует host network и порт 443, конфликтующий с Caddy.
По умолчанию не включать его в перенос. Если владелец просит сохранить и его,
архивировать оба файла отдельно и оставить контейнер остановленным.

Не требуются для запуска: /opt/llmproxy/backups, неактивный chatgpt_streaming.py,
caddy/Dockerfile и немонтируемые вспомогательные скрипты панели.
Пользовательские архивы не удалять; просто не считать их частью рабочего стека.
