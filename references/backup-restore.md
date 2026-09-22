# Backup и перенос Docker-приложений

> **Историческая процедура.** Это ручной fallback и исходный материал до
> появления P0-инструмента `vps3xui`. Единственный источник синтаксиса команд —
> `bin/vps3xui --help`, а актуальный протокол — в корневом `SKILL.md`.
> Не использовать этот файл как исполняемую спецификацию; механику
> backup/verify/fetch выполняет код. Архитектура — `references/architecture.md`,
> ручное восстановление — `references/recovery.md`.

Эта инструкция применяется после явного разрешения на backup/остановку источника
и запись на названную целевую VPS. Ни один из этих шагов не выполняется при обычной
диагностике или обновлении скилла. Установка Docker Engine и плагина Docker Compose
на целевой VPS входит в развёртывание из backup. Также входят установка Certbot
и настройка его systemd-таймера для сертификата панели. Установка ОС и общее
обслуживание системных библиотек вне scope; зависимости Docker/Certbot входят
в установку этих компонентов.

UFW сохраняется только для справки. При развёртывании НЕЛЬЗЯ применять его правила,
менять конфигурацию или состояние UFW целевой VPS. Это остаётся на пользователе.
Не копировать архивные файлы в /etc/ufw или /etc/default/ufw, не выполнять
ufw enable/disable/reload/reset/default/allow/deny и не импортировать эти правила
через iptables-restore, nft либо startup hooks. Этот запрет действует и при
проверке доступности приложений; при блокировке порта сообщить пользователю.

Разрешённое владельцем исключение: восстановить и активировать certbot-http01-guard
для временного доступа TCP/80 во время продления kewlsub.duckdns.org, аварийной
очистки и перезапуска 3x-ui после успеха. Разрешение включено в certbot-automation.tar
и перепривязывается к новой VPS без повторного согласования. Это не разрешает
применять ufw-config.tar, включать UFW или постоянно открывать порт 80.

## Состав копии

| Артефакт | Содержимое |
|---|---|
| binds.tar | Два Compose, .env, LiteLLM YAML, Caddyfile, весь panel/db, всё дерево /etc/letsencrypt |
| llmproxy_chatgpt_auth.tar | Авторизация ChatGPT |
| llmproxy_caddy_data.tar | Сертификаты/ACME Caddy |
| llmproxy_caddy_config.tar | Состояние Caddy |
| 3xui-fail2ban-config.tar / 3xui-fail2ban-data.tar | Конфигурация и БД Fail2ban из writable layer панели |
| images.txt | Имена контейнеров, ссылки из конфигурации и RepoDigests для скачивания из registry; без самих образов |
| certbot-automation.tar | Скрипт hooks Certbot, cleanup service/timer, drop-in и разрешение их активации на новой VPS |
| ufw-config.tar | /etc/ufw и /etc/default/ufw; только для ручного использования пользователем |
| ufw-meta.txt, ufw-status.txt, ufw-numbered.txt, ufw-added.txt | Дата/версия UFW, состояние, нумерованные и добавленные правила; не исполнять |
| SHA256SUMS | Проверка целостности перечисленных файлов |

Это секретная копия: в ней ключи шлюза, OAuth, клиенты панели и приватные сертификаты.
Каталог 0700, файлы доступны только владельцу. Передавать по SSH и хранить
в согласованном зашифрованном хранилище. Не прикладывать к ответу и не класть в git.
Не выводить содержимое .env, auth.json или БД. SHA256 проверяет целостность,
но не заменяет доверенный канал и проверку происхождения архива.

Docker-образы не архивировать. При восстановлении они скачиваются из интернета;
нужен доступ целевой VPS к соответствующим registry. RepoDigest фиксирует версию
образа и отличается от локального Image ID: для скачивания нужна полная ссылка
repository@sha256:digest, а не голый sha256 ID.

## 1. Подготовка источника

Перед остановкой сверить [карту mounts](apps.md), существование всех путей
и объём свободного места под архивы данных. Не сохранять полный docker inspect.
Не копировать контейнерный writable layer целиком или весь Docker data-root.
Из writable layer сохранять только указанные прикладные каталоги Fail2ban.
Проверить, нет ли важных данных вне перечисленных mounts; при расхождении
сначала дополнить состав копии, а не объявлять её полной.

Убедиться, что во время копирования никто не меняет конфигурации/сертификаты.
Исключить запуск Certbot на время согласованной копии. Убедиться, что нет
действующей HTTP-01 lease; не останавливать аварийный cleanup при открытом порте.
Согласовать окно недоступности: остановка 3x-ui прерывает Xray и MTProto,
остановка LiteLLM/Caddy прерывает оба LLM-клиента.

Для финального переноса прекратить использование источника перед последней
копией и оставить приложения остановленными. Одновременный запуск двух
LiteLLM с копией одного OAuth-хранилища может привести к конкурирующему refresh.
Обычная резервная копия обязательно возвращает исходные сервисы в работу.
Агент зависит от этого LiteLLM/Caddy: пока шлюз остановлен, модель недоступна.
Финальный перенос с оставленным выключенным источником выполнять только через
независимый канал модели либо по полностью подготовленной процедуре пользователя.
Без такого канала не начинать финальное выключение и не рассчитывать, что агент
после остановки сам отправит следующую команду или переключит себя на новую VPS.

## 2. Согласованная копия

Пример ниже — содержимое автономного worker для обычного backup (root, Bash,
GNU tar), а не команды для последовательного выполнения агентом. До остановки
сохранить его на VPS как /root/vps-apps-backup-worker.sh (root:root, 0700),
проверить bash -n и все предусловия. Не запускать worker напрямую: его запускает
systemd-задача из следующего подраздела. Архивы и журнал остаются на VPS.

Пример предполагает, что все три контейнера до запуска задачи работают; проверить
это ещё до systemd-run. Иначе адаптировать и остановку, и ExecStopPost под исходные
состояния, не оживляя остановленные контейнеры. Для финального переноса этот
worker не подходит: он всегда возвращает источник в работу.

```bash
set -euo pipefail
umask 077
backup_dir=$(mktemp -d /root/vps-apps-backup.XXXXXXXX)
chmod 700 "$backup_dir"

test -d /etc/ufw
test -f /etc/default/ufw
{
  date -u '+%Y-%m-%dT%H:%M:%SZ'
  ufw version
} > "$backup_dir/ufw-meta.txt"
ufw status verbose > "$backup_dir/ufw-status.txt"
ufw status numbered > "$backup_dir/ufw-numbered.txt"
ufw show added > "$backup_dir/ufw-added.txt"
tar --numeric-owner --acls --xattrs -cpf "$backup_dir/ufw-config.tar" -C / \
  etc/ufw etc/default/ufw
tar --numeric-owner --acls --xattrs -cpf "$backup_dir/certbot-automation.tar" -C / \
  usr/local/sbin/certbot-http01-guard \
  etc/systemd/system/certbot-http01-cleanup.service \
  etc/systemd/system/certbot-http01-cleanup.timer \
  etc/systemd/system/certbot.service.d/http01-cleanup.conf \
  etc/certbot-http01-guard.enabled

for container in litellm caddy 3xui_app; do
  test "$(docker inspect --format '{{.State.Running}}' "$container")" = true
done
for volume in llmproxy_chatgpt_auth llmproxy_caddy_data llmproxy_caddy_config; do
  docker volume inspect "$volume" --format '{{.Mountpoint}}' >/dev/null
done

for container in litellm caddy 3xui_app; do
  docker inspect --format '{{.Name}} {{.Config.Image}}' "$container"
  image_id=$(docker inspect --format '{{.Image}}' "$container")
  repo_digests=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image_id")
  test -n "$repo_digests"
  printf '%s\n' "$repo_digests"
done > "$backup_dir/images.txt"

docker stop -t 60 caddy litellm 3xui_app
for container in litellm caddy 3xui_app; do
  test "$(docker inspect --format '{{.State.Running}}' "$container")" = false
done

bind_paths=(
  opt/llmproxy/docker-compose.yaml
  opt/llmproxy/litellm-config.yaml
  opt/llmproxy/.env
  opt/llmproxy/caddy/Caddyfile
  root/panel/compose.yml
  root/panel/db
  etc/letsencrypt
)
for extra in opt/llmproxy/restore-images.yaml root/panel/restore-images.yaml; do
  if [ -f "/$extra" ]; then bind_paths+=("$extra"); fi
done
tar --numeric-owner --acls --xattrs -cpf "$backup_dir/binds.tar" -C / "${bind_paths[@]}"
docker cp -a 3xui_app:/etc/fail2ban - > "$backup_dir/3xui-fail2ban-config.tar"
docker cp -a 3xui_app:/var/lib/fail2ban - > "$backup_dir/3xui-fail2ban-data.tar"

for volume in llmproxy_chatgpt_auth llmproxy_caddy_data llmproxy_caddy_config; do
  volume_dir=$(docker volume inspect "$volume" --format '{{.Mountpoint}}')
  test -d "$volume_dir"
  tar --numeric-owner --acls --xattrs -cpf "$backup_dir/$volume.tar" -C "$volume_dir" .
done

(
  cd "$backup_dir"
  sha256sum binds.tar images.txt certbot-automation.tar \
    ufw-config.tar ufw-meta.txt ufw-status.txt ufw-numbered.txt ufw-added.txt \
    3xui-fail2ban-config.tar 3xui-fail2ban-data.tar \
    llmproxy_chatgpt_auth.tar llmproxy_caddy_data.tar llmproxy_caddy_config.tar \
    > SHA256SUMS
)
printf 'complete\n' > "$backup_dir/COMPLETE"
printf 'Backup directory: %s\n' "$backup_dir"
```

### Автономный запуск и возвращение прокси

До запуска получить разрешение на backup и окно недоступности, подготовить worker
целиком и сообщить пользователю unit name и аварийную команду запуска контейнеров.
Не оставлять установку зависимостей, запросы подтверждений или следующие шаги
агента на период, когда прокси будет выключен. Для каждой задачи выбрать свободное
уникальное имя unit; имя в примере использовать только если оно ещё не занято.

Запустить на VPS через systemd-run без --wait, --pipe и --pty. SSH только передаёт
задачу systemd; задача продолжает работу независимо от SSH и доступности модели:

```bash
systemd-run --unit=vps-apps-backup \
  --property=Type=exec \
  --property=RuntimeMaxSec=15min \
  --property=TimeoutStopSec=90s \
  --property=KillMode=control-group \
  --property='ExecStopPost=/usr/bin/docker start litellm caddy 3xui_app' \
  --property=StandardOutput=journal \
  --property=StandardError=journal \
  /bin/bash /root/vps-apps-backup-worker.sh
```

ExecStopPost запускает сервисы после успеха, ошибки или принудительного завершения
worker по лимиту времени. KillMode=control-group останавливает также дочерние
процессы копирования перед окончанием остановки службы. Не заменять это одним
shell trap: он не гарантирован при SIGKILL. Лимит 15 минут согласовать с объёмом
данных заранее; истечение лимита означает неуспешный backup.

Не удалять unit через --collect до проверки результата. Не запускать два backup
одновременно. Если Docker или хост неисправен, ExecStopPost не гарантирует запуск:
у пользователя должен оставаться независимый SSH-доступ и команда восстановления
для исходно работавших контейнеров: docker start litellm caddy 3xui_app.

После возвращения прокси продолжить проверку (при необходимости пользователь
возобновляет диалог). Получить результат и путь архива из журнала:

```bash
systemctl show vps-apps-backup.service -p Result -p ExecMainStatus
journalctl -u vps-apps-backup.service --no-pager -n 80
docker inspect litellm caddy 3xui_app --format '{{.Name}} {{.State.Running}}'
```

Прочитать журналы с очисткой возможных чувствительных данных. Проверить liveliness
прокси без генерации. Backup считать готовым только при Result=success,
ExecMainStatus=0, наличии COMPLETE и всех архивов, успешном sha256sum -c SHA256SUMS.
Восстановление сервисов при ошибке не делает частичные архивы пригодными.
Не удалять предыдущие копии или исходные данные.
Передать весь каталог на целевую VPS по SSH. Уточнить точный alias назначения;
не использовать vps-3xui по привычке в командах восстановления.

## 3. Восстановление на чистой VPS

Сначала проверить наличие Docker Engine и плагина Docker Compose на целевой VPS.
Если они отсутствуют, определить дистрибутив и установить их с необходимыми
зависимостями по актуальной официальной инструкции https://docs.docker.com/engine/install/.
Запустить Docker и включить его запуск при загрузке средствами целевой ОС.
Это обычная часть разрешённого развёртывания, отдельное разрешение на установку
Docker не требуется. Существующую рабочую установку не переустанавливать и не
обновлять без необходимости. Проверить docker version и docker compose version.

Перед восстановлением целевой Docker должен поддерживать выбранные образы
и иметь доступ к registry, имена контейнеров/проектов не заняты.
Домены пока остаются на источнике.
Все действия этого раздела выполняются на целевой VPS, не на источнике.

ufw-config.tar и ufw-*.txt оставить в каталоге backup и передать пользователю.
Их контрольные суммы проверяются вместе с остальными файлами, но они исключены
из всех шагов восстановления ниже. Не распаковывать UFW в системные каталоги,
не исполнять ufw-added.txt и не запускать архивные hooks даже косвенно.
UFW на цели может отсутствовать или иметь собственные правила: не устанавливать
и не перенастраивать его в рамках развёртывания приложений.

certbot-automation.tar восстановить по разделу 5: этот архив включает разрешение
на активацию конкретных hooks. /etc/certbot-http01-guard.enabled на цели должен
содержать её собственный machine-id, а не скопированное значение источника.
Runtime lease и временные правила не переносить. Не выдавать отсутствующий
helper или неработающий cleanup-таймер за настроенное продление.

1. В переданном каталоге выполнить sha256sum -c SHA256SUMS. Проверить список
   членов binds.tar без вывода содержимого файлов. Принимать только свою
   доверенную копию; пути должны соответствовать составу выше, без выхода за него.
2. Распаковать binds.tar в новый staging-каталог, сохранив владельцев,
   права, ACL/xattrs и symlinks. Не распаковывать поверх существующих приложений.
3. Убедиться, что /opt/llmproxy, /root/panel и /etc/letsencrypt отсутствуют
   на цели. Если хотя бы один существует, остановиться и согласовать слияние.
   Создать родительские /opt и /root при необходимости, затем перенести из
   staging только эти три дерева на их исходные абсолютные пути.
   Не разыменовывать ссылки live -> archive в /etc/letsencrypt.
4. Создать три именованных тома с исходными именами. Если том уже существует
   и не пуст, не перезаписывать его. Получать Mountpoint через Docker.
5. По images.txt подготовить override-файлы ниже с полными registry-ссылками
   и скачать образы через docker compose pull. При недоступности registry/digest
   сообщить об ошибке, не подменять образ изменяемым тегом автоматически.
6. После переноса /etc/letsencrypt установить Certbot и подготовить его расписание
   по разделу 5. Не активировать продление до проверки домена, hooks и доступности
   HTTP-01; существующие сертификаты позволяют сначала запустить приложения.

Пример восстановления одного тома; повторить для всех трёх с их архивами:

```bash
docker volume create llmproxy_chatgpt_auth
volume_dir=$(docker volume inspect llmproxy_chatgpt_auth --format '{{.Mountpoint}}')
test -d "$volume_dir"
test -z "$(ls -A "$volume_dir")"
tar --numeric-owner --same-owner --acls --xattrs --keep-old-files \
  -xpf /ABSOLUTE_BACKUP_DIR/llmproxy_chatgpt_auth.tar -C "$volume_dir"
```

ABSOLUTE_BACKUP_DIR заменить проверенным путём; это пример, не готовый путь.
После извлечения проверить права .env, тома ChatGPT и auth.json по метаданным.

По images.txt создать на цели два Compose override-файла с RepoDigests.
В примерах заменить DIGEST_FROM_BACKUP реальным digest соответствующего образа
из этой копии. Не использовать локальные Image ID или значения по памяти:

```yaml
# /opt/llmproxy/restore-images.yaml
services:
  litellm:
    image: "ghcr.io/berriai/litellm@sha256:DIGEST_FROM_BACKUP"
  caddy:
    image: "caddy@sha256:DIGEST_FROM_BACKUP"
```

```yaml
# /root/panel/restore-images.yaml
services:
  3xui:
    image: "ghcr.io/mhsanaei/3x-ui@sha256:DIGEST_FROM_BACKUP"
```

Сохранять override-файлы и использовать их при последующих Compose-командах.
Блок backup включает их в binds.tar, если они существуют.
Это сохраняет выбранные версии при скачивании из registry.
Не добавлять восстановление telemt к этим проектам.

## 4. Запуск и переключение

Сначала config --quiet с теми же аргументами, затем запуск.
Значения секретов не выводить. Не использовать docker compose config без --quiet.

```bash
cd /opt/llmproxy
docker compose -p llmproxy -f docker-compose.yaml -f restore-images.yaml config --quiet
docker compose -p llmproxy -f docker-compose.yaml -f restore-images.yaml pull
docker compose -p llmproxy -f docker-compose.yaml -f restore-images.yaml up -d

cd /root/panel
docker compose -p panel -f compose.yml -f restore-images.yaml config --quiet
docker compose -p panel -f compose.yml -f restore-images.yaml pull
docker compose -p panel -f compose.yml -f restore-images.yaml create
docker cp -a - 3xui_app:/etc < /ABSOLUTE_BACKUP_DIR/3xui-fail2ban-config.tar
docker cp -a - 3xui_app:/var/lib < /ABSOLUTE_BACKUP_DIR/3xui-fail2ban-data.tar
docker compose -p panel -f compose.yml -f restore-images.yaml start
```

Копирование Fail2ban выполняется один раз в новый остановленный контейнер.
При последующем пересоздании эти немонтируемые данные опять потребуют переноса;
добавление постоянных mounts для них является отдельным изменением архитектуры.

Для panel не заменять cd одним --project-directory: Compose использует $PWD/db.
Проверить docker inspect .Mounts; путь должен быть /root/panel/db, не каталог
backup/staging. У llmproxy должны использоваться восстановленные три тома,
а не новые пустые тома с другим project prefix.

До переключения DNS проверить:
- Контейнеры запущены, mounts совпадают, LiteLLM liveliness и список моделей работают.
- HTTPS двух доменов Caddy на новом IP через curl --resolve; Caddy сохранил сертификаты.
  Сертификат kewlsub.duckdns.org проверяется отдельно на портах 3164 и 2096.
- Панель видит перенесённые inbounds/клиентов; слушает порты Xray и MTProto.
  Адреса 127.0.0.1 и Docker service name litellm сохраняются; внешний старый IP
  в клиентских ссылках/настройках при наличии требует отдельной замены.
- Прикладная доступность необходимых портов обеспечена на целевой площадке.
  Правила UFW пользователь применяет самостоятельно; агент только сообщает,
  какие проверки не проходят. Управление DNS согласовывается отдельно.

После согласованного переключения трёх DuckDNS-доменов проверить Claude Code,
Codex и Telegram с клиентского устройства. Генерация требует разрешения;
HTTP 200 от /v1/models не доказывает работу подписок.
При одинаковых домене и ключе LLM-клиентские конфиги остаются прежними.

Не держать два активных сервера с одним ChatGPT OAuth-хранилищем.
Для отката сначала остановить целевые приложения, затем вернуть маршрутизацию
и запустить источник. Не запускать источник с устаревшим auth.json вслепую,
если целевой сервер успел обновить токены; может потребоваться повторный вход.
Старую VPS и backup не удалять до подтверждения работы всех трёх клиентов.

## 5. Автоматическое продление сертификатов

Этот раздел относится к целевой VPS. Восстановление /etc/letsencrypt переносит
сертификаты, ACME-аккаунт, cli.ini и renewal-конфигурации, но не программу Certbot
и не systemd units. Их установка и настройка входят в разрешённое развёртывание.

1. После восстановления дерева /etc/letsencrypt установить Certbot способом,
   соответствующим целевому дистрибутиву. Для Ubuntu/Debian с systemd использовать
   пакет certbot из репозитория: apt-get update, затем apt-get install -y certbot.
   Существующую установку не переустанавливать; не смешивать apt, snap и pip.
   Пакет может автоматически активировать таймер: на время подготовки предотвратить
   его запуск на цели, затем снять временную блокировку перед шагом 4.
2. Проверить certbot --version и наличие certbot.service/certbot.timer.
   Использовать пакетные units; не копировать их вслепую с другой ОС.
   Проверить запуск renew без интерактивного входа, регулярное расписание
   (два окна в сутки со случайной задержкой) и Persistent=true.
   Не создавать дополнительный cron, если работает systemd-таймер.
3. Проверить renewal/kewlsub.duckdns.org.conf, пути live/archive и hooks.
   Распаковать проверенный certbot-automation.tar в отдельный staging-каталог.
   Убедиться, что архив содержит скрипт, три systemd-файла и непустой файл
   разрешения etc/certbot-http01-guard.enabled. При неполном/недоверенном архиве
   не активировать hooks. Установить helper в /usr/local/sbin (root:root, 0755),
   cleanup.service, cleanup.timer и drop-in в указанные в архиве пути /etc/systemd/system
   (root:root, 0644). Не перезаписывать существующую отличающуюся автоматизацию.
   Проверить пути /usr/bin/python3, docker и systemctl, а также цепочки ufw-user-input
   и ufw6-user-input в используемых iptables/ip6tables. При отсутствии цепочек
   сообщить пользователю: создавать или включать UFW самостоятельно нельзя.
   Создать разрешение с machine-id новой VPS, затем включить watchdog и проверить
   helper, не вызывая open/deploy. Команды после установки файлов и проверки архива:

   ```bash
   test -s /etc/machine-id
   install -o root -g root -m 600 /etc/machine-id /etc/certbot-http01-guard.enabled
   systemd-analyze verify certbot-http01-cleanup.service certbot-http01-cleanup.timer
   systemctl daemon-reload
   systemctl enable --now certbot-http01-cleanup.timer
   /usr/local/sbin/certbot-http01-guard check
   ```

   Сохранить pre_hook=open, post_hook=close и renew_hook=deploy в renewal-файле.
   Не переносить lease.json и не копировать machine-id источника в ОС цели.
   Для standalone HTTP-01 домен должен указывать на новую VPS, локальный порт 80
   должен быть свободен, а внешняя сеть допускать доступ Let’s Encrypt. Временное
   локальное разрешение создаст hook только при продлении; постоянное не добавлять.
   При блокировке на стороне площадки сообщить пользователю, не менять её firewall.
4. После выполнения условий и переключения kewlsub.duckdns.org активировать
   таймер и проверить его состояние. Пример для пакетного Certbot на systemd:

   ```bash
   systemctl enable --now certbot.timer
   systemctl is-enabled certbot.timer
   systemctl is-active certbot.timer
   systemctl list-timers --all certbot.timer
   ```

5. Проверить журнал certbot.service и следующий запуск. Сообщение
   "Certificate not yet due for renewal" подтверждает лишь проверку срока.
   certbot renew --dry-run является активной ACME-проверкой, а не чтением:
   выполнять только в рамках согласованной проверки продления после переключения
   DNS. На исходной VPS его автоматически не запускать.
6. Проверить, что deploy-hook привязан к нужному lineage и перезапускает только
   работающий 3xui_app с проверкой сертификата на 3164/2096. Такой перезапуск
   после успешного продления разрешён и прерывает Xray/MTProto. Не запускать
   его при восстановлении без продления и не перезапускать весь стек.
   Наличие таймера само по себе не доказывает успешность полного цикла обновления.

Для доменов Caddy достаточно восстановленных томов и автоматического TLS:
не добавлять их в Certbot и не копировать сертификаты между двумя хранилищами.
При будущих backup исключить одновременное продление и копирование
/etc/letsencrypt; учитывать certbot.timer и возможные новые deploy-hooks.
