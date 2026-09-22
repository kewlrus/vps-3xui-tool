# Архитектура vps3xui (P0)

Это карта реализации исполняемого инструмента: что где лежит, какие данные
текут и какие свойства безопасности обеспечиваются кодом. Не дублирует синтаксис
команд — он в `bin/vps3xui --help`, а схема манифеста в
`config/manifest.schema.json`.

## Назначение

Агент принимает решения (что разрешено, какой scope, какой этап), а утилита
реализует проверяемый алгоритм backup и возвращает структурированный результат.
Критическая механика не зависит от доступности модели или живой SSH-сессии:
после `backup start` задача выполняется автономно на хосте под systemd.

Размещение соответствует §3 проекта: небольшая Python-обёртка локально, release
на хосте, состояние в `/var/lib/vps3xui`, секретные копии в `/var/backups/vps3xui`.

## Компоненты

```text
bin/vps3xui ── vps3xui/cli.py ──────────── локальный CLI (read-only по умолчанию)
                 │  manifest.py  ── типизированный манифест, требуемый набор артефактов
                 │  inventory.py ── drift-сравнение манифеста с фактами
                 │  plan.py      ── привязанный к машине план с истечением
                 │  jobs.py      ── durable registry/lock/idempotency
                 │  backup.py    ── оркестрация plan/start/status/verify/fetch/recover
                 │  verify.py    ── переносимая проверка (артефакты, sums, архив)
                 │  release.py   ── сборка и digest закреплённого release
                 │  probe.py     ── фиксированный read-only probe (stdin на хост)
                 └ adapters/ssh.py ── строгий OpenSSH transport (HostOps)

host: bin/vps3xui-worker ── worker/backup_worker.py ── автономный backup
                            worker/system.py         ── Docker/systemd/GNU tar
                            worker/finalizer.py      ── ExecStopPost / job recover
                            worker/jobctx.py         ── durable job dir (0700/0600)
                            worker/metadata.py       ── images.json / backup.json
```

Логические модули разрешено объединять; новые абстракции не добавлялись без
второго сценария.

## Поток данных

1. `inspect` запускает `probe.py` на хосте через `adapters/ssh.py` и сравнивает
   факты с манифестом (`inventory.compare`). Любой необъяснённый ресурс
   блокирует, а не «включается молча».
2. `backup plan` строит план, привязанный к host key fingerprint, machine-id,
   digest манифеста, структурному digest инвентаря, версии инструмента и сроку
   (`plan.py`). `verify_plan` отклоняет устаревший/истёкший/чужой план как
   `E_PLAN_STALE`/`E_PLAN_EXPIRED`/`E_HOST_IDENTITY_MISMATCH`.
3. `backup start` под локальным lock регистрирует request id **до** отправки,
   доставляет закреплённый release, проверяет его digest и запускает
   `vps3xui-worker` под systemd с лимитами времени и `KillMode=control-group`.
   Резервирование и запуск идут через один host-wide `flock` (`remote_ops.py`):
   незавершённая задача блокирует новые, повторный request id с тем же планом
   идемпотентен, другой план — `E_REQUEST_ID_CONFLICT`.
4. Worker фиксирует исходное состояние (какие контейнеры реально running),
   останавливает только их по одному в исходном порядке, копирует объявленные
   данные, возвращает сервисы и восстанавливает точное состояние Certbot. Worker
   заканчивает на состоянии `copied` и **не** публикует `COMPLETE`; маркер
   публикует только независимый finalizer (`ExecStopPost` / `job recover`) после
   собственных финальных проверок.
5. `job status` читает durable state; `backup verify` проверяет требуемый набор
   артефактов и `SHA256SUMS`; `backup fetch` переносит секретную копию.

## Manifest: факты, а не команды

Манифест (`manifest.py`, JSON) содержит идентификаторы, типы и пути, но не
shell-snippets и не значения секретов. Пример — `config/manifest.example.json`
(снимок 2026-09-20), намеренно `approved=false`. Требуемый набор артефактов
выводится из провалидированного манифеста, а не из содержимого `SHA256SUMS`,
поэтому пропущенный обязательный архив — ошибка даже при внутренне согласованном
sums. Локально собранный образ без registry digest невосстановим →
`E_IMAGE_NOT_RESTORABLE`.

Пример содержит `pending_approval` для `agent-relay`: backup, заявляющий
полноту, блокируется, пока свежий read-only `inspect` не подтвердит ресурс и
манифест не будет утверждён. Любая запись `pending_approval` блокирует полноту
безусловно, независимо от угаданного имени контейнера.

Утверждённый манифест обязан закрепить **полный** trust-контракт:
`trusted_files` (sha256) обязан покрывать guard-хелпер, его маркер включения,
cleanup-юниты, dropin и renewal-файл линии; для привилегированного guard-хелпера
дополнительно закрепляются `mode`/`uid`/`gid` (привязка прав к машине), а
`certbot.hook_fingerprints` — все разрешённые hook-команды. Подмножество
trust-контракта запрещено при `approved=true`; fingerprint-ы и права хранятся
приватно и не печатаются в `inspect`.

Перед любым изменением план дополнительно блокируется, если не наблюдаются или
ниже согласованных минимумов Python/Docker/Compose/systemd, отсутствует GNU tar
(или это не GNU tar), известный физический `docker.root_dir` пересекается с
объявленным путём архива, runtime-lease certbot попадает внутрь объявленного
include, объявленные пути перекрываются или имя артефакта принадлежит двум
ресурсам. Планировщики Certbot определяются по содержимому файлов. В P0 cron/at-запись и
любой источник, кроме `systemd`, блокируют план безусловно: fingerprint
подтверждает содержимое файла, но не его бездействие, а guard управляет только
временным доступом HTTP-01 и сам по себе ничего не разрешает. Запись с
`source=systemd` проходит только когда это непосредственный файл в
`/etc/systemd/system`, `/lib/systemd/system` или `/usr/lib/systemd/system`, его
basename точно объявлен в `manifest.certbot` (`service_unit`, `timer_unit`,
`cleanup_service`, `cleanup_timer`), а манифест закрепляет непустой observed
digest. Такие объявленные unit-ы worker маскирует и восстанавливает, а pinned
cleanup-автоматизация остаётся активной; посторонний или переименованный unit
по-прежнему блокируется. Разрешение cron/at требует отдельного доказательства
бездействия под systemd; до этого P0 отказывает. Активная система при этом не
изменяется.

Очередь `at`/batch проверяется отдельно, не по содержимому: read-only `atq`
(когда доступен) и наблюдение документированных Linux-спулов
`/var/spool/cron/atjobs`, `/var/spool/at` и `/var/spool/at/jobs`. Известные
каталоги вывода (`/var/spool/cron/atspool`, `/var/spool/at/spool`) не читаются
и не считаются задачами. Любая ожидающая `at`-задача блокирует план как
`E_CONFLICT` безусловно — P0 не анализирует shell-тело или wrapper, которые
могут вызвать Certbot; тела задач, окружение и сырой вывод `atq` не читаются и
не печатаются, остаётся только ограниченное свидетельство (наличие
инструментов, путь спула, счётчик). Отсутствие `at`/спулов остаётся
поддержанным состоянием, а нечитаемый, неправильный или неопознанный спул либо
сбой `atq` — это error-токен (`E_PROBE_INCOMPLETE`), а не пустая очередь.
Единственный разрешённый служебный файл внутри спула — `.SEQ`, и только как
валидный regular non-symlink; одноимённая ссылка или другой тип остаётся
неопознанной. Захват `atq` ограничен по байтам/строкам/времени, а обход
каталога — по числу записей; превышение любой границы даёт `unknown`, а не
пустую очередь. Установленный `at` без инспектируемой очереди (нет `atq` и нет
известного спула) — тоже `unknown`/`E_PROBE_INCOMPLETE`, а не `absent`.
Факты очереди входят в structural inventory digest, поэтому изменение очереди
между планом и preflight делает план устаревшим (`E_PLAN_STALE`), а не
запускает копирование.

## Свойства безопасности

- **Транспорт.** `adapters/ssh.py` всегда ставит `StrictHostKeyChecking=yes`,
  `BatchMode=yes`, отключает multiplexing (`ControlMaster=no`,
  `ControlPath=none`) и `UpdateHostKeys=no`. Alias — валидированный идентификатор,
  не интерполируется в shell. Неизвестный host key → `E_HOST_KEY_UNKNOWN`.
  Каждая команда связывается с закреплённым host key: `GlobalKnownHostsFile=/dev/null`,
  `UserKnownHostsFile=<найденный файл>`, `HostKeyAlgorithms=<keytype>`,
  `Hostname`/`Port` из `ssh -G`; `proxycommand`/`proxyjump`/`hostkeyalias`/
  `knownhostscommand` отвергаются как невязываемые. Нет TOFU и `ssh-keyscan`.
  Чужой child stderr не сохраняется: только длина и digest.
- **Probe.** `probe.py` фиксирован, read-only, передаётся по stdin; только
  валидированный JSON-spec из манифеста (пути, Compose-проекты, unit-имена,
  writable-layer пути, config для fingerprint) передаётся отдельным argv-токеном,
  с реальным cwd/PWD для `docker compose`. Ничего не пишет и не устанавливает;
  не печатает env, содержимое секретных файлов, полный `docker inspect`, раскрытый
  Compose или arbitrary volume options. Пустой/ошибочный probe fail-closed.
- **Архив.** `adapters/archive.py` до распаковки отвергает traversal, абсолютные
  пути, дубликаты, устройства/FIFO, setuid/setgid, опасные PAX capabilities и
  symlink-ancestor атаки; при этом сохраняет безопасные относительные ссылки
  Let's Encrypt (`live/x -> ../../archive/x/...`).
- **Состояние.** Каталоги `0700`, чувствительные файлы `0600`, атомарные
  durable-записи, безопасные ID/пути, без symlink-clobber. В логах нет raw
  stderr, env, значения секретов, HTTP-тел или текста исключений.
- **Планировщик и firewall.** Неизвестный Certbot scheduler/hook — конфликт;
  UFW — reference-only артефакт, никогда не применяется, включая drill.
- **Политика в коде.** Отсутствующая операция надёжнее запрета в тексте:
  в CLI просто нет `restore`/`prune`/`import ufw`/`deploy`/установки пакетов.
- **Restore drill.** `scripts/vm-restore-drill.sh` (+ `scripts/vm_drill.py`) —
  отдельная процедура проверки восстановимости, не часть рантайма: собственный
  синтетический fixture с per-run токеном (токен перечитывается из валидированного
  ownership-ledger перед запуском unit-а), явные argv для настоящих
  `bin/vps3xui-worker`/`bin/vps3xui-finalizer` под `systemd-run`, реальный
  `RuntimeMaxSec`, SIGKILL по unit, потеря submitter-а и восстановление реальных
  архивов в созданный-остановленный контейнер (`docker cp -a -`). Для каждого
  сценария строится свежий реальный probe+plan, план сверяется на `E_PLAN_STALE`;
  fixture дополнительно держит изначально остановленный `<prefix>-idle`-контейнер,
  пинует certbot-unit-файлы и создаёт host backup root `/var/backups/vps3xui`.
  Триггеры certbot ставятся в vendor-каталог `/usr/lib/systemd/system`, ниже
  runtime-маски `/run/systemd/system`, поэтому `systemctl mask --runtime` реально
  перекрывает их (`/etc` файл перекрыл бы маску и worker отказал бы fail-closed);
  cleanup-юниты и drop-in остаются в `/etc` согласно контракту манифеста. На
  usrmerge-хосте (`/lib` -> `usr/lib`) реальный `probe_cron` видит тот же vendor-файл
  ещё и как `/lib/systemd/system/<unit>`; fixture добавляет runtime-пин для этого
  алиаса только когда он резолвится в тот же установленный файл (совпадают
  dev+inode и digest). Отдельный или чужой `/lib`-файл доверия не получает и
  блокируется `compare` (fail closed); алиас не создаётся и не попадает в ledger;
  harness проверяет numeric uid/gid/mode, ACL/xattr и содержимое volume,
  дожидается finalizer-aware терминального состояния (systemctl/bus-ошибка никогда
  не считается «остановлен») и сохраняет job-evidence до очистки. Портативная часть
  проходит локально; VM-часть на текущей машине `NOT RUN` (нет одноразовой
  Linux-цели), поэтому Docker/systemd-гарантии считаются недоказанными до
  записанного прогона.

## Код возврата и ошибки

`errors.py` держит стабильные коды и группы exit-кодов: `0` успех, `2`
контракт/аргументы, `3` предусловие/конфликт, `4` выполнение, `5` проверка.
Всякий сбой несёт безопасный `error.code`, `message`, `resource`, `next_action`.

## Состояние и версионирование

- Локальный реестр запросов: `jobs.py` (`JobStore`), каталог по умолчанию
  приватный, `0700`; записи `0600`.
- Состояние задачи на хосте: `/var/lib/vps3xui/jobs/<job-id>/`; секретная копия:
  `/var/backups/vps3xui/<backup-id>/`.
- Версия инструмента: `vps3xui/__init__.py` (`TOOL_VERSION`). Release собирается
  из фиксированного списка файлов (`release.py`) с детерминированным digest и
  проверяется при доставке.
