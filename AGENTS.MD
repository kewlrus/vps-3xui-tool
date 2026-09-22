# vps3xui: описание проекта и правила работы с P0

## Назначение

`vps3xui` — исполняемый CLI для диагностики и безопасного резервного копирования
Docker-приложений личной VPS `vps-3xui`: LiteLLM, Caddy и 3x-ui/Xray/MTProto.
Состав конкретной копии задаётся проверенным и утверждённым манифестом.
Полнота backup означает соответствие этому инвентарю, а не сохранение всей VPS.

Агент согласует намерение, машину и этап операции, объясняет результат и
разбирает конфликты. Код выполняет preflight, остановку, копирование,
восстановление сервисов и проверку результата. После принятия задачи её
критическая механика работает автономно под systemd, без доступной модели
и живой SSH-сессии. Это существенно: модельный канал агента может проходить
через тот же LiteLLM/Caddy, который останавливается во время backup.

Реализация: Python 3.9+, только стандартная библиотека. Небольшие shell-обёртки
служат точками запуска и аварийным helper. На исходном Linux-хосте используются
штатные OpenSSH, Docker Engine, Docker Compose, systemd и GNU tar.
Поддерживаемые версии и факты окружения проверяются кодом; `inspect` и `plan`
не устанавливают зависимости.

## Источники требований и текущий статус

- [Исходный дизайн](vps3xui-executable-tool-design.md): требования P0, контракт
  CLI, безопасность, формат backup и приёмочные сценарии. Документ также
  описывает будущий P1; его статус «проект» не отражает текущую готовность кода.
- [Протокол агента](SKILL.md): правила использования инструмента и разрешений.
- [Архитектура](references/architecture.md) и
  [восстановление после сбоев](references/recovery.md): устройство реализации,
  finalizer, ручной fallback и restore drill.
- [Handoff](handoff.md) и
  [аудит функциональности](docs/agent-work/p0/FUNCTIONALITY-AUDIT.md): актуальные
  результаты проверок и ограничения. Старые отчёты не заменяют текущий аудит.
- Синтаксис команд сверяй с `bin/vps3xui --help` и справкой подкоманд;
  структуру манифеста — с `config/manifest.schema.json`.

На 2026-09-23 локальный функционал P0 реализован. Последний полный прогон:
581 тест PASS; переносимая часть restore drill: 11 проверок PASS.
Реальный Linux restore drill имеет статус **NOT RUN**. До его прохождения
общая приёмка P0 остаётся открытой, готовность к эксплуатации не доказана.
Эти числа описывают зафиксированный прогон, а не заменяют проверку нового кода.

Пример `config/manifest.example.json` имеет `approved=false`. Он основан на
снимке стека и не является утверждённым production-инвентарём. `agent-relay`
требует подтверждения ресурсов и воспроизводимого образа; реальные guard/hooks
Certbot — отдельной проверки и закрепления доверенных файлов. Нельзя получать
«рабочий» манифест простым переключением `approved` или выдумыванием отпечатков.

## Границы P0

P0 включает read-only инвентаризацию, построение плана, устойчивую регистрацию
задач, автономный обычный backup, восстановление исходных сервисов после
операции, проверку архивов на источнике и локально, контролируемое скачивание
копии и изолированную процедуру проверки восстановимости.

Пользовательский CLI `restore prepare/stage/activate/verify` и активация Certbot
на новой VPS относятся к P1. `job recover` в P0 восстанавливает исходное
состояние ресурсов своей задачи; это не развёртывание backup на другой машине.

В P0 не добавлять универсальный remote exec, произвольный shell из манифеста,
DNS cutover, финальное выключение источника, `--leave-stopped`, retention/prune,
архивирование Docker-образов, автоматический boot recovery, установку пакетов
или deployment. MCP, HTTP API, постоянный daemon и универсальный workflow engine
также не входят в эту версию.

## Реализованный CLI

Запуск из корня репозитория: `bin/vps3xui`. Это shell-обёртка;
не запускать её как `python3 bin/vps3xui`.

| Команда | Назначение и эффекты |
| --- | --- |
| `inspect --host HOST --manifest FILE` | Чтение инвентаря и сравнение с манифестом |
| `backup plan --host HOST --manifest FILE --out PLAN` | Чтение предусловий и запись локального плана |
| `backup start --host HOST --manifest FILE --plan PLAN --request-id ID --apply` | Доставка закреплённого release, регистрация и автономный запуск задачи |
| `job status ID --host HOST` | Чтение долговечного состояния и доказательств результата |
| `backup verify --host HOST --job ID --manifest FILE` | Проверка исходной задачи и её архивов |
| `backup verify --directory DIR --manifest FILE` | Независимая проверка перенесённой копии |
| `backup fetch --host HOST --job ID --manifest FILE --destination DIR --apply` | Скачивание секретной копии и локальная проверка |
| `job recover --host HOST --job ID --apply` | Ограниченное восстановление записанных ресурсов исходной задачи |

Все команды поддерживают `--json`: stdout содержит один объект результата,
а не смесь JSON с выводом Docker/SSH. Ошибки имеют стабильный `error.code` и
безопасную диагностику. Группы exit-кодов: `0` — команда выполнена, `2` —
контракт/аргументы, `3` — предусловия/конфликт, `4` — исполнение, `5` — проверка.

У `backup start` код 0 означает принятие задачи, не готовность копии.
У `job status` код 0 означает успешное чтение статуса: сама задача может быть
`failed`. Всегда проверяй `state`, `operation_complete` и отчёт.
Успешная команда `backup verify` требует прохождения обязательных проверок.
Проверка на источнике поддерживает новый клиент без локальной истории: данные
берутся из проверенного неизменяемого request на хосте; локальный манифест должен
соответствовать задаче. Независимое `job recover` также не требует локальной записи.

## Карта реализации

| Путь | Ответственность |
| --- | --- |
| `bin/vps3xui`, `vps3xui/cli.py`, `vps3xui/errors.py` | Публичный интерфейс, JSON и ошибки |
| `vps3xui/manifest.py`, `vps3xui/jsonschema_lite.py`, `config/` | Схема, семантика инвентаря и требуемые артефакты |
| `vps3xui/probe.py`, `vps3xui/inventory.py` | Фиксированный read-only probe и выявление drift |
| `vps3xui/plan.py` | Срок действия, идентичность машины, предусловия и состав операции |
| `vps3xui/backup.py`, `vps3xui/jobs.py` | Клиентский workflow и локальный реестр запросов |
| `vps3xui/coordination.py`, `vps3xui/remote_ops.py` | Блокировки, host-side регистрация, запуск и согласование evidence |
| `vps3xui/release.py` | Сборка и проверка закреплённого набора исполняемых файлов |
| `vps3xui/worker/backup_worker.py`, `vps3xui/worker/system.py` | Preflight, Certbot, остановка, копирование и возврат сервисов |
| `vps3xui/worker/finalizer.py`, `bin/vps3xui-finalizer` | Независимая финализация через ExecStopPost и recover |
| `vps3xui/worker/jobctx.py`, `vps3xui/worker/failure_journal.py`, `vps3xui/worker/metadata.py` | Долговечное состояние, первая причина сбоя и metadata |
| `vps3xui/verify.py`, `vps3xui/remote_verify.py`, `vps3xui/adapters/` | Проверка копий, SSH, Docker/systemd facts и безопасные архивы |
| `scripts/portable_restore_drill.py`, `scripts/vm-restore-drill.sh`, `scripts/vm_drill*.py`, `scripts/vm_restore_fixture.py` | Синтетическое восстановление и испытания отказов |
| `scripts/emergency-recover.sh` | Ограниченный ручной fallback через независимый канал |
| `tests/unit/`, `tests/integration/`, `tests/support.py`, `tests/fakeexec.py` | Тесты, синтетические данные и адаптеры |

На хосте release закрепляется в `/opt/vps3xui/releases/<version>-<digest-prefix>`.
Задачи хранятся в `/var/lib/vps3xui/jobs/<job-id>/`, копии — в
`/var/backups/vps3xui/<job-id>/`. Активная задача не переключается на новый код.
При добавлении модулей worker проверяй состав поставляемого release.

## Инварианты реализации

1. **Разрешения и идентичность.** `--apply` обязателен для изменяющих команд,
   но не доказывает согласие человека. Действующая VPS по умолчанию read-only.
   Backup/остановка, deployment отдельной цели и переключение DNS имеют разные
   границы разрешений. SSH использует известный host key, BatchMode и строгую
   проверку без TOFU, обновления ключей или multiplexing. План связан с host key,
   machine-id, контекстом подключения, версиями, манифестом, инвентарём и сроком.
   Перед изменениями выполняется повторная проверка под блокировкой.

2. **Инвентарь и данные.** Manifest содержит типизированные факты и пути без
   секретов и исполняемых команд. Неизвестные сервисы, mounts, writers, volume
   drivers/options и неполные probe-факты блокируют операцию. Образы должны быть
   воспроизводимы по registry digest; локальную сборку нельзя молча заменить
   тегом. Сохраняются утверждённые bind trees, named volumes, весь каталог БД
   panel, Let's Encrypt и два отдельных каталога Fail2ban. Весь Docker data-root
   и Docker-образы не копируются.

3. **Задачи и отказоустойчивость.** Request ID фиксируется до отправки запуска.
   Повтор того же ID/плана разрешает существующую задачу, другой план даёт
   конфликт. Общая блокировка охватывает резервирование, worker, finalizer и
   recover; незавершённая задача продолжает блокировать новые после потери lock.
   Исходное состояние надёжно записывается до первой остановки. systemd запускает
   worker с `Type=exec`, `RuntimeMaxSec`, `TimeoutStopSec`,
   `KillMode=control-group` и независимым `ExecStopPost`.

4. **Возврат источника.** Останавливаются и запускаются только записанные
   исходно работающие container IDs в согласованном порядке. Изначально
   остановленные контейнеры, включая исключённый `telemt`, не запускаются.
   Сервисы возвращаются сразу после копирования, до длительной проверки SHA256.
   Сохраняется первая причина ошибки; удачный recovery не превращает сорванное
   копирование в успешный backup. При неполных доказательствах — `unknown` или
   `recovery_required`, а не успех.

5. **Certbot и UFW.** Активная HTTP-01 lease, продление, неизвестный hook или
   scheduler блокируют backup. Известные триггеры временно блокируются с точным
   восстановлением исходного состояния и повторной проверкой гонки; cleanup
   остаётся доступным. Очередь `at` проверяется ограниченно, без чтения тел задач;
   непустая или неизвестная очередь блокирует операцию. UFW сохраняется только
   отдельным reference-артефактом и никогда не применяется, в том числе в drill.
   Не воссоздавать production guard по описанию и не выдавать его за доверенный.

6. **Доказательства успеха.** `COMPLETE` публикуется только после успешной
   финализации, проверки данных, восстановления источника и подтверждения исхода
   unit. Маркер, state, report, failure journal и привязки путей должны
   согласовываться. Доступность прокси, отсутствие unit и один маркер не
   доказывают успех. `status`, `verify` и `fetch` обязаны одинаково отклонять
   противоречивое завершение. Корректирующие изменения evidence выполняет
   finalizer/recover после проверки идентичности и принадлежности путей.

7. **Архивы и секреты.** Весь backup считается секретным. Каталоги имеют `0700`,
   чувствительные файлы — `0600`; записи критического состояния атомарны и
   долговечны. Проверяется точный набор артефактов и metadata, `SHA256SUMS` и
   безопасность tar: traversal, дубликаты, special files, опасные PAX и выходящие
   ссылки отклоняются. Безопасные относительные ссылки Let's Encrypt сохраняются.
   `fetch` отказывается от непустого назначения и небезопасных симлинков;
   не раскрывай ссылки до проверок, стирая свидетельство перенаправления.
   SHA256 подтверждает целостность, но не аутентифицирует отправителя.

8. **Безопасная диагностика.** Не выводить env, OAuth, ключи, содержимое БД,
   HTTP-тела, полный inspect/раскрытый Compose и сырой stderr дочерних процессов.
   Не запускать генерацию модели, login/refresh, активные ACME-проверки,
   `/health` или `/health/drain` как пассивную диагностику. Отчёт отделяет
   целостность данных и возврат источника от непроведённых модельных,
   Telegram-клиентских и restore-проверок.

## Разработка и проверки

Сохраняй совместимость с Python 3.9 и отсутствие сторонних runtime-зависимостей.
Не переноси основную логику в shell и не добавляй абстракции без конкретной
потребности. Изменения безопасности должны сохранять отказ при неизвестных
фактах; не ослабляй проверки ради прохождения fixture или production-примера.

Рабочее дерево содержит существенные незакоммиченные и untracked файлы;
одного `git diff` недостаточно для оценки реализации. Сохраняй чужие изменения,
`.codegraph/` и `.gitignore`; `.DS_Store` не относится к функциональности.
Не включай в git runtime state, рабочие секретные манифесты, backup и credentials.

Базовые локальные проверки из корня репозитория:

```bash
PYTHONPYCACHEPREFIX=/private/tmp/vps3xui-pycache PYTHONPATH=tests:. python3 -m unittest discover -s tests
PYTHONPYCACHEPREFIX=/private/tmp/vps3xui-pycache python3 -m compileall -q vps3xui bin tests scripts
PYTHONPYCACHEPREFIX=/private/tmp/vps3xui-pycache PYTHONPATH=tests:. python3 scripts/portable_restore_drill.py
PYTHONPYCACHEPREFIX=/private/tmp/vps3xui-pycache bin/vps3xui --help
```

Тесты используют синтетические fixtures, fake adapters и секреты-канарейки.
Регрессии должны проверять наблюдаемый результат, сохранение состояния и
отсутствие запрещённых эффектов. При изменениях жизненного цикла проверяй
повторы/конкурентность, ошибки copy, timeout/SIGKILL, потерю транспорта,
недоступное восстановление, Certbot lease/race, drift и противоречивый `COMPLETE`.
При изменениях проверки/fetch проверяй частичные копии, повреждённые суммы,
неверный состав артефактов, небезопасные пути и отсутствие утечки канареек.

## Условие полной приёмки P0

Обязателен реальный restore drill на явно согласованной одноразовой Linux-цели
с systemd, Docker, GNU tar, ACL/xattr tools и заранее загруженным синтетическим
образом `repository@sha256:...`. Процедура описана в `references/recovery.md`.
Нужно подтвердить успешное восстановление, UID/GID/mode/ACL/xattrs, отдельные
destinations, оба Fail2ban-каталога, сохранение остановленных контейнеров,
SIGKILL/timeout/потерю submitter и очистку только принадлежащих fixture ресурсов.
Сохраняй evidence результата и cleanup; `NOT RUN` не считать успешным тестом.

Владелец сообщил, что одноразовой Linux-машины пока нет. Не запрашивай её повторно
без нового контекста и не используй production как замену. Локальные проверки
можно выполнять независимо; live-инвентарь и утверждение production trust-набора
остаются отдельной задачей.

<!-- CODEGRAPH_START -->
## CodeGraph

In repositories indexed by CodeGraph (a `.codegraph/` directory exists at the repo root), reach for it BEFORE grep/find or reading files when you need to understand or locate code:

- **MCP tool** (when available): `codegraph_explore` answers most code questions in one call — the relevant symbols' verbatim source plus the call paths between them, including dynamic-dispatch hops grep can't follow. Name a file or symbol in the query to read its current line-numbered source. If it's listed but deferred, load it by name via tool search.
- **Shell** (always works): `codegraph explore "<symbol names or question>"` prints the same output.

If there is no `.codegraph/` directory, skip CodeGraph entirely — indexing is the user's decision.
<!-- CODEGRAPH_END -->
