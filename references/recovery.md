# Восстановление и ручной fallback (P0)

Как читать состояние автономного backup и что делать, если источник остался в
незавершённом состоянии. Предпочтительный путь всегда один: `vps3xui` и его
идемпотентный finalizer. Ручные команды — только fallback, когда systemd или
инструмент недоступны, и они никогда не публикуют `COMPLETE`.

## Состояния задачи

Worker (`vps3xui/worker/backup_worker.py`) — машина состояний:

```text
accepted → preflight → quiescing → copying → recovering → verifying → succeeded
                                                  │
                                             failed / recovery_required / unknown
```

- `accepted` — задача только принята; это не успех.
- `preflight` — проверка инвентаря, требуемых артефактов, места и identity.
- `quiescing` — остановка только тех контейнеров, что реально были running
  (по id из записанного исходного состояния), в порядке манифеста.
- `copying` — копирование объявленных данных (mounts, volumes, writable layers).
- `recovering` — возврат записанных контейнеров и точного состояния Certbot.
- `verifying` — проверка копии тем же кодом, что и локально.
- `succeeded` — только после успешной финализации и полного набора evidence.
- `failed` — операция провалена; исходная причина сохранена.
- `recovery_required` — сервисы не подтверждены восстановленными.
- `unknown`/`interrupted` — доказательств недостаточно; успехом не считается.

Исходный сбой хранится независимо от результата восстановления
(`report.json: original_failure`). Потеря boot/unit не превращается в успех.

## Finalizer и job recover

`vps3xui/worker/finalizer.py` используется двумя способами:

- как systemd `ExecStopPost` — восстанавливает контейнеры и состояние таймера
  даже при `RuntimeMaxSec`, `SIGKILL` или сбое на хосте;
- как `vps3xui job recover --host ALIAS --job JOB_ID --apply` — доносит
  восстановление для задачи, у которой evidence показывает
  `recovery_required` или `unknown`.

Он идемпотентен: при уже полном состоянии ничего не делает
(`already_complete`), без записанного `initial-state.json` переводит задачу в
`unknown` (`missing_initial_state`), запускает только записанные id и
восстанавливает Certbot только если он был записан. Восстановление само по себе
не делает незавершённую операцию успешной: при полном возврате сервисов состояние
остаётся `failed`/`unknown`, а не `succeeded`.

## Противоречивые доказательства завершения

`COMPLETE` сам по себе не доказывает успех. Успех принимается только по
согласованному writer-произведённому терминальному report: `state: succeeded`
без `original_failure`, `source_runtime_recovery: verified`,
`recovery_complete: true` и полным unit-proof
`SERVICE_RESULT=success`/`EXIT_CODE=exited`/`EXIT_STATUS=0`. Если рядом есть
durable first-cause журнал (`failure.json`), report с `copied`/неуспешным
`state`, неполным восстановлением или неподтверждённым unit-result, маркер стоит
при неуспешном, отсутствующем или повреждённом состоянии, либо расходятся пути
и metadata (`request.backup_dir`, report, `backup.json`), задача считается
несогласованной: `job status`, `blocking`, verify и fetch не возвращают успех.
Пустой или символический `COMPLETE` (и маркер через симлинкового предка) успехом
не считается и никогда не разыменовывается.

Реконсиляцию выполняет только `job recover` (finalizer) под stack lock и после
проверки machine identity. Единственная авторитетная цель — неизменяемый
`request.backup_dir` задачи: report и `backup.json` могут только согласиться с
ним, а сам каталог не должен иметь символических предков. Любое расхождение
блокирует успех: безопасное восстановление источников на проверенном хосте может
уже выполниться, после чего задача получает диагностический
`recovery_required`, а каталог бэкапа не изменяется. Причина сохраняется в
`recovery.binding_problem` и возвращается в результате, поэтому повторный
`job recover` снова даёт `recovery_required` и новые задачи остаются
заблокированными, пока расхождение не устранено; после починки задача
становится терминальной `failed` (успех не фабрикуется). Задача, которая честно
упала до копирования и не записала backup-путь, остаётся `failed` и не получает
binding-проблему. Незавершённая ревизия (`recovery.revocation.ok == false`) или
сохранённый binding problem держат задачу незавершённой и после того, как
state-файл ошибочно записан как `failed`.

Невыполнимая ревизия (чужой хост, небезопасный путь, ошибка `unlink`) сохраняет
маркер и исходную причину. Ошибка `fsync` наступает уже после успешного
`unlink`: запись удалена, но долговечность не доказана, поэтому ревизия остаётся
незавершённой — следующий `job recover` обязан снова сделать `fsync` каталога,
прежде чем считать отсутствие маркера доказанным. Согласованная завершённая
задача остаётся идемпотентной; терминальная `failed`-задача после успешной
ревизии маркера остаётся `failed` и не возвращается в `recovery_required`.

## Как действовать

1. Прочитай `vps3xui job status JOB_ID --host ALIAS --json`: поля `state`,
   `report.data_integrity`, `report.source_runtime_recovery`,
   `report.original_failure`.
2. Если `recovery_required` или `unknown` — выполни
   `vps3xui job recover --host ALIAS --job JOB_ID --apply`.
3. Затем `vps3xui backup verify --host ALIAS --job JOB_ID --manifest FILE`.
   Одного `COMPLETE` или доступности прокси недостаточно для вывода об успехе.

## Ручной fallback

`scripts/emergency-recover.sh JOB_DIR --apply` — для оператора с независимым SSH,
когда systemd/инструмент недоступны. Он читает `initial-state.json`, запускает
только записанные контейнеры, не публикует `COMPLETE` и отказывается работать без
`--apply` или без записанного исходного состояния. Это не замена `job recover`.

## Restore drill (обязателен до эксплуатации)

`scripts/vm-restore-drill.sh` — исполняемая процедура проверки восстановимости.
VM-часть создаёт **собственную синтетическую** fixture через
`scripts/vm_restore_fixture.py` и требует **одноразовую** Linux VM/контейнер root:

- `VPS3XUI_DRILL_ROOT` — одноразовый scratch root, никогда не `/`;
- `VPS3XUI_DRILL_IMAGE` — заранее загруженный тестовый образ в виде
  `repo@sha256:...` (drill никогда не тянет образы: только `--pull=never`);
- `VPS3XUI_DRILL_CONFIRM=disposable` — явное подтверждение одноразовости;
- опционально `VPS3XUI_DRILL_ID` и `VPS3XUI_DRILL_RELEASE`.

Fixture использует только уникальные имена `vps3xui-drill-<id>` для
volume/container/unit, отказывается переиспользовать существующие ресурсы и
перезаписывать существующие host-пути, не принимает реальные backup-аргументы и
не использует production-образы/OAuth. Fail-closed гарантии: отказ при `/` и
системных каталогах (`/opt`, `/etc`, `/var`, `/root`, `/home`), требование
маркера `.vps3xui-drill` и пустого scratch root, никаких загрузок, применения UFW
или запуска реальных приложений. Без обязательных переменных печатает `NOT RUN` и
выходит с кодом 3.

Drill состоит из двух частей:

1. **Портативная** (`scripts/portable_restore_drill.py`, вызывается первым и
   локально на синтетических fixtures) проверяет: полную копию принимает, а
   частичную отклоняет; named volume и оба Fail2ban-каталога восстанавливаются в
   **раздельные** destinations; восстановленный secret сохраняет mode 0600;
   относительная ссылка Let's Encrypt остаётся внутри дерева; UFW reference не
   применяется; после SIGKILL посреди copy нет `COMPLETE` и finalizer не объявляет
   успех; записанные контейнеры перезапускаются по одному в исходном порядке.
2. **VM** (Linux + GNU tar + docker/systemd + root + preloaded test image)
   выполняется `scripts/vm_drill.py` и гоняет **настоящие** установленные
   entrypoint-ы явными argv-массивами (`bin/vps3xui-worker --release-dir DIR JOB`
   и `bin/vps3xui-finalizer --release-dir DIR JOB`), а не строкой «команда с
   аргументами». `ExecStopPost` собирается с C-style escaping systemd и
   round-trip проверкой; для копирования добавляется только test-only PATH-shim
   `tar`, который приостанавливает первый `tar -cpf` (барьер), не меняя код
   продукта и не подделывая результат. Четыре независимых синтетических job:
   - success+restore: worker доходит до `succeeded`, публикует `COMPLETE`,
     архивы реально разворачиваются в ledger-owned изолированные destinations, а
     оба реальных `docker cp`-архива Fail2ban (`/etc/fail2ban`,
     `/var/lib/fail2ban`) вливаются в **созданный-остановленный** контейнер:
     содержимое и mode проверяются, контейнер обязан остаться остановленным;
   - SIGKILL: `systemctl kill --kill-who=all --signal=SIGKILL` по unit во время
     копирования после достигнутого барьера → нет `COMPLETE`, finalizer не
     объявляет успех, исходные контейнеры восстановлены;
   - timeout: реальный `RuntimeMaxSec=30` истекает во время копирования →
     `unit_result.SERVICE_RESULT == "timeout"` и отказ finalizer-а объявлять успех;
   - transport-loss: отдельный submitter убивается, но worker остаётся под
     управлением systemd и доходит до `succeeded` после снятия барьера.
   Дополнительно: GNU tar metadata round-trip (mode/owner/ACL/xattr), раздельные
   restore destinations и UFW reference, который никогда не применяется, с
   сравнением хешей исходников до и после. Очистка удаляет только уникальные
   созданные fixture-ресурсы.
   
   R9-дополнения к VM-части: fixture создаёт третий, изначально остановленный
   контейнер (`<prefix>-idle`), который план обязан оставить остановленным, и
   проверяет это во всех сценариях; создаёт host backup root `/var/backups/vps3xui`
   и отказывается переиспользовать существующий. Harness берёт launch-токен из
   валидированного ownership-ledger; пинует оба certbot-unit-файла
   (`certbot.service`, `certbot.timer`) в vendor-каталоге
   `/usr/lib/systemd/system` — ниже runtime-маски `/run`, поэтому `mask --runtime`
   реально их перекрывает, а `/etc`-файл перекрыл бы и worker отказал бы
   fail-closed — и подтверждает их реальным `probe_cron`; cleanup-юниты и drop-in
   остаются в `/etc` согласно манифесту. На usrmerge-хосте (`/lib` -> `usr/lib`)
   тот же vendor-файл виден ещё и как `/lib/systemd/system/<unit>`: fixture
   добавляет точный runtime-пин для алиаса только при совпадении dev+inode и
   digest с установленным файлом, а отдельный/чужой `/lib`-файл блокируется
   `compare`; симлинк `/lib` не создаётся и не записывается в ledger;
   строит для каждого job **свежий** реальный probe+plan (план, клонированный из
   шаблона, отвергается как `E_PLAN_STALE`); проверяет numeric uid/gid/mode, ACL и
   xattr восстановленного bind-файла, цель симлинков Let's Encrypt и содержимое
   volume; восстанавливает Fail2ban-слои через `docker cp -a -`; ждёт терминального
   состояния именно от finalizer-а (терминальное state → стабильный report → unit
   остановлен/отсутствует → `COMPLETE`), причём ошибка systemctl/bus никогда не
   трактуется как «остановлен»; сохраняет `report.json`/`state.json`/
   `initial-state.json`/`unit_result` в evidence до очистки; убивает submitter в
   `finally`; превращает `SystemExit`/неожиданное исключение в FAILED
   `evidence.json`; отказывается переиспользовать или пересекать evidence-каталог с
   ledger-owned путями.

`VPS3XUI_DRILL_EVIDENCE` должен указывать на новый каталог с существующим
родителем. Обёртка создаёт его эксклюзивно; существующие каталоги, symlink-пути
и пересечения с удаляемыми fixture-ресурсами отклоняются до записи evidence.
По умолчанию используется новый `<drill root>/evidence`.

**Статус:** портативная часть прогоняется и проходит локально; VM-часть
`NOT RUN` (нет одноразовой Linux VM в этой среде). Пока VM-часть не пройдена на
одноразовом хосте и результат не зафиксирован, P0 не считается пригодным для
эксплуатации — доказаны создание, целостность и структура восстановления архива,
но не полная восстановимость на реальном Docker/systemd.
