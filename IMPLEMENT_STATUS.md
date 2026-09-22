# Статус реализации backlog

## P1-01 — Общий контракт restore и поддерживаемая среда

**Статус:** DONE-LOCAL, решения приняты владельцем 2026-09-23.

Сделано:
- `vps3xui/restore/__init__.py` и `vps3xui/restore/contracts.py`. Это чистый модуль контракта
  без SSH, Docker и записей на хост. Он содержит backup и source identity, target facts и
  отказ для target, совпадающего с source, RestorePlan с TTL и identity, стабильный
  `rst-…` job ID, retry по `--plan`, immutable request, журнал intent/outcome и
  ownership, receipts стадий, доказательства cutover, диагностику, матрицу ОС и
  интерфейсы потоков.
- Семь схем `config/restore-*.schema.json`.
- `tests/restore_support.py`: fixtures на реальной синтетической P0-копии.
- `tests/unit/test_restore_contracts.py`: 44 теста.
- `docs/agent-work/p1/contracts.md`: решения контракта (открытых вопросов нет).

Проверки:
- `python3 -m unittest discover -s tests`: 625 тестов OK (581 прежних и 44 новых).
- `python3 -m compileall -q vps3xui bin tests scripts`: OK.
- Portable drill не запускался: общие P0-модули не изменялись.

Не изменялось: `cli.py`, `errors.py`, `jobs.py`, `coordination.py`, release,
P0-модули. Новых error-кодов и зависимостей нет. Production не затрагивался.

Решения владельца (2026-09-23), внесены в код и `docs/agent-work/p1/contracts.md`:
1. Source record: read-only чтение `request.json` исходной задачи.
2. Матрица ОС: только Ubuntu 24.04 x86_64 (Debian удалён, добавлен тест отказа).
3. Fencing через `restart_policy: no` без маскировки Docker допустим.
4. TTL доказательств cutover: 300 с.

Backlog обновлён: P1-01 — DONE-LOCAL, P1-02–P1-10 — READY. Следующая задача: P1-02.

## P1-02 — Жизненный цикл target-job и журнал частичных эффектов

**Статус:** DONE-LOCAL, 2026-09-23. Реальный Linux не запускался.

Сделано:
- `vps3xui/restore/job.py` — долговечная restore-задача в `restore-jobs/<job-id>/`:
  - `request.json` неизменяем, `state.json` хранит состояние;
  - журнал `journal/NNNNNN.json` публикуется эксклюзивно с fsync и никогда не заменяется;
  - `receipts/`, `attempts/`, первая причина сбоя в `failure.json`.
  - Регистрация идёт под общей блокировкой. Повтор того же ID/плана возвращает
    существующую задачу. Другие привязки дают `E_REQUEST_ID_CONFLICT` или `E_PLAN_STALE`.
  - Стадии prepared/staged/activated/verified и `certbot_active` проверяются по порядку
    и receipts. `staged` не разрешает запуск: activate требует принятого cutover.
  - Intent записывается до эффекта, outcome — после наблюдения. Проверяется ownership:
    чужой существующий ресурс нельзя объявить `created_by_job`.
  - Повтор шага разрешён только после `failed` или `not_applied`, для того же ресурса.
    Шаг без outcome переводит задачу в `unknown` и блокирует продолжение.
  - `reconcile` фиксирует `unknown`, `recovery_required` или прерывание.
    Он ничего не запускает и не удаляет.
- `vps3xui/restore/runtime.py`:
  - фиксированный argv `systemd-run`: `Type=exec`, `RuntimeMaxSec`, `TimeoutStopSec`,
    `KillMode=control-group`, без `ExecStopPost` и source finalizer;
  - маркер запуска pending/launched с boot id;
  - `observe`: смена boot, неподтверждённый запуск, остановленный unit, неизвестная
    живость (она не считается остановкой);
  - `run_bounded` с жёстким timeout, где timeout означает `unknown`.
  Автоматического восстановления при загрузке нет.
- `vps3xui/coordination.py`:
  - `scan_blocking` учитывает restore-задачи. Незавершённая restore блокирует backup,
    recover и другие restore до `verified` или `certbot_active`;
  - испорченная запись или симлинк блокируют;
  - поведение P0 для `jobs/` не изменено.
- Тесты: `tests/unit/test_restore_job.py` (39) и `tests/unit/test_restore_runtime.py` (17). Они покрывают:
  - конкурентную регистрацию и занятый lock;
  - потерянный ответ и изменённую цель;
  - сбой fsync при intent, outcome и state;
  - SIGKILL реального процесса между эффектом и outcome;
  - повторы и чужие ресурсы;
  - подмену receipt, сохранение первой причины;
  - взаимную блокировку backup и restore;
  - reboot и неизвестную живость unit.

Проверки:
- `python3 -m unittest discover -s tests`: 681 тест OK (625 прежних и 56 новых).
- `python3 -m compileall -q vps3xui bin tests scripts`: OK.
- `scripts/portable_restore_drill.py`: 11 проверок, 0 сбоев. GNU tar round-trip NOT RUN локально.
- `bin/vps3xui --help`: OK.

Не изменялось:
- `jobs.py`: локальный реестр клиента понадобится только при проводке CLI.
- `cli.py`, `errors.py`, `remote_ops.py`, `release.py`, `hostops.py`: относятся к P1-13.
- Новых error-кодов и зависимостей нет. Production не затрагивался.

Для P1-13:
- `bin/vps3xui-restore-worker` (на него ссылается runtime) ещё не создан.
- Модули `vps3xui/restore/*` нужно добавить в состав release.
- В `remote_ops` restore-задача уже блокирует резервирование backup через `scan_blocking`.

Backlog обновлён: P1-02 — DONE-LOCAL; из WAIT P1-11 и P1-12 зависимость P1-02 снята.
