# P1-01 — Общий контракт restore

Статус: реализовано локально; решения §2, §7, §9 приняты владельцем 2026-09-23. Код контракта:
`vps3xui/restore/contracts.py`; схемы: `config/restore-*.schema.json`;
fixtures: `tests/restore_support.py`; тесты: `tests/unit/test_restore_contracts.py`.
Модуль чистый: без SSH, Docker и записей на хост. Общие файлы (`cli.py`,
`errors.py`, `jobs.py`, `coordination.py`, release) не изменялись.

## 1. Версионированные записи

Все записи имеют `schema_version: 1`, закрытые схемы (`additionalProperties: false`)
и проверяются `jsonschema_lite`. Ошибка схемы сообщает JSON pointer, не значение.

| Запись | Схема | Назначение |
| --- | --- | --- |
| RestorePlan | `restore-plan.schema.json` | План одной стадии: backup, source, target, allowlist ресурсов, операции, граница активации, TTL, `identity` |
| Target facts | `plan.properties.target` | alias, host key, machine-id, resolved SSH context, ОС/версия/arch, `platform_id` |
| Backup identity | `plan.properties.backup` | `backup_id`, `backup_digest` = sha256 `SHA256SUMS`, format 1, manifest id/digest, артефакты |
| Source record | `restore-source-record.schema.json` | Явно привязанная к backup идентичность source |
| Immutable request | `restore-request.schema.json` | Регистрация job: привязки, начальный plan identity, release digest |
| Journal entry | `restore-journal-entry.schema.json` | `intent` до эффекта → `outcome` по наблюдению; ownership |
| Stage receipt | `restore-receipt.schema.json` | Результат проверенных шагов стадии, `receipt_digest` |
| Source observation | `restore-source-observation.schema.json` | Машинное наблюдение source для cutover |
| Cutover attestation | `restore-cutover-attestation.schema.json` | Решение оператора и независимый канал управления |

Ошибки используют существующие коды `errors.py`; новых кодов нет. Если P1-13
решит ввести специализированные коды, это делается там с обратной совместимостью.

## 2. Идентичность source (решение)

`backup.json` формата 1 не содержит host key и machine-id, и restore их
не выводит. Идентичность принимается только из двух источников (`resolve_source_identity`):

1. **Source record**. Это запись, явно привязанная к `backup_id`, `backup_digest`, manifest id/digest
   и `source_job_id == backup_id`. Метод получения один: `source_job_request`, то есть
   неизменяемый `request.json` исходной задачи на source (там есть machine_id и
   host_key_fingerprint). Если запись противоречит пинам манифеста, restore отклоняется.
2. **Полные пины манифеста**. Оба значения, `expected_machine_id` и `expected_host_key_fingerprint`,
   берутся из того манифеста, с которым сделан backup (digest совпадает).

Во всех остальных случаях restore отклоняется с `E_PRECONDITION`: один пин, отсутствие данных, alias, доступность сети
или совпадение имён контейнеров не принимаются. Формат backup 2 с
идентичностью в metadata не вводится. Его добавит отдельная задача вместе с
совместимым reader P0 verifier (`SUPPORTED_BACKUP_FORMATS`).

**Решение владельца (2026-09-23):** source record получается read-only чтением
`request.json` исходной задачи через закреплённый host key source. На source ничего
не пишется и не запускается. Реализация относится к P1-03/P1-13.

## 3. Target и отказ от source

Target facts требуют известный host key, machine-id и поддерживаемую платформу.
`check_target_distinct` отклоняет target, если у него тот же machine-id **или**
тот же host key, что у source. Поэтому второй alias на source не проходит.
`verify_restore_plan` перед записью заново проверяет expiry, версию инструмента,
манифест, backup, host key, machine-id, resolved context и digest target facts.

## 4. Restore job ID и retry

`job_id = "rst-" + sha256({backup_digest, manifest_digest, target host key,
target machine-id})[:24]`. Один backup на одной target-машине всегда даёт одну
job. Поэтому планы разных стадий, построенные в разное время (TTL 30 мин), указывают
на одну и ту же job, а синтаксис `--plan FILE --apply` остаётся без изменений.

`request_matches_plan`:
- тот же job, backup, manifest, source и target дают `resume` (новый plan identity допустим);
- другие привязки при том же job дают `E_REQUEST_ID_CONFLICT`;
- другая версия инструмента даёт `E_PLAN_STALE` (активная job не переключается на новый код).

`--apply` лишь разрешает запись. Согласием он не считается: cutover требует отдельной
attestation (§6). Параметры CLI до P1-13 фиксируются так:
`restore plan --target HOST --backup DIR --manifest FILE [--source-record FILE] --out FILE`.
Манифест обязателен, чтобы сопоставить digest с backup.

Стадии и состояния job: `planned → preparing → prepared → staging → staged →
activating → activated → verifying → verified → certbot_activating →
certbot_active`. Состояния `failed`, `recovery_required` и `unknown` блокируют
продолжение (`check_stage_entry`). Стадию `verify` можно повторять.

## 5. Журнал и ownership

- `intent` записывается долговечно до эффекта. `outcome` записывается после наблюдения; `applied` без
  `observed` запрещён.
- Intent без outcome получает статус `unknown`: нужна сверка, успех не предполагается.
- Последовательность `seq` непрерывна. Outcome должен совпадать со своим intent по stage, kind,
  resource, ownership и expected. Повтор шага допускается только после `failed` или
  `not_applied`. Запись другой job приводит к `E_NOT_OWNED`.
- `owned_resources` включает только `created_by_job` с исходом `applied` или `unknown`.
  Ресурсы `preexisting_accepted` job никогда не принадлежат.

Хранение журнала реализовано в P1-02 (`vps3xui/restore/job.py`): задача в
`restore-jobs/<job-id>/` под общей блокировкой backup/restore/recover; каждая запись
журнала публикуется эксклюзивно с fsync и никогда не заменяется; первая причина сбоя
хранится отдельно от попыток. Незавершённая restore-задача блокирует backup и другие
restore до `verified` или `certbot_active`.

## 6. Receipts и интерфейсы потоков

Receipt выдаётся, только если каждый указанный шаг в журнале имеет исход `applied` и принадлежит
стадии этого receipt. Потребитель (`validate_receipt` и `check_stage_inputs`)
принимает receipt только своей job, backup и target с верным digest.

| Стадия | Потребляет | Производит | Интерфейс |
| --- | --- | --- | --- |
| plan | backup, manifest, source record | RestorePlan | `RestorePlanner.build` |
| prepare | — | `prepared_target` | `TargetPreparer.prepare` |
| stage/transfer | `prepared_target` | `verified_payload` | `PayloadTransfer.transfer` |
| stage/data | `prepared_target` | `data_restored` | `DataStager.restore_data` |
| stage/containers | `prepared_target` | `containers_created` | `ContainerStager.create_containers` |
| stage/guard | `prepared_target` | `guard_prepared` | `GuardPreparer.prepare_guard` |
| activate | 5 receipts prepare/stage + cutover | `activation` | `Activator.activate` |
| verify | `activation` | `verification_report` | `Diagnostics.verify` |
| certbot activate | `guard_prepared`, `activation`, `verification_report` | `certbot_activated` | P1-12 |

Порядок `verified_payload → data/containers/guard` внутри stage задаёт
оркестратор P1-11. Потоки получают `StageContext` (request, plan, receipts,
journal) и не пишут состояние job напрямую.

## 7. Доказательства cutover

`evaluate_cutover` требует **обе** части:

- **Машинное наблюдение** (`source_observation`). Оно получено по `ssh_pinned_host_key`
  от записанной идентичности source (не от target), с полным probe. Каждый включённый
  контейнер присутствует со статусом `running: false` (`null` означает «неизвестно» и
  отклоняется) или отсутствует. Fencing обеспечивается одним из двух способов: `docker.service` и
  `docker.socket` в состоянии masked+inactive, либо `restart_policy: "no"` у всех контейнеров.
- **Решение оператора** (`cutover_attestation`). Оно привязано к job и plan identity,
  содержит `cutover_permitted` и отдельное подтверждение независимого канала управления.

**Решение владельца (2026-09-23):** оба метода fencing допустимы, включая
`restart_policy: "no"` без маскировки Docker.

Свежесть: возраст не больше `max_evidence_age_seconds` из плана (по умолчанию 300 с —
утверждено владельцем; допустимо 60–900); запись из будущего допускается максимум на 60 с. Если source
недоступен, наблюдения нет и выдаётся `E_PRECONDITION`. Автоматических действий над source
нет: `automatic_source_actions` всегда пуст, это закреплено в схеме.

## 8. Диагностика

`build_verification_report` разделяет машинные и ручные проверки. Если машинной проверки
нет, её статус `unknown`. Ручные проверки (модель, Telegram, ACME) имеют статус `not_run` и не
могут получить `passed` от машины. Неизвестные проверки отклоняются. Итог `passed`
ставится только при прохождении всех обязательных машинных проверок, в том числе
`response_from_target`.

## 9. Матрица ОС

| platform_id | ОС | arch | Docker | Installer |
| --- | --- | --- | --- | --- |
| `ubuntu-24.04-amd64` | Ubuntu 24.04 | x86_64 | docker-apt-repository | не подтверждён |

Остальные ОС получают `E_UNSUPPORTED`. `require_install_confirmed` отклоняет установку
пакетов, пока владелец не подтвердит выпуск (`install_confirmed: true`) и пока установка не пройдёт
проверку на Linux (P1-04/P1-15). **Решение владельца (2026-09-23):** поддерживается только
Ubuntu 24.04 x86_64, как на source; Debian не поддерживается.

## 10. Fixtures

`tests/restore_support.py` строит полный сценарий на реальной P0-копии
(`support.complete_backup`): backup identity, source record, target на другой
машине, план, request, journal, observation и attestation. Для противоречивых вариантов
есть `mutated`, `same_machine_target_facts` и параметры времени и fencing. Тесты
покрывают успешные, неполные (нет пинов, фактов, receipt, наблюдения) и
противоречивые (чужой backup, source=target, tamper, журнал, receipt) данные.

## Решения владельца (2026-09-23)

1. Source record: read-only чтение `request.json` исходной задачи (§2).
2. Матрица ОС: только Ubuntu 24.04 x86_64 (§9).
3. Fencing через `restart_policy: no` без маскировки Docker допустим (§7).
4. TTL доказательств cutover по умолчанию 300 с (§7).

Открытых архитектурных вопросов по P1-01 нет. Установка пакетов остаётся
заблокированной (`install_confirmed: false`), пока installer не проверен на Linux.
