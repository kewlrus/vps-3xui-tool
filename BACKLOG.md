# Backlog vps3xui

[Общие условия, контракты, критерии приёмки и отложенные направления](backlog/GUIDE.md).

## P1: порядок реализации

Задача начинается после приёмки её зависимостей. Задачи одной параллельной группы
можно выполнять независимо; изменение одной VPS остаётся последовательным.

| Задача | Когда выполнять |
| --- | --- |
| [P1-01 — Контракты restore и среда](backlog/P1-01.md) | **DONE-LOCAL** 2026-09-23 |
| [P1-02 — Target-job и журнал эффектов](backlog/P1-02.md) | **DONE-LOCAL** 2026-09-23 |
| [P1-03 — Target probe и restore plan](backlog/P1-03.md) | **READY**; параллельно P1-02–P1-10 |
| [P1-04 — Prepare: зависимости ОС](backlog/P1-04.md) | **READY**; параллельно P1-02–P1-10 |
| [P1-05 — Передача и staging backup](backlog/P1-05.md) | **READY**; параллельно P1-02–P1-10 |
| [P1-06 — Bind trees и volumes](backlog/P1-06.md) | **READY**; параллельно P1-02–P1-10 |
| [P1-07 — Images, Compose и Fail2ban](backlog/P1-07.md) | **READY**; параллельно P1-02–P1-10 |
| [P1-08 — Подготовка Certbot guard](backlog/P1-08.md) | **READY**; параллельно P1-02–P1-10 |
| [P1-09 — Activate и защита OAuth](backlog/P1-09.md) | **READY**; параллельно P1-02–P1-10 |
| [P1-10 — Пассивная restore verify](backlog/P1-10.md) | **READY**; параллельно P1-02–P1-10 |
| [P1-11 — Оркестрация prepare/stage](backlog/P1-11.md) | P1-03–P1-08 (P1-02 выполнена); параллельно P1-12 |
| [P1-12 — Certbot activate](backlog/P1-12.md) | P1-08–P1-10 (P1-02 выполнена); параллельно P1-11 |
| [P1-13 — CLI, SSH и release](backlog/P1-13.md) | P1-03, P1-04, P1-09–P1-12 |
| [P1-14 — Локальная приёмка и security review](backlog/P1-14.md) | P1-13 |
| [P1-15 — Linux restore drill P1](backlog/P1-15.md) | P1-14, P0-A01; Linux-среда и OPS-02 |
| [P1-16 — Документация и выпускная приёмка](backlog/P1-16.md) | Подготовка после P1-14; завершение после P1-15 |

## Внешние задачи: независимо от локальной разработки

- [P0-A01 — Реальный drill P0](backlog/P0-A01.md): при появлении согласованной среды; до полной приёмки P0 и P1-15.
- [OPS-01 — Production-инвентарь](backlog/OPS-01.md): до готовности конкретной VPS к эксплуатации.
- [OPS-02 — Доверенный Certbot guard/hooks](backlog/OPS-02.md): до реальной приёмки Certbot и P1-15; локальные P1-08/12 используют fixtures.

## P0: выполнено локально

- [P0-01 — Строгий manifest, read-only inspect/probe, выявление drift и неизвестных schedulers](backlog/P0-01.md)
- [P0-02 — План с TTL, host key, machine-id, версиями и digest входных фактов](backlog/P0-02.md)
- [P0-03 — Request ID, durable state, lock, повторная отправка, блокировка незавершённых задач](backlog/P0-03.md)
- [P0-04 — Автономный backup, Certbot lease/race, исходные container IDs, finalizer/recover](backlog/P0-04.md)
- [P0-05 — Точный набор архивов/metadata, SHA256SUMS, безопасные ссылки и согласованный COMPLETE](backlog/P0-05.md)
- [P0-06 — Source/local verify, новый клиент без истории, контролируемый fetch](backlog/P0-06.md)
- [P0-07 — JSON, стабильные ошибки, отсутствие секретов в выводе](backlog/P0-07.md)
- [P0-08 — Исполняемая синтетическая процедура restore drill](backlog/P0-08.md)
