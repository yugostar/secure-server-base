# Лаба 4 — модуль антивирусных сигнатур

## Что реализовано

Модуль находится в пакете:

`src/main/java/com/security/serverbase/malware`

### Модели / таблицы

- `MalwareSignature` → таблица `signatures`, текущее состояние сигнатуры.
- `MalwareSignatureHistory` → таблица `signatures_history`, прошлые версии перед update/delete.
- `MalwareSignatureAudit` → таблица `signatures_audit`, журнал действий create/update/delete.
- `SignatureStatus` → статусы `ACTUAL` и `DELETED`.

### Операции API

Базовый путь: `/api/signatures`

1. `GET /api/signatures` — полная база, только `ACTUAL`.
2. `GET /api/signatures/increment?since=...` — изменения после времени `since`, включая `DELETED`.
3. `POST /api/signatures/by-ids` — получение записей по списку UUID.
4. `POST /api/signatures` — создание сигнатуры, только ADMIN.
5. `PUT /api/signatures/{id}` — обновление сигнатуры, только ADMIN.
6. `DELETE /api/signatures/{id}` — логическое удаление, только ADMIN.
7. `GET /api/signatures/{id}/history` — история по signatureId, только ADMIN.
8. `GET /api/signatures/{id}/audit` — аудит по signatureId, только ADMIN.

### ЭЦП

Подпись сигнатуры формируется в `MalwareSignatureSigningService`.

В подпись включаются только поля:

- `threatName`
- `firstBytesHex`
- `remainderHashHex`
- `remainderLength`
- `fileType`
- `offsetStart`
- `offsetEnd`
- `status`

`updatedAt` и `digitalSignatureBase64` в подпись не включаются.

### Где создаётся подпись

`MalwareSignatureService`:

- при `create` формируется подпись новой записи;
- при `update` старая версия уходит в history, потом поля меняются и подпись пересчитывается;
- при `delete` старая версия уходит в history, статус меняется на `DELETED`, подпись пересчитывается.

### Тест

`src/test/java/com/security/serverbase/malware/MalwareSignatureFlowIntegrationTest.java`

Проверяет:

- создание сигнатуры;
- получение полной базы;
- получение по ids;
- обновление и пересчёт подписи;
- логическое удаление;
- отсутствие `DELETED` в полной базе;
- наличие `DELETED` в инкременте;
- записи history после update/delete;
- записи audit после create/update/delete.
