# Задание 5 — бинарный API сигнатур

## Что реализовано

Добавлен отдельный бинарный API:

- `GET /api/binary/signatures/full` — полная бинарная выгрузка только `ACTUAL`;
- `GET /api/binary/signatures/increment?since=...` — инкрементальная бинарная выгрузка `updatedAt > since`, включая `DELETED`;
- `POST /api/binary/signatures/by-ids` — бинарная выгрузка по списку UUID.

Ответы возвращаются как `multipart/mixed` с двумя частями:

1. `manifest.bin`
2. `data.bin`

## Где код

- `com.security.serverbase.malware.binary.controller.BinarySignatureController` — endpoints;
- `com.security.serverbase.malware.binary.service.BinarySignatureExportService` — выборка записей и сборка пакета;
- `BinaryDataBuilder` — формирует `data.bin`;
- `BinaryManifestBuilder` — формирует `manifest.bin` и подписывает его;
- `BinaryPrimitiveWriter` — единый протокол записи типов в байты;
- `MultipartMixedResponseFactory` — формирует `multipart/mixed` ответ;
- `com.security.serverbase.signature.RawSignatureService` — новый метод ЭЦП для подписи готовых байтов.

## Протокол типов

Используется единый порядок байт BigEndian, потому что `DataOutputStream` пишет многобайтовые числа старшим байтом вперёд.

Типы:

- `uint8` — 1 байт;
- `uint16` — 2 байта, BigEndian;
- `uint32` — 4 байта, BigEndian;
- `int64` — 8 байт, BigEndian;
- `UUID` — два `int64`: mostSignificantBits + leastSignificantBits;
- `String` — `uint32 length` + UTF-8 bytes;
- `byte[]` — `uint32 length` + bytes.

## manifest.bin

Содержит:

- `magic = MF-ROSST`;
- `version`;
- `exportType`: `1 = FULL`, `2 = INCREMENT`, `3 = BY_IDS`;
- `generatedAtEpochMillis`;
- `sinceEpochMillis`, для full/by-ids = `-1`;
- `recordCount`;
- `dataSha256`, SHA-256 от всего `data.bin`;
- массив `ManifestEntry[recordCount]`;
- подпись манифеста.

Одна запись манифеста содержит:

- `id`;
- `statusCode`: `1 = ACTUAL`, `2 = DELETED`;
- `updatedAtEpochMillis`;
- `dataOffset`;
- `dataLength`;
- `recordSignatureLength`;
- `recordSignatureBytes`.

Важно: подписи записей не пересчитываются в binary API. В манифест кладётся уже существующая подпись из `digitalSignatureBase64`.

## data.bin

Содержит:

- `magic = DB-ROSST`;
- `version`;
- `recordCount`;
- массив бинарных записей.

Одна запись `data.bin` содержит:

- `threatName` как UTF-8 строка;
- `firstBytes`, декодированные из `firstBytesHex`;
- `remainderHash`, декодированный из `remainderHashHex`;
- `remainderLength`;
- `fileType` как UTF-8 строка;
- `offsetStart`;
- `offsetEnd`.

`id`, `status`, `updatedAt` и `digitalSignatureBase64` не лежат в `data.bin`, потому что они находятся в манифесте.

## Что говорить на защите

> В 5 задании я добавил отдельный бинарный API для передачи сигнатур. Он не заменяет обычный JSON CRUD, а отдаёт клиенту бинарный пакет `multipart/mixed` из двух частей: `manifest.bin` и `data.bin`. `data.bin` хранит полезную нагрузку сигнатур, а `manifest.bin` хранит id, статус, updatedAt, смещения в data.bin, подписи записей, SHA-256 данных и подпись самого манифеста. Для подписи манифеста я добавил метод в ЭЦП-модуль, который подписывает уже готовый массив байт.

## Важно

Если преподаватель требует именно твою фамилию в `magic`, поменяй константы в:

`BinaryProtocolConstants`

- `MF-ROSST`
- `DB-ROSST`

на свою фамилию.
