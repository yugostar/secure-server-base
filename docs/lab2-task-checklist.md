# Проверка выполнения задания №2

## 1. Структура таблиц и связей по ER-диаграмме
Реализованы сущности и таблицы:
- `users`
- `product`
- `license_type`
- `license`
- `device`
- `device_license`
- `license_history`
- `user_sessions`

Связи реализованы через `@ManyToOne` и внешние ключи в таблицах.

## 2. Операция создания лицензии
Реализована в `LicenseService#createLicense` и вызывается из `POST /api/licenses`.

## 3. Операция активации лицензии
Реализована в `LicenseService#activateLicense` и вызывается из `POST /api/licenses/activate`.

## 4. Операция проверки лицензии
Реализована в `LicenseService#checkLicense` и вызывается из `POST /api/licenses/check`.

## 5. Операция продления лицензии
Реализована в `LicenseService#renewLicense` и вызывается из `POST /api/licenses/renew`.

## 6. Класс Ticket
Реализован в `license/dto/Ticket.java`.
Содержит:
- текущую дату сервера
- время жизни тикета
- дату активации лицензии
- дату истечения лицензии
- идентификатор пользователя
- идентификатор устройства
- флаг блокировки лицензии

## 7. Класс TicketResponse
Реализован в `license/dto/TicketResponse.java`.
Содержит:
- `ticket`
- `signature`

Подпись формируется в `TicketSignatureService` по алгоритму `SHA256withRSA`.
