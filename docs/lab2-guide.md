# Лабораторная работа №2 — модуль управления лицензиями

## Что реализовано

### 1. Таблицы и связи по ER-диаграмме
В проект добавлены сущности и таблицы:
- `users`
- `product`
- `license_type`
- `license`
- `device`
- `device_license`
- `license_history`
- `user_sessions`

### 2. Создание лицензии
`POST /api/licenses`
- доступно только `ADMIN`
- проверяет продукт, тип лицензии и владельца
- создаёт лицензию с уникальным кодом
- пишет запись в `license_history` со статусом `CREATED`

### 3. Активация лицензии
`POST /api/licenses/activate`
- ищет лицензию по коду
- привязывает лицензию к пользователю при первой активации
- создаёт устройство по MAC, если его ещё нет
- создаёт связь в `device_license`
- пишет историю `ACTIVATED`
- возвращает `TicketResponse`

### 4. Проверка лицензии
`POST /api/licenses/check`
- ищет устройство по MAC
- ищет активную лицензию пользователя на это устройство и продукт
- возвращает `TicketResponse`

### 5. Продление лицензии
`POST /api/licenses/renew`
- ищет лицензию по коду
- разрешает продление, если лицензия уже истекла или истечёт в течение 7 дней
- продлевает `endingDate` на `defaultDurationInDays`
- пишет историю `RENEWED`
- возвращает `TicketResponse`

### 6. Ticket
Поля `Ticket`:
- текущая дата сервера
- время жизни тикета
- дата активации лицензии
- дата истечения лицензии
- идентификатор пользователя
- идентификатор устройства
- флаг блокировки лицензии

### 7. TicketResponse
Поля `TicketResponse`:
- `ticket`
- `signature`

Подпись формируется в `TicketSignatureService` по алгоритму `SHA256withRSA`.
Если SSL keystore настроен, используется его закрытый ключ. Если нет — при старте создаётся временная RSA-пара, чтобы проект всё равно запускался и тестировался.

## Полезные endpoint'ы для демонстрации
- `GET /api/admin/catalog/products`
- `GET /api/admin/catalog/license-types`
- `POST /api/licenses`
- `POST /api/licenses/activate`
- `POST /api/licenses/check`
- `POST /api/licenses/renew`

## Что показать на защите
1. Таблицы в PostgreSQL.
2. Создание лицензии администратором.
3. Активацию лицензии пользователем.
4. Проверку лицензии по MAC и productId.
5. Продление лицензии.
6. Объект `TicketResponse` с полями тикета и подписью.


## Примечание по безопасности API
Для REST API используется JWT Bearer-authentication и stateless-конфигурация Spring Security, поэтому CSRF в `SecurityConfig` отключён. Для демонстрации достаточно отправлять Bearer-токен в заголовке `Authorization`.
