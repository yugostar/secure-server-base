# Задание 3. Модуль ЭЦП — что показывать на защите

## Что сделано
1. В проект добавлен модуль подписи (`signature`).
2. Приватный ключ и публичный сертификат берутся из `secure-server-keystore.p12`.
3. Публичный сертификат нужно положить в GitHub Variables как `SIGNATURE_PUBLIC_CERT_B64`.
4. Подпись формируется сервисом `TicketSignatureService`.
5. Подпись подключена к ответам лицензии (`activate`, `check`, `renew`).
6. Корректность подписи проверяется тестом `TicketSignatureServiceTest`.

## Какие классы объяснять
- `SignatureProperties` — хранит настройки.
- `SignatureKeyStoreService` — загружает приватный и публичный ключ из keystore и кэширует их.
- `JsonCanonicalizer` — приводит объект `Ticket` к детерминированному JSON и переводит его в UTF-8 байты.
- `TicketSignatureService` — подписывает эти байты алгоритмом `SHA256withRSA` и возвращает Base64.
- `LicenseService` — вызывает подпись и кладет результат в `TicketResponse`.

## Как формируется подпись
1. Создается `Ticket`.
2. `JsonCanonicalizer` делает канонический JSON.
3. JSON переводится в UTF-8 байты.
4. `TicketSignatureService` подписывает байты приватным ключом.
5. Подпись кодируется в Base64.
6. Клиент получает `ticket` и `signature`.

## Что показать преподавателю
### Пункт 2. Keystore
Файл: `secure-server-keystore.p12`

### Пункт 4. Компоненты модуля ЭЦП
Показать классы из пакета `signature` и `TicketSignatureService`.

### Пункт 5. Подключение к лицензии
Метод `buildSignedTicketResponse(...)` в `LicenseService`.

### Пункт 6. Корректность подписи
Тест: `src/test/java/com/security/serverbase/license/service/TicketSignatureServiceTest.java`

## Как получить публичный сертификат для GitHub Variables
Пример команды:

```bash
keytool -exportcert -rfc -alias secure-server -keystore secure-server-keystore.p12 -storetype PKCS12 -storepass changeit | base64 -w 0
```

Полученную строку положить в GitHub Variable:
- `SIGNATURE_PUBLIC_CERT_B64`

## Какие secrets/variables нужны в GitHub
### Secrets
- `SIGNATURE_KEYSTORE_B64`
- `SIGNATURE_KEYSTORE_PASSWORD`

### Variables
- `SIGNATURE_KEY_ALIAS`
- `SIGNATURE_PUBLIC_CERT_B64`
