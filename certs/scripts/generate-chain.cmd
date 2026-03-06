@echo off
setlocal enabledelayedexpansion

REM Lab 6: generate certificate chain (3 links)
REM Root CA -> Intermediate CA -> Server cert (localhost)
REM Требование: идентификатор студента должен быть в сертификатах.
REM Передайте STUDENT_ID=... (номер студенческого билета)
REM Example:
REM   set STUDENT_ID=123456
REM   certs\scripts\generate-chain.cmd

if "%STUDENT_ID%"=="" (
  echo ERROR: STUDENT_ID env is required (номер студенческого билета)
  exit /b 1
)

set OUT_DIR=certs\out
set CFG=certs\config\openssl.cnf
if not exist %OUT_DIR% mkdir %OUT_DIR%

REM уникальные имена (не как в примере)
set ROOT_NAME=rs-root-ca
set INT_NAME=rs-intermediate-ca
set SRV_NAME=rs-secure-server-server

set ROOT_KEY=%OUT_DIR%\%ROOT_NAME%.key
set ROOT_CRT=%OUT_DIR%\%ROOT_NAME%.crt

set INT_KEY=%OUT_DIR%\%INT_NAME%.key
set INT_CSR=%OUT_DIR%\%INT_NAME%.csr
set INT_CRT=%OUT_DIR%\%INT_NAME%.crt

set SRV_KEY=%OUT_DIR%\%SRV_NAME%.key
set SRV_CSR=%OUT_DIR%\%SRV_NAME%.csr
set SRV_CRT=%OUT_DIR%\%SRV_NAME%.crt

set CHAIN_PEM=%OUT_DIR%\%SRV_NAME%-chain.pem
set TRUST_PEM=%OUT_DIR%\%ROOT_NAME%-trust.pem

set P12=%OUT_DIR%\rs-secure-server-keystore.p12
if "%KEYSTORE_PASSWORD%"=="" (set P12_PASS=changeit) else (set P12_PASS=%KEYSTORE_PASSWORD%)
if "%KEYSTORE_ALIAS%"=="" (set P12_ALIAS=rs-secure-server) else (set P12_ALIAS=%KEYSTORE_ALIAS%)

echo Generating Root CA...
openssl genrsa -out "%ROOT_KEY%" 4096
openssl req -x509 -new -nodes -key "%ROOT_KEY%" -sha256 -days 3650 ^
  -subj "/C=RU/O=RS Secure Server/CN=RS Root CA/serialNumber=%STUDENT_ID%" ^
  -extensions v3_root_ca -config "%CFG%" ^
  -out "%ROOT_CRT%"

echo Generating Intermediate CA...
openssl genrsa -out "%INT_KEY%" 4096
openssl req -new -key "%INT_KEY%" ^
  -subj "/C=RU/O=RS Secure Server/CN=RS Intermediate CA/serialNumber=%STUDENT_ID%" ^
  -out "%INT_CSR%"
openssl x509 -req -in "%INT_CSR%" -CA "%ROOT_CRT%" -CAkey "%ROOT_KEY%" -CAcreateserial ^
  -out "%INT_CRT%" -days 1825 -sha256 -extfile "%CFG%" -extensions v3_intermediate_ca

echo Generating Server certificate for localhost...
openssl genrsa -out "%SRV_KEY%" 2048
openssl req -new -key "%SRV_KEY%" ^
  -subj "/C=RU/O=RS Secure Server/CN=localhost/serialNumber=%STUDENT_ID%" ^
  -out "%SRV_CSR%"
openssl x509 -req -in "%SRV_CSR%" -CA "%INT_CRT%" -CAkey "%INT_KEY%" -CAcreateserial ^
  -out "%SRV_CRT%" -days 825 -sha256 -extfile "%CFG%" -extensions v3_server

echo Building chain (server + intermediate + root)...
copy /b "%SRV_CRT%"+"%INT_CRT%"+"%ROOT_CRT%" "%CHAIN_PEM%" >nul
copy "%ROOT_CRT%" "%TRUST_PEM%" >nul

echo Creating PKCS12 keystore (NOT committed to git)...
type "%INT_CRT%" "%ROOT_CRT%" > "%OUT_DIR%\chain.tmp.pem"
openssl pkcs12 -export -out "%P12%" -inkey "%SRV_KEY%" -in "%SRV_CRT%" ^
  -certfile "%OUT_DIR%\chain.tmp.pem" -name "%P12_ALIAS%" -passout pass:%P12_PASS%
del "%OUT_DIR%\chain.tmp.pem" >nul 2>&1

echo.
echo DONE.
echo Keystore: %P12% (password from KEYSTORE_PASSWORD or default 'changeit')
echo Trust root: %TRUST_PEM%
echo.
echo To run HTTPS (in IntelliJ Run Configuration - Environment variables):
echo   SSL_ENABLED=true
echo   SERVER_PORT=8443
echo   SSL_KEYSTORE_PATH=%CD%\%P12%
echo   SSL_KEYSTORE_PASSWORD=%P12_PASS%
endlocal
