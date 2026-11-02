#!/usr/bin/env bash
# Выпуск учебной PKI: корпоративный УЦ, сертификат шлюза, клиентские сертификаты
# администраторов и ключевая пара для подписи JWT. Ключи ECDSA P-256.
# В эксплуатации серверный сертификат выпускается в Yandex Certificate Manager,
# а закрытые ключи хранятся в Yandex Lockbox.
set -euo pipefail
# Git Bash / MSYS2 в Windows превращают "/CN=..." в путь C:/...; отключаем это преобразование
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")"
OUT=out; mkdir -p "$OUT"; cd "$OUT"
DAYS=365

# 1. Корневой сертификат корпоративного УЦ
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
# Расширения указаны явно: Python 3.13+ проверяет цепочку в строгом режиме (VERIFY_X509_STRICT)
printf "[req]\ndistinguished_name=dn\n[dn]\n[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n" > ca.cnf
openssl req -x509 -new -key ca.key -sha256 -days $DAYS -config ca.cnf -extensions v3 -subj "/CN=SAG Corporate CA" -out ca.crt

# 2. Сертификат шлюза (имена sag.local и localhost)
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=sag.local" -out server.csr
# EXTRA_SAN позволяет добавить внешний адрес балансировщика, например EXTRA_SAN=IP:51.250.1.2
SAN="DNS:sag.local,DNS:localhost,IP:127.0.0.1${EXTRA_SAN:+,$EXTRA_SAN}"
LEAF="basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
printf "${LEAF}subjectAltName=%s\nextendedKeyUsage=serverAuth\n" "$SAN" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days $DAYS -sha256 -extfile server.ext -out server.crt

# 3. Клиентские сертификаты администраторов, выпущенные корпоративным УЦ
for user in admin auditor; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$user.key"
  openssl req -new -key "$user.key" -subj "/CN=$user" -out "$user.csr"
  printf "${LEAF}extendedKeyUsage=clientAuth\n" > client.ext
  openssl x509 -req -in "$user.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days $DAYS -sha256 -extfile client.ext -out "$user.crt"
done

# 4. Самоподписанный сертификат нарушителя (не выпущен корпоративным УЦ)
openssl ecparam -name prime256v1 -genkey -noout -out intruder.key
openssl req -x509 -new -key intruder.key -sha256 -days $DAYS -subj "/CN=admin" -out intruder.crt

# 5. Ключевая пара учебного OIDC-провайдера для подписи JWT (RS256)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem

rm -f ./*.csr ./*.ext ./*.srl
echo "PKI готова: $(pwd)"
