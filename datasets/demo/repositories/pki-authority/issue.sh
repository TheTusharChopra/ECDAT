#!/bin/sh
# Issue a server certificate from the intermediate CA.
set -eu
openssl req -new -newkey rsa:3072 -nodes -keyout "$1.key" -out "$1.csr" -subj "$2"
openssl x509 -req -in "$1.csr" -CA intermediate-ca.crt -CAkey intermediate-ca.key \
    -sha384 -days 730 -out "$1.crt"
