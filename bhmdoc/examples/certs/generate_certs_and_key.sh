#!/usr/bin/env bash

# This script generates keys and certificates for use with the example code.
# Pre-requisites:
# - `openssl` CLI tool must be installed

# generate root
echo "Generating root certificate..."
openssl ecparam -genkey -name secp256r1 -out root.key
openssl req -new -key root.key -out root.csr -sha256 \
    --subj "/C=HR/ST=Grad Zagreb/L=Zagreb/O=TBTL/OU=Team Bee/CN=root"
openssl x509 -req -days 36500 -in root.csr -signkey root.key \
    -out root.crt -extensions v3_ca -extfile root.config

# generate intermediary
echo "Generating intermediary certificate..."
openssl ecparam -genkey -name secp256r1 -out intermediary.key
openssl req -new -key intermediary.key -out intermediary.csr -sha256 \
    --subj "/C=HR/ST=Grad Zagreb/L=Zagreb/O=TBTL/OU=Team Bee/CN=intermediary"
openssl x509 -req -in intermediary.csr -CA root.crt -CAkey root.key \
    -out intermediary.crt -days 36500 -sha256 -extensions v3_intermediate_ca \
    -extfile mid.config
