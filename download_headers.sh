#!/usr/bin/env bash

#BASE_URL=https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/include/pkcs11-v3.0/
BASE_URL=https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/include/pkcs11-v3.1/

wget -P include ${BASE_URL}pkcs11.h
wget -P include ${BASE_URL}pkcs11f.h
wget -P include ${BASE_URL}pkcs11t.h