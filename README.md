# PKCS#11 KMIP Module

[![Go](https://github.com/yocto/pkcs11-module-kmip-go/actions/workflows/go.yml/badge.svg)](https://github.com/yocto/pkcs11-module-kmip-go/actions/workflows/go.yml)

A PKCS#11 module which connects to a KMIP server.

## Build

To build this module, you just run:

```shell
make build
```

Note: Because of Cgo, `gcc` is expected to be installed.