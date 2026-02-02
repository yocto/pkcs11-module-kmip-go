all: clean build install

build:
	if [ ! -f "./include/pkcs11.h" ];then chmod +x *.sh && ./download_headers.sh; fi
	mkdir -p bin
	go build --buildmode=c-shared -o bin/

install:
	mkdir -p /usr/lib/pkcs11/
	cp bin/pkcs11-kmip /usr/lib/pkcs11/pkcs11-kmip.so
	chmod +x /usr/lib/pkcs11/pkcs11-kmip.so

clean:
	rm -Rf bin

.PHONY: all build install clean