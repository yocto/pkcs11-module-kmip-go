all:
	build
	install
	clean

build:
	if [ ! -d "./include" ];then chmod +x *.sh && ./download_headers.sh; fi
	mkdir -p bin
	go build --buildmode=c-shared -o bin/

install:
	cp bin/pkcs11-kmip /usr/lib/pkcs11/pkcs11-kmip.so
	chmod +x /usr/lib/pkcs11/pkcs11-kmip.so

clean:
	rm -Rf bin

.PHONY: all build install clean