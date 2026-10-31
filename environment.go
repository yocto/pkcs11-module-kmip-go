package main

import "os"
import "strconv"

func getDebugMode() int {
	env_debug, err := strconv.Atoi(os.Getenv("PKCS11_DEBUG"))
	if err != nil {
		return 0
	}
	return env_debug
}

func getKMIPServer() string {
	return os.Getenv("PKCS11_KMIP_SERVER")
}
