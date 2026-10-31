package main

// #include "cgo.h"
import "C"

func dereferenceUnsignedLong(pul C.CK_ULONG_PTR) any {
	if pul == nil {
		return nil
	}
	return *pul
}
