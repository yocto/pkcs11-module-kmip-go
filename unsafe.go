package main

import "unsafe"

func copyIntoField(source []byte, destination any) int {
	len := len(source)
	ptr := unsafe.Pointer(destination.(*any))
	slice := unsafe.Slice((*byte)(ptr), len)
	copy(slice, source)
	return len
}

func getSizeOf[ArbitraryType any](x ArbitraryType) uintptr {
	return unsafe.Sizeof(x)
}
