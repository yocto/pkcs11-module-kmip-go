package main

import "unsafe"

func copyIntoField(source []byte, destination any) int {
	len := len(source)
	ptr := unsafe.Pointer(destination.(*any))
	slice := unsafe.Slice((*byte)(ptr), len)
	copy(slice, source)
	return len
}

func pointerToArray[ArbitraryType any](ptr *ArbitraryType, len uint) []ArbitraryType {
	return unsafe.Slice(ptr, len)
}

func getSizeOf[ArbitraryType any](x ArbitraryType) uintptr {
	return unsafe.Sizeof(x)
}
