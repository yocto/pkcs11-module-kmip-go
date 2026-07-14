package main

import "unsafe"

func arrayToPointer[ArbitraryType any](slice []ArbitraryType) *ArbitraryType {
	return unsafe.SliceData(slice)
}

func copyIntoField(source []byte, destination any) int {
	len := len(source)
	ptr := unsafe.Pointer(destination.(*any))
	slice := pointerToArray((*byte)(ptr), uint(len))
	copy(slice, source)
	return len
}

func pointerToArray[ArbitraryType any](ptr *ArbitraryType, len uint) []ArbitraryType {
	return unsafe.Slice(ptr, len)
}

func getSizeOf[ArbitraryType any](x ArbitraryType) uint {
	return uint(unsafe.Sizeof(x))
}
