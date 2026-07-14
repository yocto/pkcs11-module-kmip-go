package main

import "unsafe"

func arrayToPointer[ArbitraryType any](slice []ArbitraryType) *ArbitraryType {
	return unsafe.SliceData(slice)
}

func getNativePointer[ArbitraryType any](value *ArbitraryType) unsafe.Pointer {
	return unsafe.Pointer(value)
}

func getSizeOf[ArbitraryType any](x ArbitraryType) uint {
	return uint(unsafe.Sizeof(x))
}

func pointerToArray[ArbitraryType any](ptr *ArbitraryType, len uint) []ArbitraryType {
	if ptr == nil {
		return nil
	}
	return unsafe.Slice(ptr, len)
}
