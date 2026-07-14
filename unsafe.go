package main

import "unsafe"

func copyIntoField(source []byte, destination any) int {
	len := len(source)
	ptr := unsafe.Pointer(destination.(*any))
	slice := unsafe.Slice((*byte)(ptr), len)
	copy(slice, source)
	return len
}
