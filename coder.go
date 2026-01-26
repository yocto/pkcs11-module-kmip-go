package main

import "bytes"

// #include "cgo.h"
import "C"
import "encoding/binary"
import "unsafe"

func ConvertBooleanToByte(boolean bool) C.CK_BYTE {
	if boolean {
		return 0x01
	}
	return 0x00
}

func EncodeByte(_byte C.CK_BYTE) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, byte(_byte))
	return buffer.Bytes()
}

func EncodeUnsignedLong(ulong C.CK_ULONG) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, uint64(ulong))
	return buffer.Bytes()
}

func EncodeUnsignedLongAsLength(ulong C.CK_ULONG) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, uint32(ulong))
	return buffer.Bytes()
}

func EncodeLong(long C.CK_LONG) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, int64(long))
	return buffer.Bytes()
}

func EncodeMechanism(mechanism C.CK_MECHANISM) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, uint64(mechanism.mechanism))
	binary.Write(buffer, binary.BigEndian, bool(mechanism.pParameter != nil))
	if bool(mechanism.pParameter != nil) {
		binary.Write(buffer, binary.BigEndian, uint32(mechanism.ulParameterLen)+4)
		//TODO: Detect if string. If yes: length prepend (and +4 in above), if not, just object.
		binary.Write(buffer, binary.BigEndian, uint32(mechanism.ulParameterLen))
		binary.Write(buffer, binary.BigEndian, unsafe.Slice((*byte)(mechanism.pParameter), mechanism.ulParameterLen))
	}
	return buffer.Bytes()
}

// Test helper functions (because CGO cannot be directly used in tests)

func getByteForTest() C.CK_BYTE {
	return C.CK_BYTE(0x01)
}

func getUnsignedLongForTest() C.CK_ULONG {
	return C.CK_ULONG(0x7E7F8081)
}

func getLongForTest() C.CK_LONG {
	return C.CK_LONG(-0x7E7F8081)
}

func getMechanismForTest() C.CK_MECHANISM {
	var iv []C.CK_BYTE = []C.CK_BYTE{1, 2, 3, 4, 5, 6, 7, 8}

	return C.CK_MECHANISM{
		mechanism:      C.CKM_DES_CBC_PAD,
		pParameter:     C.CK_VOID_PTR(unsafe.SliceData(iv)),
		ulParameterLen: C.CK_ULONG(len(iv)),
	}
}
