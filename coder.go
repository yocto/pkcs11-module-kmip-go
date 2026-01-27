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

func DecodeUnsignedLong(data []byte) C.CK_ULONG {
	var ulong uint64

	buffer := bytes.NewBuffer(data)
	binary.Read(buffer, binary.BigEndian, &ulong)

	return C.CK_ULONG(ulong)
}

func DecodeUnsignedLongAsLength(data []byte) C.CK_ULONG {
	var ulong uint32

	buffer := bytes.NewBuffer(data)
	binary.Read(buffer, binary.BigEndian, &ulong)

	return C.CK_ULONG(ulong)
}

func DecodeInfo(data []byte) C.CK_INFO {
	info := C.CK_INFO{
		//TODO Decode
	}

	return info
}

func DecodeSlotInfo(data []byte) C.CK_SLOT_INFO {
	slotInfo := C.CK_SLOT_INFO{
		//TODO Decode
	}

	return slotInfo
}

func DecodeTokenInfo(data []byte) C.CK_TOKEN_INFO {
	tokenInfo := C.CK_TOKEN_INFO{
		//TODO Decode
	}

	return tokenInfo
}

func DecodeSessionInfo(data []byte) C.CK_SESSION_INFO {
	sessionInfo := C.CK_SESSION_INFO{
		//TODO Decode
	}

	return sessionInfo
}

func DecodeMechanismInfo(data []byte) C.CK_MECHANISM_INFO {
	mechanismInfo := C.CK_MECHANISM_INFO{
		//TODO Decode
	}

	return mechanismInfo
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

func EncodeBytePointer(bytePointer C.CK_BYTE_PTR, bytePointerLength C.CK_ULONG) []byte {
	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeUnsignedLongAsLength(bytePointerLength)) // Moved up
	for _, _byte := range unsafe.Slice(bytePointer, bytePointerLength) {
		inBuffer.Write(EncodeByte(_byte))
	}
	// Length field originally placed here, but "moved up" before variable byte pointer array.
	return inBuffer.Bytes()
}

func EncodeAttribute(attribute C.CK_ATTRIBUTE, isRequest bool) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, uint64(attribute._type))
	binary.Write(buffer, binary.BigEndian, bool(attribute.pValue != nil && !isRequest))
	binary.Write(buffer, binary.BigEndian, bool(attribute.ulValueLen != 0))
	// TODO Something with values and requests/responses
	return buffer.Bytes()
}

func EncodeMechanism(mechanism C.CK_MECHANISM) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, uint64(mechanism.mechanism))
	binary.Write(buffer, binary.BigEndian, bool(mechanism.pParameter != nil))
	if bool(mechanism.pParameter != nil) {
		binary.Write(buffer, binary.BigEndian, uint32(mechanism.ulParameterLen)+4)
		// TODO: Detect if string. If yes: length prepend (and +4 in above), if not, just object.
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

func getAttributeForTest1() C.CK_ATTRIBUTE {
	var sensitive C.CK_BYTE

	return C.CK_ATTRIBUTE{
		_type:      C.CKA_SENSITIVE,
		pValue:     C.CK_VOID_PTR(&sensitive),
		ulValueLen: C.CK_ULONG(unsafe.Sizeof(sensitive)),
	}
}

func getAttributeForTest2() C.CK_ATTRIBUTE {
	var checkValue [16]C.CK_BYTE_PTR

	return C.CK_ATTRIBUTE{
		_type:      C.CKA_CHECK_VALUE,
		pValue:     C.CK_VOID_PTR(&checkValue),
		ulValueLen: C.CK_ULONG(unsafe.Sizeof(checkValue)),
	}
}

func getAttributeForTest3() C.CK_ATTRIBUTE {
	var mechanisms [64]C.CK_MECHANISM_TYPE

	return C.CK_ATTRIBUTE{
		_type:      C.CKA_ALLOWED_MECHANISMS,
		pValue:     C.CK_VOID_PTR(&mechanisms),
		ulValueLen: C.CK_ULONG(unsafe.Sizeof(mechanisms)),
	}
}

func getMechanismForTest() C.CK_MECHANISM {
	var iv []C.CK_BYTE = []C.CK_BYTE{1, 2, 3, 4, 5, 6, 7, 8}

	return C.CK_MECHANISM{
		mechanism:      C.CKM_DES_CBC_PAD,
		pParameter:     C.CK_VOID_PTR(unsafe.SliceData(iv)),
		ulParameterLen: C.CK_ULONG(len(iv)),
	}
}
