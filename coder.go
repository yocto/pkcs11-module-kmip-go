package main

import "bytes"

// #include "cgo.h"
import "C"
import "encoding/binary"
import "reflect"
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
	info := C.CK_INFO{}

	var offset int

	pointerAsSliceDestination := unsafe.Slice((*byte)(unsafe.Pointer(&info.cryptokiVersion)), 2)
	copy(pointerAsSliceDestination, data[offset:(offset+2)])
	offset += 2

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&info.manufacturerID)), 32)
	copy(pointerAsSliceDestination, data[offset:(offset+32)])
	offset += 32

	info.flags = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&info.libraryDescription)), 32)
	copy(pointerAsSliceDestination, data[offset:(offset+32)])
	offset += 32

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&info.libraryVersion)), 2)
	copy(pointerAsSliceDestination, data[offset:(offset+2)])
	offset += 2

	return info
}

func DecodeSlotInfo(data []byte) C.CK_SLOT_INFO {
	slotInfo := C.CK_SLOT_INFO{}

	var offset int

	pointerAsSliceDestination := unsafe.Slice((*byte)(unsafe.Pointer(&slotInfo.slotDescription)), 64)
	copy(pointerAsSliceDestination, data[offset:(offset+64)])
	offset += 64

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&slotInfo.manufacturerID)), 32)
	copy(pointerAsSliceDestination, data[offset:(offset+32)])
	offset += 32

	slotInfo.flags = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&slotInfo.hardwareVersion)), 2)
	copy(pointerAsSliceDestination, data[offset:(offset+2)])
	offset += 2

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&slotInfo.firmwareVersion)), 2)
	copy(pointerAsSliceDestination, data[offset:(offset+2)])
	offset += 2

	return slotInfo
}

func DecodeTokenInfo(data []byte) C.CK_TOKEN_INFO {
	tokenInfo := C.CK_TOKEN_INFO{}

	var offset int

	pointerAsSliceDestination := unsafe.Slice((*byte)(unsafe.Pointer(&tokenInfo.label)), 32)
	copy(pointerAsSliceDestination, data[offset:(offset+32)])
	offset += 32

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&tokenInfo.manufacturerID)), 32)
	copy(pointerAsSliceDestination, data[offset:(offset+32)])
	offset += 32

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&tokenInfo.model)), 16)
	copy(pointerAsSliceDestination, data[offset:(offset+16)])
	offset += 16

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&tokenInfo.serialNumber)), 16)
	copy(pointerAsSliceDestination, data[offset:(offset+16)])
	offset += 16

	tokenInfo.flags = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulMaxSessionCount = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulSessionCount = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulMaxRwSessionCount = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulRwSessionCount = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulMaxPinLen = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulMinPinLen = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulTotalPublicMemory = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulFreePublicMemory = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulTotalPrivateMemory = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	tokenInfo.ulFreePrivateMemory = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&tokenInfo.hardwareVersion)), 2)
	copy(pointerAsSliceDestination, data[offset:(offset+2)])
	offset += 2

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&tokenInfo.firmwareVersion)), 2)
	copy(pointerAsSliceDestination, data[offset:(offset+2)])
	offset += 2

	pointerAsSliceDestination = unsafe.Slice((*byte)(unsafe.Pointer(&tokenInfo.utcTime)), 16)
	copy(pointerAsSliceDestination, data[offset:(offset+16)])
	offset += 16

	return tokenInfo
}

func DecodeSessionInfo(data []byte) C.CK_SESSION_INFO {
	sessionInfo := C.CK_SESSION_INFO{}

	var offset int

	sessionInfo.slotID = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	sessionInfo.state = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	sessionInfo.flags = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	sessionInfo.ulDeviceError = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	return sessionInfo
}

func DecodeMechanismInfo(data []byte) C.CK_MECHANISM_INFO {
	mechanismInfo := C.CK_MECHANISM_INFO{}

	var offset int

	mechanismInfo.ulMinKeySize = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	mechanismInfo.ulMaxKeySize = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	mechanismInfo.flags = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

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

func EncodeVoidPointerAsBytePointer(voidPointer C.CK_VOID_PTR, voidPointerLength C.CK_ULONG) []byte {
	return EncodeBytePointer(C.CK_BYTE_PTR(voidPointer), voidPointerLength)
}

func ConvertAttributeValue(attribute C.CK_ATTRIBUTE) any {
	if attribute.pValue == nil {
		return nil
	}
	// ---------------
	if attribute._type == C.CKA_CLASS {
		count := attribute.ulValueLen / C.sizeof_CK_OBJECT_CLASS
		return unsafe.Slice((*C.CK_OBJECT_CLASS)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_SENSITIVE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_CHECK_VALUE {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_ALLOWED_MECHANISMS {
		count := attribute.ulValueLen / C.sizeof_CK_MECHANISM_TYPE
		return unsafe.Slice((C.CK_MECHANISM_TYPE_PTR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_LABEL {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	// TODO: Fill all
	return nil
}

func EncodeAttribute(attribute C.CK_ATTRIBUTE, forceValueNil bool) []byte {
	attributeValue := ConvertAttributeValue(attribute)

	hasValue := bool(attribute.pValue != nil)
	hasLength := bool(attribute.ulValueLen != 0) // Assuming exact multiple

	if forceValueNil || !hasLength {
		hasValue = false
	}

	buffer := new(bytes.Buffer)
	buffer.Write(EncodeUnsignedLong(attribute._type))

	buffer.Write(EncodeByte(ConvertBooleanToByte(hasValue)))
	buffer.Write(EncodeByte(ConvertBooleanToByte(hasLength)))

	if hasLength && reflect.TypeOf(attributeValue).Kind() == reflect.Slice {
		buffer.Write(EncodeUnsignedLongAsLength(C.CK_ULONG(reflect.ValueOf(attributeValue).Len())))
	}

	if hasValue {
		buffer.Write(EncodeVoidPointerAsBytePointer(attribute.pValue, attribute.ulValueLen)[4:])
	}

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
	var checkValue [16]C.CK_BYTE

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

func getAttributeForTest4() C.CK_ATTRIBUTE {
	var label [42]C.CK_BYTE

	return C.CK_ATTRIBUTE{
		_type:      C.CKA_LABEL,
		pValue:     C.CK_VOID_PTR(&label),
		ulValueLen: C.CK_ULONG(unsafe.Sizeof(label)),
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
