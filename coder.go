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

func DecodeByte(data []byte) C.CK_BYTE {
	var _byte byte

	buffer := bytes.NewBuffer(data)
	binary.Read(buffer, binary.BigEndian, &_byte)

	return C.CK_BYTE(_byte)
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

func CalculateAttributeSize(data []byte) int {
	_type := DecodeUnsignedLong(data[0:8])
	hasValue := DecodeByte(data[8:9])
	hasLength := DecodeByte(data[9:10])

	var lengthSize int
	var valueSize int

	if _type == C.CKA_CLASS {
		lengthSize = 0
		valueSize = 8
	}
	if _type == C.CKA_KEY_TYPE {
		lengthSize = 0
		valueSize = 8
	}
	if _type == C.CKA_COPYABLE {
		lengthSize = 0
		valueSize = 1
	}
	if _type == C.CKA_TOKEN {
		lengthSize = 0
		valueSize = 1
	}
	// TODO: Do for all attribute types

	totalSize := 10
	if hasLength != 0x00 {
		totalSize += lengthSize
	}
	if hasValue != 0x00 {
		totalSize += valueSize
	}
	return totalSize
}

func DecodeAttribute(data []byte) C.CK_ATTRIBUTE {
	attribute := C.CK_ATTRIBUTE{}

	var offset int

	attribute._type = DecodeUnsignedLong(data[offset:(offset + 8)])
	offset += 8

	if attribute._type == C.CKA_CLASS {
		attribute.pValue = C.CK_VOID_PTR(unsafe.SliceData(data[8:]))
		attribute.ulValueLen = 8
	}

	if attribute._type == C.CKA_KEY_TYPE {
		attribute.pValue = C.CK_VOID_PTR(unsafe.SliceData(data[8:]))
		attribute.ulValueLen = 8
	}

	if attribute._type == C.CKA_COPYABLE {
		attribute.pValue = C.CK_VOID_PTR(unsafe.SliceData(data[8:]))
		attribute.ulValueLen = 1
	}

	if attribute._type == C.CKA_TOKEN {
		attribute.pValue = C.CK_VOID_PTR(unsafe.SliceData(data[8:]))
		attribute.ulValueLen = 1
	}

	return attribute
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
	if attribute._type == C.CKA_TOKEN {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_PRIVATE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_LABEL {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_UNIQUE_ID {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_APPLICATION {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_APPLICATION {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_OBJECT_ID {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_CERTIFICATE_TYPE {
		count := attribute.ulValueLen / C.sizeof_CK_CERTIFICATE_TYPE
		return unsafe.Slice((*C.CK_CERTIFICATE_TYPE)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_ISSUER {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_SERIAL_NUMBER {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_AC_ISSUER {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_OWNER {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_ATTR_TYPES {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_TRUSTED {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_CERTIFICATE_CATEGORY {
		count := attribute.ulValueLen / C.sizeof_CK_CERTIFICATE_CATEGORY
		return unsafe.Slice((*C.CK_CERTIFICATE_CATEGORY)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_JAVA_MIDP_SECURITY_DOMAIN {
		count := attribute.ulValueLen / C.sizeof_CK_JAVA_MIDP_SECURITY_DOMAIN
		return unsafe.Slice((*C.CK_JAVA_MIDP_SECURITY_DOMAIN)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_URL {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_HASH_OF_SUBJECT_PUBLIC_KEY {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_HASH_OF_ISSUER_PUBLIC_KEY {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_NAME_HASH_ALGORITHM {
		count := attribute.ulValueLen / C.sizeof_CK_MECHANISM_TYPE
		return unsafe.Slice((*C.CK_MECHANISM_TYPE)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_CHECK_VALUE {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_KEY_TYPE {
		count := attribute.ulValueLen / C.sizeof_CK_KEY_TYPE
		return unsafe.Slice((*C.CK_KEY_TYPE)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_SUBJECT {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_ID {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_SENSITIVE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_ENCRYPT {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_DECRYPT {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_WRAP {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_UNWRAP {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_SIGN {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_SIGN_RECOVER {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_VERIFY {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_VERIFY_RECOVER {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_DERIVE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_START_DATE {
		count := attribute.ulValueLen / C.sizeof_CK_DATE
		return unsafe.Slice((*C.CK_DATE)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_END_DATE {
		count := attribute.ulValueLen / C.sizeof_CK_DATE
		return unsafe.Slice((*C.CK_DATE)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_MODULUS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_MODULUS_BITS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_PUBLIC_EXPONENT {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_PRIVATE_EXPONENT {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_PRIME_1 {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_PRIME_2 {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_EXPONENT_1 {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_EXPONENT_2 {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_COEFFICIENT {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_PUBLIC_KEY_INFO {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_PRIME {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_SUBPRIME {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_BASE {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_PRIME_BITS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_SUBPRIME_BITS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_VALUE_BITS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_VALUE_LEN {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_EXTRACTABLE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_LOCAL {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_NEVER_EXTRACTABLE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_ALWAYS_SENSITIVE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_KEY_GEN_MECHANISM {
		count := attribute.ulValueLen / C.sizeof_CK_MECHANISM_TYPE
		return unsafe.Slice((*C.CK_MECHANISM_TYPE)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_MODIFIABLE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_COPYABLE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_DESTROYABLE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_EC_PARAMS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_EC_POINT {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	// TODO: Attribute CKA_SECONDARY_AUTH (Deprecated)
	// TODO: Attribute CKA_AUTH_PIN_FLAGS (Deprecated)
	if attribute._type == C.CKA_ALWAYS_AUTHENTICATE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_WRAP_WITH_TRUSTED {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_WRAP_TEMPLATE {
		count := attribute.ulValueLen / C.sizeof_CK_ATTRIBUTE
		return unsafe.Slice((C.CK_ATTRIBUTE_PTR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_WRAP_TEMPLATE {
		count := attribute.ulValueLen / C.sizeof_CK_ATTRIBUTE
		return unsafe.Slice((C.CK_ATTRIBUTE_PTR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_UNWRAP_TEMPLATE {
		count := attribute.ulValueLen / C.sizeof_CK_ATTRIBUTE
		return unsafe.Slice((C.CK_ATTRIBUTE_PTR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_DERIVE_TEMPLATE {
		count := attribute.ulValueLen / C.sizeof_CK_ATTRIBUTE
		return unsafe.Slice((C.CK_ATTRIBUTE_PTR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_OTP_FORMAT {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_OTP_LENGTH {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_OTP_TIME_INTERVAL {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_OTP_USER_FRIENDLY_MODE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_OTP_CHALLENGE_REQUIREMENT {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_OTP_TIME_REQUIREMENT {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_OTP_COUNTER_REQUIREMENT {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_OTP_PIN_REQUIREMENT {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_OTP_COUNTER {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_OTP_TIME {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_OTP_USER_IDENTIFIER {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_OTP_SERVICE_IDENTIFIER {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_OTP_SERVICE_LOGO {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_OTP_SERVICE_LOGO_TYPE {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_GOSTR3410_PARAMS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_GOSTR3411_PARAMS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_GOST28147_PARAMS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_HW_FEATURE_TYPE {
		count := attribute.ulValueLen / C.sizeof_CK_HW_FEATURE_TYPE
		return unsafe.Slice((*C.CK_HW_FEATURE_TYPE)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_RESET_ON_INIT {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_HAS_RESET {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_PIXEL_X {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_PIXEL_Y {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_RESOLUTION {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_CHAR_ROWS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_CHAR_COLUMNS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_COLOR {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_BITS_PER_PIXEL {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_CHAR_SETS {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_ENCODING_METHODS {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_MIME_TYPES {
		count := attribute.ulValueLen / C.sizeof_CK_UTF8CHAR
		return unsafe.Slice((*C.CK_UTF8CHAR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_MECHANISM_TYPE {
		count := attribute.ulValueLen / C.sizeof_CK_MECHANISM_TYPE
		return unsafe.Slice((*C.CK_MECHANISM_TYPE)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_REQUIRED_CMS_ATTRIBUTES {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_DEFAULT_CMS_ATTRIBUTES {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_SUPPORTED_CMS_ATTRIBUTES {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_ALLOWED_MECHANISMS {
		count := attribute.ulValueLen / C.sizeof_CK_MECHANISM_TYPE
		return unsafe.Slice((C.CK_MECHANISM_TYPE_PTR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_PROFILE_ID {
		count := attribute.ulValueLen / C.sizeof_CK_PROFILE_ID
		return unsafe.Slice((*C.CK_PROFILE_ID)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_X2RATCHET_BAG {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_BAGSIZE {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_X2RATCHET_BOBS1STMSG {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_X2RATCHET_CKR {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_CKS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_DHP {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_DHR {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_DHS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_HKR {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_HKS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_ISALICE {
		count := attribute.ulValueLen / C.sizeof_CK_BBOOL
		return unsafe.Slice((*C.CK_BBOOL)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_X2RATCHET_NHKR {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_NHKS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_X2RATCHET_NR {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_X2RATCHET_NS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_X2RATCHET_PNS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_X2RATCHET_RK {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_HSS_LEVELS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_HSS_LMS_TYPE {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_HSS_LMOTS_TYPE {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_HSS_LMS_TYPES {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_HSS_LMOTS_TYPES {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_HSS_KEYS_REMAINING {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
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
		switch casted := attributeValue.(type) {
		case C.CK_BYTE:
			{
				buffer.Write(EncodeByte(casted))
				break
			}
		case []C.CK_BYTE:
			{
				buffer.Write(EncodeVoidPointerAsBytePointer(attribute.pValue, attribute.ulValueLen)[4:])
				break
			}
		}
		// TODO: Do for every attribute value type
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
