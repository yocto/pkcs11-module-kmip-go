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
	// TODO: Attribute CKA_START_DATE         0x00000110UL CK_DATE
	// TODO: Attribute CKA_END_DATE           0x00000111UL CK_DATE
	// TODO: Attribute CKA_MODULUS            0x00000120UL BIGINT
	if attribute._type == C.CKA_MODULUS_BITS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	// TODO: Attribute CKA_PUBLIC_EXPONENT    0x00000122UL BIGINT
	// TODO: Attribute CKA_PRIVATE_EXPONENT   0x00000123UL BIGINT
	// TODO: Attribute CKA_PRIME_1            0x00000124UL BIGINT
	// TODO: Attribute CKA_PRIME_2            0x00000125UL BIGINT
	// TODO: Attribute CKA_EXPONENT_1         0x00000126UL BIGINT
	// TODO: Attribute CKA_EXPONENT_2         0x00000127UL BIGINT
	// TODO: Attribute CKA_COEFFICIENT        0x00000128UL BIGINT
	if attribute._type == C.CKA_PUBLIC_KEY_INFO {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	// TODO: Attribute CKA_PRIME              0x00000130UL BIGINT
	// TODO: Attribute CKA_SUBPRIME           0x00000131UL BIGINT
	// TODO: Attribute CKA_BASE               0x00000132UL BIGINT
	if attribute._type == C.CKA_PRIME_BITS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	if attribute._type == C.CKA_SUBPRIME_BITS {
		count := attribute.ulValueLen / C.sizeof_CK_ULONG
		return unsafe.Slice((*C.CK_ULONG)(attribute.pValue), count)[0]
	}
	// TODO: Attribute CKA_VALUE_BITS         0x00000160UL CK_ULONG
	// TODO: Attribute CKA_VALUE_LEN          0x00000161UL CK_ULONG
	// TODO: Attribute CKA_EXTRACTABLE        0x00000162UL CK_BBOOL
	// TODO: Attribute CKA_LOCAL              0x00000163UL CK_BBOOL
	// TODO: Attribute CKA_NEVER_EXTRACTABLE  0x00000164UL CK_BBOOL
	// TODO: Attribute CKA_ALWAYS_SENSITIVE   0x00000165UL CK_BBOOL
	// TODO: Attribute CKA_KEY_GEN_MECHANISM  0x00000166UL CK_MECHANISM_TYPE
	// TODO: Attribute CKA_MODIFIABLE         0x00000170UL CK_BBOOL
	// TODO: Attribute CKA_COPYABLE           0x00000171UL CK_BBOOL
	// TODO: Attribute CKA_DESTROYABLE        0x00000172UL CK_BBOOL
	if attribute._type == C.CKA_EC_PARAMS {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_EC_POINT {
		count := attribute.ulValueLen / C.sizeof_CK_BYTE
		return unsafe.Slice((*C.CK_BYTE)(attribute.pValue), count)
	}
	// TODO: Attribute CKA_SECONDARY_AUTH     0x00000200UL /* Deprecated */
	// TODO: Attribute CKA_AUTH_PIN_FLAGS     0x00000201UL /* Deprecated */
	// TODO: Attribute CKA_ALWAYS_AUTHENTICATE  0x00000202UL
	// TODO: Attribute CKA_WRAP_WITH_TRUSTED    0x00000210UL CKA_ALWAYS_AUTHENTICATE
	// TODO: Attribute CKA_WRAP_TEMPLATE        (CKF_ARRAY_ATTRIBUTE|0x00000211UL)
	// TODO: Attribute CKA_UNWRAP_TEMPLATE      (CKF_ARRAY_ATTRIBUTE|0x00000212UL)
	// TODO: Attribute CKA_DERIVE_TEMPLATE      (CKF_ARRAY_ATTRIBUTE|0x00000213UL)
	// TODO: Attribute CKA_OTP_FORMAT                0x00000220UL
	// TODO: Attribute CKA_OTP_LENGTH                0x00000221UL
	// TODO: Attribute CKA_OTP_TIME_INTERVAL         0x00000222UL
	// TODO: Attribute CKA_OTP_USER_FRIENDLY_MODE    0x00000223UL
	// TODO: Attribute CKA_OTP_CHALLENGE_REQUIREMENT 0x00000224UL
	// TODO: Attribute CKA_OTP_TIME_REQUIREMENT      0x00000225UL
	// TODO: Attribute CKA_OTP_COUNTER_REQUIREMENT   0x00000226UL
	// TODO: Attribute CKA_OTP_PIN_REQUIREMENT       0x00000227UL
	// TODO: Attribute CKA_OTP_COUNTER               0x0000022eUL
	// TODO: Attribute CKA_OTP_TIME                  0x0000022fUL
	// TODO: Attribute CKA_OTP_USER_IDENTIFIER       0x0000022aUL
	// TODO: Attribute CKA_OTP_SERVICE_IDENTIFIER    0x0000022bUL
	// TODO: Attribute CKA_OTP_SERVICE_LOGO          0x0000022cUL
	// TODO: Attribute CKA_OTP_SERVICE_LOGO_TYPE     0x0000022dUL
	// TODO: Attribute CKA_GOSTR3410_PARAMS            0x00000250UL
	// TODO: Attribute CKA_GOSTR3411_PARAMS            0x00000251UL
	// TODO: Attribute CKA_GOST28147_PARAMS            0x00000252UL
	// TODO: Attribute CKA_HW_FEATURE_TYPE             0x00000300UL
	// TODO: Attribute CKA_RESET_ON_INIT               0x00000301UL
	// TODO: Attribute CKA_HAS_RESET                   0x00000302UL
	// TODO: Attribute CKA_PIXEL_X                     0x00000400UL
	// TODO: Attribute CKA_PIXEL_Y                     0x00000401UL
	// TODO: Attribute CKA_RESOLUTION                  0x00000402UL
	// TODO: Attribute CKA_CHAR_ROWS                   0x00000403UL
	// TODO: Attribute CKA_CHAR_COLUMNS                0x00000404UL
	// TODO: Attribute CKA_COLOR                       0x00000405UL
	// TODO: Attribute CKA_BITS_PER_PIXEL              0x00000406UL
	// TODO: Attribute CKA_CHAR_SETS                   0x00000480UL
	// TODO: Attribute CKA_ENCODING_METHODS            0x00000481UL
	// TODO: Attribute CKA_MIME_TYPES                  0x00000482UL
	// TODO: Attribute CKA_MECHANISM_TYPE              0x00000500UL
	// TODO: Attribute CKA_REQUIRED_CMS_ATTRIBUTES     0x00000501UL
	// TODO: Attribute CKA_DEFAULT_CMS_ATTRIBUTES      0x00000502UL
	// TODO: Attribute CKA_SUPPORTED_CMS_ATTRIBUTES    0x00000503UL
	if attribute._type == C.CKA_ALLOWED_MECHANISMS {
		count := attribute.ulValueLen / C.sizeof_CK_MECHANISM_TYPE
		return unsafe.Slice((C.CK_MECHANISM_TYPE_PTR)(attribute.pValue), count)
	}
	if attribute._type == C.CKA_PROFILE_ID {
		count := attribute.ulValueLen / C.sizeof_CK_PROFILE_ID
		return unsafe.Slice((*C.CK_PROFILE_ID)(attribute.pValue), count)[0]
	}
	// TODO: Attribute CKA_X2RATCHET_BAG               0x00000602UL []byte
	// TODO: Attribute CKA_X2RATCHET_BAGSIZE           0x00000603UL ULONG
	// TODO: Attribute CKA_X2RATCHET_BOBS1STMSG        0x00000604UL BOOL
	// TODO: Attribute CKA_X2RATCHET_CKR               0x00000605UL []byte
	// TODO: Attribute CKA_X2RATCHET_CKS               0x00000606UL []byte
	// TODO: Attribute CKA_X2RATCHET_DHP               0x00000607UL []byte
	// TODO: Attribute CKA_X2RATCHET_DHR               0x00000608UL []byte
	// TODO: Attribute CKA_X2RATCHET_DHS               0x00000609UL []byte
	// TODO: Attribute CKA_X2RATCHET_HKR               0x0000060aUL []byte
	// TODO: Attribute CKA_X2RATCHET_HKS               0x0000060bUL []byte
	// TODO: Attribute CKA_X2RATCHET_ISALICE           0x0000060cUL BOOL
	// TODO: Attribute CKA_X2RATCHET_NHKR              0x0000060dUL []byte
	// TODO: Attribute CKA_X2RATCHET_NHKS              0x0000060eUL []byte
	// TODO: Attribute CKA_X2RATCHET_NR                0x0000060fUL ULONG
	// TODO: Attribute CKA_X2RATCHET_NS                0x00000610UL ULONG
	// TODO: Attribute CKA_X2RATCHET_PNS               0x00000611UL ULONG
	// TODO: Attribute CKA_X2RATCHET_RK                0x00000612UL []byte
	// TODO: Attribute CKA_HSS_LEVELS                  0x00000617UL CK_ULONG
	// TODO: Attribute CKA_HSS_LMS_TYPE                0x00000618UL CK_ULONG
	// TODO: Attribute CKA_HSS_LMOTS_TYPE              0x00000619UL CK_ULONG
	// TODO: Attribute CKA_HSS_LMS_TYPES               0x0000061aUL CK_ULONG_PTR
	// TODO: Attribute CKA_HSS_LMOTS_TYPES             0x0000061bUL CK_ULONG_PTR
	// TODO: Attribute CKA_HSS_KEYS_REMAINING          0x0000061cUL CK_ULONG
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
