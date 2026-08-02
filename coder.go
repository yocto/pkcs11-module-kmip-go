package main

import "bytes"

// #include "cgo.h"
import "C"
import "encoding/binary"
import "reflect"

func copyIntoField[ArbitraryType any](source []byte, destination *ArbitraryType) int {
	slice := pointerToArray((*byte)(getNativePointer(destination)), uint(len(source)))
	return copy(slice, source)
}

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

	offset += copyIntoField(data[offset:offset+2], &info.cryptokiVersion)
	offset += copyIntoField(data[offset:offset+32], &info.manufacturerID)

	info.flags = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	offset += copyIntoField(data[offset:offset+32], &info.libraryDescription)
	offset += copyIntoField(data[offset:offset+2], &info.libraryVersion)

	return info
}

func DecodeSlotInfo(data []byte) C.CK_SLOT_INFO {
	slotInfo := C.CK_SLOT_INFO{}

	var offset int

	offset += copyIntoField(data[offset:offset+64], &slotInfo.slotDescription)
	offset += copyIntoField(data[offset:offset+32], &slotInfo.manufacturerID)

	slotInfo.flags = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	offset += copyIntoField(data[offset:offset+2], &slotInfo.hardwareVersion)
	offset += copyIntoField(data[offset:offset+2], &slotInfo.firmwareVersion)

	return slotInfo
}

func DecodeTokenInfo(data []byte) C.CK_TOKEN_INFO {
	tokenInfo := C.CK_TOKEN_INFO{}

	var offset int

	offset += copyIntoField(data[offset:offset+32], &tokenInfo.label)
	offset += copyIntoField(data[offset:offset+32], &tokenInfo.manufacturerID)
	offset += copyIntoField(data[offset:offset+16], &tokenInfo.model)
	offset += copyIntoField(data[offset:offset+16], &tokenInfo.serialNumber)

	tokenInfo.flags = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulMaxSessionCount = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulSessionCount = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulMaxRwSessionCount = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulRwSessionCount = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulMaxPinLen = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulMinPinLen = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulTotalPublicMemory = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulFreePublicMemory = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulTotalPrivateMemory = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	tokenInfo.ulFreePrivateMemory = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	offset += copyIntoField(data[offset:offset+2], &tokenInfo.hardwareVersion)
	offset += copyIntoField(data[offset:offset+2], &tokenInfo.firmwareVersion)
	offset += copyIntoField(data[offset:offset+16], &tokenInfo.utcTime)

	return tokenInfo
}

func DecodeSessionInfo(data []byte) C.CK_SESSION_INFO {
	sessionInfo := C.CK_SESSION_INFO{}

	var offset int

	sessionInfo.slotID = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	sessionInfo.state = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	sessionInfo.flags = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	sessionInfo.ulDeviceError = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	return sessionInfo
}

func CalculateAttributeSize(data []byte) int {
	_type := DecodeUnsignedLong(data[0:8])
	hasValue := DecodeByte(data[8:9])
	hasLength := DecodeByte(data[9:10])

	valueType := GetAttributeValueType(_type, 0)

	var lengthSize int
	var valueSize int

	if hasLength != 0x00 {
		if valueType.Kind() == reflect.Slice {
			lengthSize = 4

			if hasValue != 0x00 {
				if valueType.Elem() == reflect.TypeOf(*new(C.CK_ATTRIBUTE)) {
					// TODO: Value size @ attribute with attributes
				} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_BYTE)) {
					valueSize = int(DecodeUnsignedLongAsLength(data[10:14]))
				} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_MECHANISM_TYPE)) {
					valueSize = int(DecodeUnsignedLongAsLength(data[10:14])) * 8
				} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_ULONG)) {
					valueSize = int(DecodeUnsignedLongAsLength(data[10:14])) * 8
				} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_UTF8CHAR)) {
					valueSize = int(DecodeUnsignedLongAsLength(data[10:14]))
				}
			}
		} else {
			lengthSize = 0

			if hasValue != 0x00 {
				if valueType == reflect.TypeOf(*new(C.CK_BBOOL)) {
					valueSize = 1
				} else if valueType == reflect.TypeOf(*new(C.CK_CERTIFICATE_CATEGORY)) {
					valueSize = 8
				} else if valueType == reflect.TypeOf(*new(C.CK_CERTIFICATE_TYPE)) {
					valueSize = 8
				} else if valueType == reflect.TypeOf(*new(C.CK_DATE)) {
					valueSize = 8
				} else if valueType == reflect.TypeOf(*new(C.CK_HW_FEATURE_TYPE)) {
					valueSize = 8
				} else if valueType == reflect.TypeOf(*new(C.CK_JAVA_MIDP_SECURITY_DOMAIN)) {
					valueSize = 8
				} else if valueType == reflect.TypeOf(*new(C.CK_KEY_TYPE)) {
					valueSize = 8
				} else if valueType == reflect.TypeOf(*new(C.CK_MECHANISM_TYPE)) {
					valueSize = 8
				} else if valueType == reflect.TypeOf(*new(C.CK_OBJECT_CLASS)) {
					valueSize = 8
				} else if valueType == reflect.TypeOf(*new(C.CK_ULONG)) {
					valueSize = 8
				}
			}
		}
	}

	return 10 + lengthSize + valueSize
}

func DecodeAttribute(data []byte) C.CK_ATTRIBUTE {
	attribute := C.CK_ATTRIBUTE{}

	attribute._type = DecodeUnsignedLong(data[0:8])
	hasValue := DecodeByte(data[8:9])
	hasLength := DecodeByte(data[9:10])

	valueType := GetAttributeValueType(attribute._type, attribute.ulValueLen)

	if hasLength != 0x00 {
		remaining := data[10:]

		if valueType.Kind() == reflect.Slice {
			if valueType.Elem() == reflect.TypeOf(*new(C.CK_ATTRIBUTE)) {
				attribute.ulValueLen = DecodeUnsignedLongAsLength(remaining[0:4]) * C.sizeof_CK_ATTRIBUTE
			} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_BYTE)) {
				attribute.ulValueLen = DecodeUnsignedLongAsLength(remaining[0:4])
			} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_MECHANISM_TYPE)) {
				attribute.ulValueLen = DecodeUnsignedLongAsLength(remaining[0:4]) * C.sizeof_CK_MECHANISM_TYPE
			} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_ULONG)) {
				attribute.ulValueLen = DecodeUnsignedLongAsLength(remaining[0:4]) * C.sizeof_CK_ULONG
			} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_UTF8CHAR)) {
				attribute.ulValueLen = DecodeUnsignedLongAsLength(remaining[0:4])
			}
		} else {
			if valueType == reflect.TypeOf(*new(C.CK_BBOOL)) {
				attribute.ulValueLen = 1
			} else if valueType == reflect.TypeOf(*new(C.CK_CERTIFICATE_CATEGORY)) {
				attribute.ulValueLen = 8
			} else if valueType == reflect.TypeOf(*new(C.CK_CERTIFICATE_TYPE)) {
				attribute.ulValueLen = 8
			} else if valueType == reflect.TypeOf(*new(C.CK_DATE)) {
				attribute.ulValueLen = 8
			} else if valueType == reflect.TypeOf(*new(C.CK_HW_FEATURE_TYPE)) {
				attribute.ulValueLen = 8
			} else if valueType == reflect.TypeOf(*new(C.CK_JAVA_MIDP_SECURITY_DOMAIN)) {
				attribute.ulValueLen = 8
			} else if valueType == reflect.TypeOf(*new(C.CK_KEY_TYPE)) {
				attribute.ulValueLen = 8
			} else if valueType == reflect.TypeOf(*new(C.CK_MECHANISM_TYPE)) {
				attribute.ulValueLen = 8
			} else if valueType == reflect.TypeOf(*new(C.CK_OBJECT_CLASS)) {
				attribute.ulValueLen = 8
			} else if valueType == reflect.TypeOf(*new(C.CK_ULONG)) {
				attribute.ulValueLen = 8
			}
		}

		if hasValue != 0x00 {
			if valueType.Kind() == reflect.Slice {
				if valueType.Elem() == reflect.TypeOf(*new(C.CK_ATTRIBUTE)) {
					// TODO: Decode value @ attribute with attributes
				} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_BYTE)) {
					value := remaining[4 : 4+attribute.ulValueLen]
					attribute.pValue = C.CK_VOID_PTR(arrayToPointer(value))
				} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_MECHANISM_TYPE)) {
					arrayBuffer := bytes.NewBuffer(remaining[4 : 4+attribute.ulValueLen])

					mechanismTypeArray := make([]C.CK_MECHANISM_TYPE, attribute.ulValueLen/C.sizeof_CK_MECHANISM_TYPE)
					for i := 0; i < len(mechanismTypeArray); i++ {
						mechanismTypeArray[i] = DecodeUnsignedLong(arrayBuffer.Next(8))
					}
					value := mechanismTypeArray
					attribute.pValue = C.CK_VOID_PTR(arrayToPointer(value))
				} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_ULONG)) {
					arrayBuffer := bytes.NewBuffer(remaining[4 : 4+attribute.ulValueLen])

					ulongArray := make([]C.CK_ULONG, attribute.ulValueLen/C.sizeof_CK_ULONG)
					for i := 0; i < len(ulongArray); i++ {
						ulongArray[i] = DecodeUnsignedLong(arrayBuffer.Next(8))
					}
					value := ulongArray
					attribute.pValue = C.CK_VOID_PTR(arrayToPointer(value))
				} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_UTF8CHAR)) {
					value := remaining[4 : 4+attribute.ulValueLen]
					attribute.pValue = C.CK_VOID_PTR(arrayToPointer(value))
				}
			} else {
				if valueType == reflect.TypeOf(*new(C.CK_BBOOL)) {
					value := DecodeByte(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				} else if valueType == reflect.TypeOf(*new(C.CK_CERTIFICATE_CATEGORY)) {
					value := DecodeUnsignedLong(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				} else if valueType == reflect.TypeOf(*new(C.CK_CERTIFICATE_TYPE)) {
					value := DecodeUnsignedLong(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				} else if valueType == reflect.TypeOf(*new(C.CK_DATE)) {
					value := DecodeDate(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				} else if valueType == reflect.TypeOf(*new(C.CK_HW_FEATURE_TYPE)) {
					value := DecodeUnsignedLong(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				} else if valueType == reflect.TypeOf(*new(C.CK_JAVA_MIDP_SECURITY_DOMAIN)) {
					value := DecodeUnsignedLong(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				} else if valueType == reflect.TypeOf(*new(C.CK_KEY_TYPE)) {
					value := DecodeUnsignedLong(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				} else if valueType == reflect.TypeOf(*new(C.CK_MECHANISM_TYPE)) {
					value := DecodeUnsignedLong(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				} else if valueType == reflect.TypeOf(*new(C.CK_OBJECT_CLASS)) {
					value := DecodeUnsignedLong(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				} else if valueType == reflect.TypeOf(*new(C.CK_ULONG)) {
					value := DecodeUnsignedLong(remaining[0:attribute.ulValueLen])
					attribute.pValue = C.CK_VOID_PTR(&value)
				}
			}
		}
	}

	return attribute
}

func DecodeDate(data []byte) C.CK_DATE {
	date := C.CK_DATE{}

	var offset int

	offset += copyIntoField(data[offset:offset+4], &date.year)
	offset += copyIntoField(data[offset:offset+2], &date.month)
	offset += copyIntoField(data[offset:offset+2], &date.day)

	return date
}

func DecodeMechanismInfo(data []byte) C.CK_MECHANISM_INFO {
	mechanismInfo := C.CK_MECHANISM_INFO{}

	var offset int

	mechanismInfo.ulMinKeySize = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	mechanismInfo.ulMaxKeySize = DecodeUnsignedLong(data[offset : offset+8])
	offset += 8

	mechanismInfo.flags = DecodeUnsignedLong(data[offset : offset+8])
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
	for _, _byte := range pointerToArray(bytePointer, uint(bytePointerLength)) {
		inBuffer.Write(EncodeByte(_byte))
	}
	// Length field originally placed here, but "moved up" before variable byte pointer array.
	return inBuffer.Bytes()
}

func EncodeUTF8CharacterPointer(utf8characterPointer C.CK_UTF8CHAR_PTR, utf8characterPointerLength C.CK_ULONG) []byte {
	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeUnsignedLongAsLength(utf8characterPointerLength)) // Moved up
	for _, utf8char := range pointerToArray(utf8characterPointer, uint(utf8characterPointerLength)) {
		inBuffer.Write(EncodeByte(utf8char))
	}
	// Length field originally placed here, but "moved up" before variable byte pointer array.
	return inBuffer.Bytes()
}

func EncodeUnsignedLongPointer(ulongPointer C.CK_ULONG_PTR, ulongPointerLength C.CK_ULONG) []byte {
	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeUnsignedLongAsLength(ulongPointerLength)) // Moved up
	for _, ulong := range pointerToArray(ulongPointer, uint(ulongPointerLength)) {
		inBuffer.Write(EncodeUnsignedLong(ulong))
	}
	// Length field originally placed here, but "moved up" before variable byte pointer array.
	return inBuffer.Bytes()
}

func EncodeMechanismTypePointer(mechanismTypePointer C.CK_MECHANISM_TYPE_PTR, mechanismTypePointerLength C.CK_ULONG) []byte {
	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeUnsignedLongAsLength(mechanismTypePointerLength)) // Moved up
	for _, mechanismType := range pointerToArray(mechanismTypePointer, uint(mechanismTypePointerLength)) {
		inBuffer.Write(EncodeUnsignedLong(mechanismType))
	}
	// Length field originally placed here, but "moved up" before variable byte pointer array.
	return inBuffer.Bytes()
}

func EncodeAttribute(attribute C.CK_ATTRIBUTE, forceValueNil bool) []byte {
	hasValue := bool(attribute.pValue != nil)
	hasLength := bool(attribute.ulValueLen != 0)

	if forceValueNil || !hasLength {
		hasValue = false
	}

	buffer := new(bytes.Buffer)
	buffer.Write(EncodeUnsignedLong(attribute._type))

	buffer.Write(EncodeByte(ConvertBooleanToByte(hasValue)))
	buffer.Write(EncodeByte(ConvertBooleanToByte(hasLength)))

	valueType := GetAttributeValueType(attribute._type, attribute.ulValueLen)
	if valueType == nil {
		return nil
	}

	if hasLength && valueType.Kind() == reflect.Slice {
		if valueType.Elem() == reflect.TypeOf(*new(C.CK_ATTRIBUTE)) {
			buffer.Write(EncodeUnsignedLongAsLength(C.CK_ULONG(attribute.ulValueLen / C.sizeof_CK_ATTRIBUTE)))
		} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_BYTE)) {
			buffer.Write(EncodeUnsignedLongAsLength(C.CK_ULONG(attribute.ulValueLen)))
		} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_MECHANISM_TYPE)) {
			buffer.Write(EncodeUnsignedLongAsLength(C.CK_ULONG(attribute.ulValueLen / C.sizeof_CK_MECHANISM_TYPE)))
		} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_ULONG)) {
			buffer.Write(EncodeUnsignedLongAsLength(C.CK_ULONG(attribute.ulValueLen / C.sizeof_CK_ULONG)))
		} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_UTF8CHAR)) {
			buffer.Write(EncodeUnsignedLongAsLength(C.CK_ULONG(attribute.ulValueLen)))
		}
	}

	if hasValue {
		if valueType.Kind() == reflect.Slice {
			if valueType.Elem() == reflect.TypeOf(*new(C.CK_ATTRIBUTE)) {
				// TODO: Encode value @ attribute with attributes
			} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_BYTE)) {
				buffer.Write(EncodeBytePointer(C.CK_BYTE_PTR(attribute.pValue), attribute.ulValueLen)[4:])
			} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_MECHANISM_TYPE)) {
				buffer.Write(EncodeMechanismTypePointer(C.CK_MECHANISM_TYPE_PTR(attribute.pValue), attribute.ulValueLen)[4:])
			} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_ULONG)) {
				buffer.Write(EncodeUnsignedLongPointer(C.CK_ULONG_PTR(attribute.pValue), attribute.ulValueLen)[4:])
			} else if valueType.Elem() == reflect.TypeOf(*new(C.CK_UTF8CHAR)) {
				buffer.Write(EncodeUTF8CharacterPointer(C.CK_UTF8CHAR_PTR(attribute.pValue), attribute.ulValueLen)[4:])
			}
		} else {
			if valueType == reflect.TypeOf(*new(C.CK_BBOOL)) {
				buffer.Write(EncodeByte(*C.CK_BYTE_PTR(attribute.pValue)))
			} else if valueType == reflect.TypeOf(*new(C.CK_CERTIFICATE_CATEGORY)) {
				buffer.Write(EncodeUnsignedLong(*C.CK_ULONG_PTR(attribute.pValue)))
			} else if valueType == reflect.TypeOf(*new(C.CK_CERTIFICATE_TYPE)) {
				buffer.Write(EncodeUnsignedLong(*C.CK_ULONG_PTR(attribute.pValue)))
			} else if valueType == reflect.TypeOf(*new(C.CK_DATE)) {
				buffer.Write(EncodeDate(*(*C.CK_DATE)(attribute.pValue)))
			} else if valueType == reflect.TypeOf(*new(C.CK_HW_FEATURE_TYPE)) {
				buffer.Write(EncodeUnsignedLong(*C.CK_ULONG_PTR(attribute.pValue)))
			} else if valueType == reflect.TypeOf(*new(C.CK_JAVA_MIDP_SECURITY_DOMAIN)) {
				buffer.Write(EncodeUnsignedLong(*C.CK_ULONG_PTR(attribute.pValue)))
			} else if valueType == reflect.TypeOf(*new(C.CK_KEY_TYPE)) {
				buffer.Write(EncodeUnsignedLong(*C.CK_ULONG_PTR(attribute.pValue)))
			} else if valueType == reflect.TypeOf(*new(C.CK_MECHANISM_TYPE)) {
				buffer.Write(EncodeUnsignedLong(*C.CK_MECHANISM_TYPE_PTR(attribute.pValue)))
			} else if valueType == reflect.TypeOf(*new(C.CK_OBJECT_CLASS)) {
				buffer.Write(EncodeUnsignedLong(*C.CK_OBJECT_CLASS_PTR(attribute.pValue)))
			} else if valueType == reflect.TypeOf(*new(C.CK_ULONG)) {
				buffer.Write(EncodeUnsignedLong(*C.CK_ULONG_PTR(attribute.pValue)))
			}
		}
	}

	return buffer.Bytes()
}

func EncodeDate(date C.CK_DATE) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(pointerToArray((*byte)(getNativePointer(&date.year)), 4))
	buffer.Write(pointerToArray((*byte)(getNativePointer(&date.month)), 2))
	buffer.Write(pointerToArray((*byte)(getNativePointer(&date.day)), 2))
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
		buffer.Write(pointerToArray((*byte)(mechanism.pParameter), uint(mechanism.ulParameterLen)))
	}
	return buffer.Bytes()
}

func GetAttributeValueType(attributeType C.CK_ATTRIBUTE_TYPE, valueLength C.CK_ULONG) reflect.Type {
	if attributeType == C.CKA_CLASS {
		return reflect.TypeOf(*new(C.CK_OBJECT_CLASS))
	}
	if attributeType == C.CKA_TOKEN {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_PRIVATE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_LABEL {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_UNIQUE_ID {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_APPLICATION {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_VALUE {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_OBJECT_ID {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_CERTIFICATE_TYPE {
		return reflect.TypeOf(*new(C.CK_CERTIFICATE_TYPE))
	}
	if attributeType == C.CKA_ISSUER {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_SERIAL_NUMBER {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_AC_ISSUER {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_OWNER {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_ATTR_TYPES {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_TRUSTED {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_CERTIFICATE_CATEGORY {
		return reflect.TypeOf(*new(C.CK_CERTIFICATE_CATEGORY))
	}
	if attributeType == C.CKA_JAVA_MIDP_SECURITY_DOMAIN {
		return reflect.TypeOf(*new(C.CK_JAVA_MIDP_SECURITY_DOMAIN))
	}
	if attributeType == C.CKA_URL {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_HASH_OF_SUBJECT_PUBLIC_KEY {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_HASH_OF_ISSUER_PUBLIC_KEY {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_NAME_HASH_ALGORITHM {
		return reflect.TypeOf(*new(C.CK_MECHANISM_TYPE))
	}
	if attributeType == C.CKA_CHECK_VALUE {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_KEY_TYPE {
		return reflect.TypeOf(*new(C.CK_KEY_TYPE))
	}
	if attributeType == C.CKA_SUBJECT {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_ID {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_SENSITIVE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_ENCRYPT {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_DECRYPT {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_WRAP {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_UNWRAP {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_SIGN {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_SIGN_RECOVER {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_VERIFY {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_VERIFY_RECOVER {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_DERIVE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_START_DATE {
		return reflect.TypeOf(*new(C.CK_DATE))
	}
	if attributeType == C.CKA_END_DATE {
		return reflect.TypeOf(*new(C.CK_DATE))
	}
	if attributeType == C.CKA_MODULUS {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_MODULUS_BITS {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_PUBLIC_EXPONENT {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_PRIVATE_EXPONENT {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_PRIME_1 {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_PRIME_2 {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_EXPONENT_1 {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_EXPONENT_2 {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_COEFFICIENT {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_PUBLIC_KEY_INFO {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_PRIME {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_SUBPRIME {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_BASE {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_PRIME_BITS {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_SUBPRIME_BITS {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_VALUE_BITS {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_VALUE_LEN {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_EXTRACTABLE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_LOCAL {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_NEVER_EXTRACTABLE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_ALWAYS_SENSITIVE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_KEY_GEN_MECHANISM {
		return reflect.TypeOf(*new(C.CK_MECHANISM_TYPE))
	}
	if attributeType == C.CKA_MODIFIABLE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_COPYABLE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_DESTROYABLE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_EC_PARAMS {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_EC_POINT {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_SECONDARY_AUTH { // Deprecated
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_AUTH_PIN_FLAGS { // Deprecated
		return reflect.TypeOf(*new(C.CK_FLAGS))
	}
	if attributeType == C.CKA_ALWAYS_AUTHENTICATE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_WRAP_WITH_TRUSTED {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_WRAP_TEMPLATE {
		return reflect.TypeOf(make([]C.CK_ATTRIBUTE, valueLength/C.sizeof_CK_ATTRIBUTE))
	}
	if attributeType == C.CKA_UNWRAP_TEMPLATE {
		return reflect.TypeOf(make([]C.CK_ATTRIBUTE, valueLength/C.sizeof_CK_ATTRIBUTE))
	}
	if attributeType == C.CKA_DERIVE_TEMPLATE {
		return reflect.TypeOf(make([]C.CK_ATTRIBUTE, valueLength/C.sizeof_CK_ATTRIBUTE))
	}
	if attributeType == C.CKA_OTP_FORMAT {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_OTP_LENGTH {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_OTP_TIME_INTERVAL {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_OTP_USER_FRIENDLY_MODE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_OTP_CHALLENGE_REQUIREMENT {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_OTP_TIME_REQUIREMENT {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_OTP_COUNTER_REQUIREMENT {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_OTP_PIN_REQUIREMENT {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_OTP_COUNTER {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_OTP_TIME {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_OTP_USER_IDENTIFIER {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_OTP_SERVICE_IDENTIFIER {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_OTP_SERVICE_LOGO {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_OTP_SERVICE_LOGO_TYPE {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_GOSTR3410_PARAMS {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_GOSTR3411_PARAMS {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_GOST28147_PARAMS {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_HW_FEATURE_TYPE {
		return reflect.TypeOf(*new(C.CK_HW_FEATURE_TYPE))
	}
	if attributeType == C.CKA_RESET_ON_INIT {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_HAS_RESET {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_PIXEL_X {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_PIXEL_Y {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_RESOLUTION {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_CHAR_ROWS {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_CHAR_COLUMNS {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_COLOR {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_BITS_PER_PIXEL {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_CHAR_SETS {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_ENCODING_METHODS {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_MIME_TYPES {
		return reflect.TypeOf(make([]C.CK_UTF8CHAR, valueLength/C.sizeof_CK_UTF8CHAR))
	}
	if attributeType == C.CKA_MECHANISM_TYPE {
		return reflect.TypeOf(*new(C.CK_MECHANISM_TYPE))
	}
	if attributeType == C.CKA_REQUIRED_CMS_ATTRIBUTES {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_DEFAULT_CMS_ATTRIBUTES {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_SUPPORTED_CMS_ATTRIBUTES {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_ALLOWED_MECHANISMS {
		return reflect.TypeOf(make([]C.CK_MECHANISM_TYPE, valueLength/C.sizeof_CK_MECHANISM_TYPE))
	}
	if attributeType == C.CKA_PROFILE_ID {
		return reflect.TypeOf(*new(C.CK_PROFILE_ID))
	}
	if attributeType == C.CKA_X2RATCHET_BAG {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_BAGSIZE {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_X2RATCHET_BOBS1STMSG {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_X2RATCHET_CKR {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_CKS {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_DHP {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_DHR {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_DHS {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_HKR {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_HKS {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_ISALICE {
		return reflect.TypeOf(*new(C.CK_BBOOL))
	}
	if attributeType == C.CKA_X2RATCHET_NHKR {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_NHKS {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_X2RATCHET_NR {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_X2RATCHET_NS {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_X2RATCHET_PNS {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_X2RATCHET_RK {
		return reflect.TypeOf(make([]C.CK_BYTE, valueLength/C.sizeof_CK_BYTE))
	}
	if attributeType == C.CKA_HSS_LEVELS {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_HSS_LMS_TYPE {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_HSS_LMOTS_TYPE {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	if attributeType == C.CKA_HSS_LMS_TYPES {
		return reflect.TypeOf(make([]C.CK_ULONG, valueLength/C.sizeof_CK_ULONG))
	}
	if attributeType == C.CKA_HSS_LMOTS_TYPES {
		return reflect.TypeOf(make([]C.CK_ULONG, valueLength/C.sizeof_CK_ULONG))
	}
	if attributeType == C.CKA_HSS_KEYS_REMAINING {
		return reflect.TypeOf(*new(C.CK_ULONG))
	}
	return nil
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
		ulValueLen: C.CK_ULONG(getSizeOf(sensitive)),
	}
}

func getAttributeForTest2() C.CK_ATTRIBUTE {
	var checkValue [16]C.CK_BYTE

	return C.CK_ATTRIBUTE{
		_type:      C.CKA_CHECK_VALUE,
		pValue:     C.CK_VOID_PTR(&checkValue),
		ulValueLen: C.CK_ULONG(getSizeOf(checkValue)),
	}
}

func getAttributeForTest3() C.CK_ATTRIBUTE {
	var mechanisms [64]C.CK_MECHANISM_TYPE

	return C.CK_ATTRIBUTE{
		_type:      C.CKA_ALLOWED_MECHANISMS,
		pValue:     C.CK_VOID_PTR(&mechanisms),
		ulValueLen: C.CK_ULONG(8 * len(mechanisms)),
	}
}

func getAttributeForTest4() C.CK_ATTRIBUTE {
	var label [42]C.CK_BYTE

	return C.CK_ATTRIBUTE{
		_type:      C.CKA_LABEL,
		pValue:     C.CK_VOID_PTR(&label),
		ulValueLen: C.CK_ULONG(getSizeOf(label)),
	}
}

func getMechanismForTest() C.CK_MECHANISM {
	var iv []C.CK_BYTE = []C.CK_BYTE{1, 2, 3, 4, 5, 6, 7, 8}

	return C.CK_MECHANISM{
		mechanism:      C.CKM_DES_CBC_PAD,
		pParameter:     C.CK_VOID_PTR(arrayToPointer(iv)),
		ulParameterLen: C.CK_ULONG(len(iv)),
	}
}
