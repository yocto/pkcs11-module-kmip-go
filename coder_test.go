package main

import "bytes"
import "testing"

func TestEncodeByte(t *testing.T) {
	_byte := getByteForTest()

	encoded := EncodeByte(_byte)
	expected := []byte{
		0x01,
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Test for %q failed:\nExpected:\n%v\nGot:\n%v", "EncodeByte", expected, encoded)
	}
}

func TestEncodeUnsignedLong(t *testing.T) {
	ulong := getUnsignedLongForTest()

	encoded := EncodeUnsignedLong(ulong)
	expected := []byte{
		0x00, 0x00, 0x00, 0x00, 0x7E, 0x7F, 0x80, 0x81,
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Test for %q failed:\nExpected:\n%v\nGot:\n%v", "EncodeUnsignedLong", expected, encoded)
	}
}

func TestEncodeUnsignedLongAsLength(t *testing.T) {
	ulong := getUnsignedLongForTest()

	encoded := EncodeUnsignedLongAsLength(ulong)
	expected := []byte{
		0x7E, 0x7F, 0x80, 0x81,
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Test for %q failed:\nExpected:\n%v\nGot:\n%v", "EncodeUnsignedLongAsLength", expected, encoded)
	}
}

func TestEncodeLong(t *testing.T) {
	ulong := getLongForTest()

	encoded := EncodeLong(ulong)
	expected := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0x81, 0x80, 0x7F, 0x7F,
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Test for %q failed:\nExpected:\n%v\nGot:\n%v", "EncodeLong", expected, encoded)
	}
}

func TestEncodeAttribute1(t *testing.T) {
	attribute := getAttributeForTest1()

	encoded := EncodeAttribute(attribute, true) // Because testing as C_GetAttributeValue
	expected := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, // CKA_SENSITIVE
		0x00, // Value not defined
		0x01, // Length defined
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Test for %q failed:\nExpected:\n%v\nGot:\n%v", "EncodeAttribute", expected, encoded)
	}
}

func TestEncodeAttribute2(t *testing.T) {
	attribute := getAttributeForTest2()

	encoded := EncodeAttribute(attribute, true) // Because testing as C_GetAttributeValue
	expected := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, // CKA_CHECK_VALUE
		0x00,                   // Value not defined
		0x01,                   // Length defined
		0x00, 0x00, 0x00, 0x10, // 16 bytes
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Test for %q failed:\nExpected:\n%v\nGot:\n%v", "EncodeAttribute", expected, encoded)
	}
}

func TestEncodeAttribute3(t *testing.T) {
	attribute := getAttributeForTest3()

	encoded := EncodeAttribute(attribute, true) // Because testing as C_GetAttributeValue
	expected := []byte{
		0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x06, 0x00, // CKA_ALLOWED_MECHANISMS
		0x00,                   // Value not defined
		0x01,                   // Length defined
		0x00, 0x00, 0x00, 0x40, // 64 mechanisms available

		// TODO: Strange bytes:
		// 0x00, // Value not defined
		// 0x00, // Length not defined (is output only)
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Test for %q failed:\nExpected:\n%v\nGot:\n%v", "EncodeAttribute", expected, encoded)
	}
}

func TestEncodeAttribute4(t *testing.T) {
	attribute := getAttributeForTest4()

	encoded := EncodeAttribute(attribute, true) // Because testing as C_GetAttributeValue
	expected := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // CKA_LABEL
		0x00,                   // Value not defined
		0x01,                   // Length defined
		0x00, 0x00, 0x00, 0x2A, // 42 bytes
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Test for %q failed:\nExpected:\n%v\nGot:\n%v", "EncodeAttribute", expected, encoded)
	}
}

func TestEncodeMechanism(t *testing.T) {
	mechanism := getMechanismForTest()

	encoded := EncodeMechanism(mechanism)
	expected := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x25, // CKM_DES_CBC_PAD
		0x01,                   // Parameter is present
		0x00, 0x00, 0x00, 0x0C, // Entire parameter length encoding
		0x00, 0x00, 0x00, 0x08, // ulParameterLen (for simple CK_BYTE array)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // pParameter, the IV
	}

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Test for %q failed:\nExpected:\n%v\nGot:\n%v", "EncodeMechanism", expected, encoded)
	}
}
