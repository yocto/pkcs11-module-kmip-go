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
