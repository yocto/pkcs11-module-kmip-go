package main

import "bytes"

// #include "cgo.h"
import "C"
import "context"
import "crypto/tls"
import "encoding/binary"
import "fmt"
import "os"
import "time"
import "unsafe"
import "github.com/google/uuid"
import "github.com/ovh/kmip-go"
import "github.com/ovh/kmip-go/kmipclient"
import "github.com/ovh/kmip-go/ttlv"

var cryptokiVersion = C.CK_VERSION{
	major: 3,
	minor: 1,
}

const profileVersion C.CK_BYTE = 0x01

var defaultInterface string = "PKCS 11"

var interfaces = []C.CK_INTERFACE{
	C.CK_INTERFACE{
		pInterfaceName: (*C.CK_CHAR)(unsafe.SliceData([]byte("PKCS 11"))),
		pFunctionList:  (C.CK_VOID_PTR)(&functionList30),
		flags:          0x0,
	},
}

var functionList = C.CK_FUNCTION_LIST{
	version: cryptokiVersion,
	// Version 2.0 and later
	C_Initialize:          (C.CK_C_Initialize)(C.C_Initialize),
	C_Finalize:            (C.CK_C_Finalize)(C.C_Finalize),
	C_GetInfo:             (C.CK_C_GetInfo)(C.C_GetInfo),
	C_GetFunctionList:     (C.CK_C_GetFunctionList)(C.C_GetFunctionList),
	C_GetSlotList:         (C.CK_C_GetSlotList)(C.C_GetSlotList),
	C_GetSlotInfo:         (C.CK_C_GetSlotInfo)(C.C_GetSlotInfo),
	C_GetTokenInfo:        (C.CK_C_GetTokenInfo)(C.C_GetTokenInfo),
	C_GetMechanismList:    (C.CK_C_GetMechanismList)(C.C_GetMechanismList),
	C_GetMechanismInfo:    (C.CK_C_GetMechanismInfo)(C.C_GetMechanismInfo),
	C_InitToken:           (C.CK_C_InitToken)(C.C_InitToken),
	C_InitPIN:             (C.CK_C_InitPIN)(C.C_InitPIN),
	C_SetPIN:              (C.CK_C_SetPIN)(C.C_SetPIN),
	C_OpenSession:         (C.CK_C_OpenSession)(C.C_OpenSession),
	C_CloseSession:        (C.CK_C_CloseSession)(C.C_CloseSession),
	C_CloseAllSessions:    (C.CK_C_CloseAllSessions)(C.C_CloseAllSessions),
	C_GetSessionInfo:      (C.CK_C_GetSessionInfo)(C.C_GetSessionInfo),
	C_GetOperationState:   (C.CK_C_GetOperationState)(C.C_GetOperationState),
	C_SetOperationState:   (C.CK_C_SetOperationState)(C.C_SetOperationState),
	C_Login:               (C.CK_C_Login)(C.C_Login),
	C_Logout:              (C.CK_C_Logout)(C.C_Logout),
	C_CreateObject:        (C.CK_C_CreateObject)(C.C_CreateObject),
	C_CopyObject:          (C.CK_C_CopyObject)(C.C_CopyObject),
	C_DestroyObject:       (C.CK_C_DestroyObject)(C.C_DestroyObject),
	C_GetObjectSize:       (C.CK_C_GetObjectSize)(C.C_GetObjectSize),
	C_GetAttributeValue:   (C.CK_C_GetAttributeValue)(C.C_GetAttributeValue),
	C_SetAttributeValue:   (C.CK_C_SetAttributeValue)(C.C_SetAttributeValue),
	C_FindObjectsInit:     (C.CK_C_FindObjectsInit)(C.C_FindObjectsInit),
	C_FindObjects:         (C.CK_C_FindObjects)(C.C_FindObjects),
	C_FindObjectsFinal:    (C.CK_C_FindObjectsFinal)(C.C_FindObjectsFinal),
	C_EncryptInit:         (C.CK_C_EncryptInit)(C.C_EncryptInit),
	C_Encrypt:             (C.CK_C_Encrypt)(C.C_Encrypt),
	C_EncryptUpdate:       (C.CK_C_EncryptUpdate)(C.C_EncryptUpdate),
	C_EncryptFinal:        (C.CK_C_EncryptFinal)(C.C_EncryptFinal),
	C_DecryptInit:         (C.CK_C_DecryptInit)(C.C_DecryptInit),
	C_Decrypt:             (C.CK_C_Decrypt)(C.C_Decrypt),
	C_DecryptUpdate:       (C.CK_C_DecryptUpdate)(C.C_DecryptUpdate),
	C_DecryptFinal:        (C.CK_C_DecryptFinal)(C.C_DecryptUpdate),
	C_DigestInit:          (C.CK_C_DigestInit)(C.C_DigestInit),
	C_Digest:              (C.CK_C_Digest)(C.C_Digest),
	C_DigestUpdate:        (C.CK_C_DigestUpdate)(C.C_DigestUpdate),
	C_DigestKey:           (C.CK_C_DigestKey)(C.C_DigestKey),
	C_DigestFinal:         (C.CK_C_DigestFinal)(C.C_DigestFinal),
	C_SignInit:            (C.CK_C_SignInit)(C.C_SignInit),
	C_Sign:                (C.CK_C_Sign)(C.C_Sign),
	C_SignUpdate:          (C.CK_C_SignUpdate)(C.C_SignUpdate),
	C_SignFinal:           (C.CK_C_SignFinal)(C.C_SignFinal),
	C_SignRecoverInit:     (C.CK_C_SignRecoverInit)(C.C_SignRecoverInit),
	C_SignRecover:         (C.CK_C_SignRecover)(C.C_SignRecover),
	C_VerifyInit:          (C.CK_C_VerifyInit)(C.C_VerifyInit),
	C_Verify:              (C.CK_C_Verify)(C.C_Verify),
	C_VerifyUpdate:        (C.CK_C_VerifyUpdate)(C.C_VerifyUpdate),
	C_VerifyFinal:         (C.CK_C_VerifyFinal)(C.C_VerifyFinal),
	C_VerifyRecoverInit:   (C.CK_C_VerifyRecoverInit)(C.C_VerifyRecoverInit),
	C_VerifyRecover:       (C.CK_C_VerifyRecover)(C.C_VerifyRecover),
	C_DigestEncryptUpdate: (C.CK_C_DigestEncryptUpdate)(C.C_DigestEncryptUpdate),
	C_DecryptDigestUpdate: (C.CK_C_DecryptDigestUpdate)(C.C_DecryptDigestUpdate),
	C_SignEncryptUpdate:   (C.CK_C_SignEncryptUpdate)(C.C_SignEncryptUpdate),
	C_DecryptVerifyUpdate: (C.CK_C_DecryptVerifyUpdate)(C.C_DecryptVerifyUpdate),
	C_GenerateKey:         (C.CK_C_GenerateKey)(C.C_GenerateKey),
	C_GenerateKeyPair:     (C.CK_C_GenerateKeyPair)(C.C_GenerateKeyPair),
	C_WrapKey:             (C.CK_C_WrapKey)(C.C_WrapKey),
	C_UnwrapKey:           (C.CK_C_UnwrapKey)(C.C_UnwrapKey),
	C_DeriveKey:           (C.CK_C_DeriveKey)(C.C_DeriveKey),
	C_SeedRandom:          (C.CK_C_SeedRandom)(C.C_SeedRandom),
	C_GenerateRandom:      (C.CK_C_GenerateRandom)(C.C_GenerateRandom),
	C_GetFunctionStatus:   (C.CK_C_GetFunctionStatus)(C.C_GetFunctionStatus),
	C_CancelFunction:      (C.CK_C_CancelFunction)(C.C_CancelFunction),
	// Version 2.1 and later
	C_WaitForSlotEvent: (C.CK_C_WaitForSlotEvent)(C.C_WaitForSlotEvent),
}

var functionList30 = C.CK_FUNCTION_LIST_3_0{
	version: cryptokiVersion,
	// Version 2.0 and later
	C_Initialize:          (C.CK_C_Initialize)(C.C_Initialize),
	C_Finalize:            (C.CK_C_Finalize)(C.C_Finalize),
	C_GetInfo:             (C.CK_C_GetInfo)(C.C_GetInfo),
	C_GetFunctionList:     (C.CK_C_GetFunctionList)(C.C_GetFunctionList),
	C_GetSlotList:         (C.CK_C_GetSlotList)(C.C_GetSlotList),
	C_GetSlotInfo:         (C.CK_C_GetSlotInfo)(C.C_GetSlotInfo),
	C_GetTokenInfo:        (C.CK_C_GetTokenInfo)(C.C_GetTokenInfo),
	C_GetMechanismList:    (C.CK_C_GetMechanismList)(C.C_GetMechanismList),
	C_GetMechanismInfo:    (C.CK_C_GetMechanismInfo)(C.C_GetMechanismInfo),
	C_InitToken:           (C.CK_C_InitToken)(C.C_InitToken),
	C_InitPIN:             (C.CK_C_InitPIN)(C.C_InitPIN),
	C_SetPIN:              (C.CK_C_SetPIN)(C.C_SetPIN),
	C_OpenSession:         (C.CK_C_OpenSession)(C.C_OpenSession),
	C_CloseSession:        (C.CK_C_CloseSession)(C.C_CloseSession),
	C_CloseAllSessions:    (C.CK_C_CloseAllSessions)(C.C_CloseAllSessions),
	C_GetSessionInfo:      (C.CK_C_GetSessionInfo)(C.C_GetSessionInfo),
	C_GetOperationState:   (C.CK_C_GetOperationState)(C.C_GetOperationState),
	C_SetOperationState:   (C.CK_C_SetOperationState)(C.C_SetOperationState),
	C_Login:               (C.CK_C_Login)(C.C_Login),
	C_Logout:              (C.CK_C_Logout)(C.C_Logout),
	C_CreateObject:        (C.CK_C_CreateObject)(C.C_CreateObject),
	C_CopyObject:          (C.CK_C_CopyObject)(C.C_CopyObject),
	C_DestroyObject:       (C.CK_C_DestroyObject)(C.C_DestroyObject),
	C_GetObjectSize:       (C.CK_C_GetObjectSize)(C.C_GetObjectSize),
	C_GetAttributeValue:   (C.CK_C_GetAttributeValue)(C.C_GetAttributeValue),
	C_SetAttributeValue:   (C.CK_C_SetAttributeValue)(C.C_SetAttributeValue),
	C_FindObjectsInit:     (C.CK_C_FindObjectsInit)(C.C_FindObjectsInit),
	C_FindObjects:         (C.CK_C_FindObjects)(C.C_FindObjects),
	C_FindObjectsFinal:    (C.CK_C_FindObjectsFinal)(C.C_FindObjectsFinal),
	C_EncryptInit:         (C.CK_C_EncryptInit)(C.C_EncryptInit),
	C_Encrypt:             (C.CK_C_Encrypt)(C.C_Encrypt),
	C_EncryptUpdate:       (C.CK_C_EncryptUpdate)(C.C_EncryptUpdate),
	C_EncryptFinal:        (C.CK_C_EncryptFinal)(C.C_EncryptFinal),
	C_DecryptInit:         (C.CK_C_DecryptInit)(C.C_DecryptInit),
	C_Decrypt:             (C.CK_C_Decrypt)(C.C_Decrypt),
	C_DecryptUpdate:       (C.CK_C_DecryptUpdate)(C.C_DecryptUpdate),
	C_DecryptFinal:        (C.CK_C_DecryptFinal)(C.C_DecryptUpdate),
	C_DigestInit:          (C.CK_C_DigestInit)(C.C_DigestInit),
	C_Digest:              (C.CK_C_Digest)(C.C_Digest),
	C_DigestUpdate:        (C.CK_C_DigestUpdate)(C.C_DigestUpdate),
	C_DigestKey:           (C.CK_C_DigestKey)(C.C_DigestKey),
	C_DigestFinal:         (C.CK_C_DigestFinal)(C.C_DigestFinal),
	C_SignInit:            (C.CK_C_SignInit)(C.C_SignInit),
	C_Sign:                (C.CK_C_Sign)(C.C_Sign),
	C_SignUpdate:          (C.CK_C_SignUpdate)(C.C_SignUpdate),
	C_SignFinal:           (C.CK_C_SignFinal)(C.C_SignFinal),
	C_SignRecoverInit:     (C.CK_C_SignRecoverInit)(C.C_SignRecoverInit),
	C_SignRecover:         (C.CK_C_SignRecover)(C.C_SignRecover),
	C_VerifyInit:          (C.CK_C_VerifyInit)(C.C_VerifyInit),
	C_Verify:              (C.CK_C_Verify)(C.C_Verify),
	C_VerifyUpdate:        (C.CK_C_VerifyUpdate)(C.C_VerifyUpdate),
	C_VerifyFinal:         (C.CK_C_VerifyFinal)(C.C_VerifyFinal),
	C_VerifyRecoverInit:   (C.CK_C_VerifyRecoverInit)(C.C_VerifyRecoverInit),
	C_VerifyRecover:       (C.CK_C_VerifyRecover)(C.C_VerifyRecover),
	C_DigestEncryptUpdate: (C.CK_C_DigestEncryptUpdate)(C.C_DigestEncryptUpdate),
	C_DecryptDigestUpdate: (C.CK_C_DecryptDigestUpdate)(C.C_DecryptDigestUpdate),
	C_SignEncryptUpdate:   (C.CK_C_SignEncryptUpdate)(C.C_SignEncryptUpdate),
	C_DecryptVerifyUpdate: (C.CK_C_DecryptVerifyUpdate)(C.C_DecryptVerifyUpdate),
	C_GenerateKey:         (C.CK_C_GenerateKey)(C.C_GenerateKey),
	C_GenerateKeyPair:     (C.CK_C_GenerateKeyPair)(C.C_GenerateKeyPair),
	C_WrapKey:             (C.CK_C_WrapKey)(C.C_WrapKey),
	C_UnwrapKey:           (C.CK_C_UnwrapKey)(C.C_UnwrapKey),
	C_DeriveKey:           (C.CK_C_DeriveKey)(C.C_DeriveKey),
	C_SeedRandom:          (C.CK_C_SeedRandom)(C.C_SeedRandom),
	C_GenerateRandom:      (C.CK_C_GenerateRandom)(C.C_GenerateRandom),
	C_GetFunctionStatus:   (C.CK_C_GetFunctionStatus)(C.C_GetFunctionStatus),
	C_CancelFunction:      (C.CK_C_CancelFunction)(C.C_CancelFunction),
	// Version 2.1 and later
	C_WaitForSlotEvent: (C.CK_C_WaitForSlotEvent)(C.C_WaitForSlotEvent),
	// Version 3.0 and later
	C_GetInterfaceList:    (C.CK_C_GetInterfaceList)(C.C_GetInterfaceList),
	C_GetInterface:        (C.CK_C_GetInterface)(C.C_GetInterface),
	C_LoginUser:           (C.CK_C_LoginUser)(C.C_LoginUser),
	C_SessionCancel:       (C.CK_C_SessionCancel)(C.C_SessionCancel),
	C_MessageEncryptInit:  (C.CK_C_MessageEncryptInit)(C.C_MessageEncryptInit),
	C_EncryptMessage:      (C.CK_C_EncryptMessage)(C.C_EncryptMessage),
	C_EncryptMessageBegin: (C.CK_C_EncryptMessageBegin)(C.C_EncryptMessageBegin),
	C_EncryptMessageNext:  (C.CK_C_EncryptMessageNext)(C.C_EncryptMessageNext),
	C_MessageEncryptFinal: (C.CK_C_MessageEncryptFinal)(C.C_MessageEncryptFinal),
	C_MessageDecryptInit:  (C.CK_C_MessageDecryptInit)(C.C_MessageDecryptInit),
	C_DecryptMessage:      (C.CK_C_DecryptMessage)(C.C_DecryptMessage),
	C_DecryptMessageBegin: (C.CK_C_DecryptMessageBegin)(C.C_DecryptMessageBegin),
	C_DecryptMessageNext:  (C.CK_C_DecryptMessageNext)(C.C_DecryptMessageBegin),
	C_MessageDecryptFinal: (C.CK_C_MessageDecryptFinal)(C.C_MessageDecryptFinal),
	C_MessageSignInit:     (C.CK_C_MessageSignInit)(C.C_MessageSignInit),
	C_SignMessage:         (C.CK_C_SignMessage)(C.C_SignMessage),
	C_SignMessageBegin:    (C.CK_C_SignMessageBegin)(C.C_SignMessageBegin),
	C_SignMessageNext:     (C.CK_C_SignMessageNext)(C.C_SignMessageNext),
	C_MessageSignFinal:    (C.CK_C_MessageSignFinal)(C.C_MessageSignFinal),
	C_MessageVerifyInit:   (C.CK_C_MessageVerifyInit)(C.C_MessageVerifyInit),
	C_VerifyMessage:       (C.CK_C_VerifyMessage)(C.C_VerifyMessage),
	C_VerifyMessageBegin:  (C.CK_C_VerifyMessageBegin)(C.C_VerifyMessageBegin),
	C_VerifyMessageNext:   (C.CK_C_VerifyMessageNext)(C.C_VerifyMessageNext),
	C_MessageVerifyFinal:  (C.CK_C_MessageVerifyFinal)(C.C_MessageVerifyFinal),
}

var client *kmipclient.Client

func main() {}

func getKMIPClient() (*kmipclient.Client, error) {
	if client != nil {
		return client, nil
	}

	createdClient, err := kmipclient.Dial(
		"yocto.com:5696",
		kmipclient.WithTlsConfig(&tls.Config{
			InsecureSkipVerify: true,
		}),
		kmipclient.WithMiddlewares(
			kmipclient.CorrelationValueMiddleware(uuid.NewString),
			kmipclient.DebugMiddleware(os.Stdout, nil),
			kmipclient.TimeoutMiddleware(500*time.Millisecond),
		),
	)
	client = createdClient

	return createdClient, err
}

func createKMIPRequest(pkcs1Interface any, pkcs11Function any, pkcs11InputParameters []byte) *kmip.UnknownPayload {
	var args ttlv.Struct

	if pkcs1Interface != nil {
		args = append(args, ttlv.Value{Tag: TagPKCS_11Interface, Value: pkcs1Interface.(string)})
	}
	if pkcs11Function != nil {
		args = append(args, ttlv.Value{Tag: TagPKCS_11Function, Value: pkcs11Function.(ttlv.Enum)})
	}
	if pkcs11InputParameters != nil {
		args = append(args, ttlv.Value{Tag: TagPKCS_11InputParameters, Value: pkcs11InputParameters})
	}

	return kmip.NewUnknownPayload(OperationPKCS_11, args...)
}

func processKMIP(pkcs1Interface any, pkcs11Function any, pkcs11InputParameters []byte) (any, any, ttlv.Enum) {
	if pkcs11Function == nil {
		fmt.Println("Function cannot be null.")
		return nil, nil, C.CKR_FUNCTION_FAILED
	}

	client, err := getKMIPClient()
	if err != nil {
		fmt.Println("Failed getting KMIP client:", err)
		return nil, nil, C.CKR_FUNCTION_FAILED
	}

	request := createKMIPRequest(pkcs1Interface, pkcs11Function, pkcs11InputParameters)

	response, err := client.Request(context.Background(), request)
	if err != nil {
		fmt.Println("Failed processing KMIP payload:", err)
		return nil, nil, C.CKR_FUNCTION_FAILED
	}

	fields := interface{}(response).(*kmip.UnknownPayload).Fields

	var fieldFunction *ttlv.Value
	var fieldOutputParameters *ttlv.Value
	var fieldReturnCode *ttlv.Value

	for _, field := range fields {
		if field.Tag == TagPKCS_11Function {
			fieldFunction = &field
			continue
		}
		if field.Tag == TagPKCS_11OutputParameters {
			fieldOutputParameters = &field
			continue
		}
		if field.Tag == TagPKCS_11ReturnCode {
			fieldReturnCode = &field
			continue
		}
	}

	if fieldFunction == nil {
		fmt.Println("Response does bot contain a function.")
		return nil, nil, C.CKR_FUNCTION_FAILED
	}
	if fieldReturnCode == nil {
		fmt.Println("Response does bot contain a return value.")
		return nil, nil, C.CKR_FUNCTION_FAILED
	}
	if (*fieldFunction).Value != pkcs11Function.(ttlv.Enum) {
		fmt.Println("Request function and response function are not the same.")
		return nil, nil, C.CKR_FUNCTION_FAILED
	}

	if fieldOutputParameters == nil {
		return (*fieldFunction).Value, nil, (*fieldReturnCode).Value.(ttlv.Enum)
	}
	return (*fieldFunction).Value, (*fieldOutputParameters).Value, (*fieldReturnCode).Value.(ttlv.Enum)
}

//export C_CancelFunction
func C_CancelFunction(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_CancelFunction(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_CancelFunction, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_CloseAllSessions
func C_CloseAllSessions(slotID C.CK_SLOT_ID) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_CloseAllSessions(slotID=%+v)\n", slotID)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_CloseAllSessions, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_CloseSession(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_CloseSession, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_CopyObject
func C_CopyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phNewObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_CopyObject(hSession=%+v, hObject=%+v, pTemplate=%+v, ulCount=%+v, phNewObject=%+v)\n", hSession, hObject, pTemplate, ulCount, phNewObject)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_CopyObject, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_CreateObject(hSession=%+v, pTemplate=%+v, ulCount=%+v, phObject=%+v)\n", hSession, pTemplate, ulCount, phObject)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_CreateObject, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, ulEncryptedDataLen C.CK_ULONG /*usEncryptedDataLen C.CK_USHORT (v1.0)*/, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR /*pusDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_Decrypt(hSession=%+v, pEncryptedData=%+v, ulEncryptedDataLen=%+v, pData=%+v, pulDataLen=%+v)\n", hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_Decrypt, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DecryptDigestUpdate
func C_DecryptDigestUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_DecryptDigestUpdate(hSession=%+v, pEncryptedPart=%+v, ulEncryptedPartLen=%+v, pPart=%+v, pulPartLen=%+v)\n", hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DecryptDigestUpdate, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DecryptFinal
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR /*usLastPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_DecryptFinal(hSession=%+v, pLastPart=%+v, pulLastPartLen=%+v)\n", hSession, pLastPart, pulLastPartLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DecryptFinal, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DecryptInit
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_DecryptInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DecryptInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DecryptMessage
func C_DecryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, ulCiphertextLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, pulPlaintextLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_DecryptMessage(hSession=%+v, ulParameterLen=%+v, ulAssociatedDataLen=%+v, ulCiphertextLen=%+v, pulPlaintextLen=%+v)\n", hSession, ulParameterLen, ulAssociatedDataLen, ulCiphertextLen, pulPlaintextLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DecryptMessage, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DecryptMessageBegin
func C_DecryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_DecryptMessageBegin(hSession=%+v, ulParameterLen=%+v, ulAssociatedDataLen=%+v)\n", hSession, ulParameterLen, ulAssociatedDataLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DecryptMessageBegin, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DecryptMessageNext
func C_DecryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, ulCiphertextPartLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, pulPlaintextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_DecryptMessageNext(hSession=%+v, ulParameterLen=%+v, ulCiphertextPartLen=%+v, pulPlaintextPartLen=%+v, flags=%+v)\n", hSession, ulParameterLen, ulCiphertextPartLen, pulPlaintextPartLen, flags)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DecryptMessageNext, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DecryptUpdate
func C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG /*usEncryptedPartLen C.CK_USHORT (v1.0)*/, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR /*pusPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_DecryptUpdate(hSession=%+v, pEncryptedPart=%+v, ulEncryptedPartLen=%+v, pPart=%+v, pulPartLen=%+v)\n", hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DecryptUpdate, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DecryptVerifyUpdate
func C_DecryptVerifyUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_DecryptVerifyUpdate(hSession=%+v, pEncryptedPart=%+v, ulEncryptedPartLen=%+v, pPart=%+v, pulPartLen=%+v)\n", hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DecryptVerifyUpdate, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DeriveKey
func C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG /*usAttributeCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_DeriveKey(hSession=%+v, pMechanism=%+v, hBaseKey=%+v, pTemplate=%+v, ulAttributeCount=%+v)\n", hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DeriveKey, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_DestroyObject(hSession=%+v, hObject=%+v)\n", hSession, hObject)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DestroyObject, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR /*pusDigestLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_Digest(hSession=%+v, pData=%+v, ulDataLen=%+v, pDigest=%+v, pulDigestLen=%+v)\n", hSession, pData, ulDataLen, pDigest, pulDigestLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_Digest, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DigestEncryptUpdate
func C_DigestEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_DigestEncryptUpdate(hSession=%+v, pPart=%+v, ulPartLen=%+v, pEncryptedPart=%+v, pulEncryptedPartLen=%+v)\n", hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DigestEncryptUpdate, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DigestFinal
func C_DigestFinal(hSession C.CK_SESSION_HANDLE, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR /*pusDigestLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_DigestFinal(hSession=%+v, pDigest=%+v, pulDigestLen=%+v)\n", hSession, pDigest, pulDigestLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DigestFinal, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_DigestInit(hSession=%+v, pMechanism=%+v)\n", hSession, pMechanism)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DigestInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DigestKey
func C_DigestKey(hSession C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_DigestKey(hSession=%+v, hKey=%+v)\n", hSession, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DigestKey, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_DigestUpdate
func C_DigestUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_DigestUpdate(hSession=%+v, pPart=%+v, ulPartLen=%+v)\n", hSession, pPart, ulPartLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_DigestUpdate, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_Encrypt
func C_Encrypt(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pEncryptedData C.CK_BYTE_PTR, pulEncryptedDataLen C.CK_ULONG_PTR /*pusEncryptedDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_Encrypt(hSession=%+v, pData=%+v, ulDataLen=%+v, pEncryptedData=%+v, pulEncryptedDataLen=%+v)\n", hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_Encrypt, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_EncryptFinal
func C_EncryptFinal(hSession C.CK_SESSION_HANDLE, pLastEncryptedPart C.CK_BYTE_PTR, pulLastEncryptedPartLen C.CK_ULONG_PTR /*pusEncryptedPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_EncryptFinal(hSession=%+v, pLastEncryptedPart=%+v, pulLastEncryptedPartLen=%+v)\n", hSession, pLastEncryptedPart, pulLastEncryptedPartLen)

	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeUnsignedLong(hSession))
	inBuffer.Write(EncodeByte(ConvertBooleanToByte(pLastEncryptedPart != nil)))   // Output pointer
	inBuffer.Write(EncodeUnsignedLongAsLength(*pulLastEncryptedPartLen)) // Output pointer length
	inputParameters := inBuffer.Bytes()

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_EncryptFinal, inputParameters)

	if outputParameters != nil {
		// TODO Handle output parameters

		return (C.CK_RV)(returnCode)
	}

	fmt.Println("Expected output parameters")
	return C.CKR_FUNCTION_FAILED
}

//export C_EncryptInit
func C_EncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_EncryptInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeUnsignedLong(hSession))
	inBuffer.Write(EncodeMechanism(*pMechanism))
	inBuffer.Write(EncodeUnsignedLong(hKey))
	inputParameters := inBuffer.Bytes()

	_, _, returnCode := processKMIP(nil, PKCS_11FunctionC_EncryptInit, inputParameters)

	return (C.CK_RV)(returnCode)
}

//export C_EncryptMessage
func C_EncryptMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG, pPlaintext C.CK_BYTE_PTR, ulPlaintextLen C.CK_ULONG, pCiphertext C.CK_BYTE_PTR, pulCiphertextLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_EncryptMessage(hSession=%+v, ulParameterLen=%+v, ulAssociatedDataLen=%+v, ulPlaintextLen=%+v, pulCiphertextLen=%+v)\n", hSession, ulParameterLen, ulAssociatedDataLen, ulPlaintextLen, pulCiphertextLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_EncryptMessage, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_EncryptMessageBegin
func C_EncryptMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pAssociatedData C.CK_BYTE_PTR, ulAssociatedDataLen C.CK_ULONG) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_EncryptMessageBegin(hSession=%+v, ulParameterLen=%+v, ulAssociatedDataLen=%+v)\n", hSession, ulParameterLen, ulAssociatedDataLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_EncryptMessageBegin, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_EncryptMessageNext
func C_EncryptMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pPlaintextPart C.CK_BYTE_PTR, ulPlaintextPartLen C.CK_ULONG, pCiphertextPart C.CK_BYTE_PTR, pulCiphertextPartLen C.CK_ULONG_PTR, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_EncryptMessageNext(hSession=%+v, ulParameterLen=%+v, ulPlaintextPartLen=%+v, ulCiphertextPartLen=%+v, flags=%+v)\n", hSession, ulParameterLen, ulPlaintextPartLen, pulCiphertextPartLen, flags)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_EncryptMessageNext, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_EncryptUpdate
func C_EncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR /*pusEncryptedPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_EncryptUpdate(hSession=%+v, pPart=%+v, ulPartLen=%+v, pEncryptedPart=%+v, pulEncryptedPartLen=%+v)\n", hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen)

	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeUnsignedLong(hSession))
	inBuffer.Write(EncodeUnsignedLongAsLength(ulPartLen)) // Moved up
	binary.Write(inBuffer, binary.BigEndian, pPart)
	// (See: Moved up)
	inBuffer.Write(EncodeByte(ConvertBooleanToByte(pEncryptedPart != nil)))   // Output pointer
	inBuffer.Write(EncodeUnsignedLongAsLength(*pulEncryptedPartLen)) // Output pointer length
	inputParameters := inBuffer.Bytes()

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_EncryptUpdate, inputParameters)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_Finalize(pReserved=%+v)\n", pReserved)

	_, _, returnCode := processKMIP(nil, PKCS_11FunctionC_Finalize, nil)

	return (C.CK_RV)(returnCode)
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG /*usMaxObjectCount C.CK_USHORT (v1.0)*/, pulObjectCount C.CK_ULONG_PTR /*pusObjectCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_FindObjects(hSession=%+v, ulMaxObjectCount=%+v)\n", hSession, ulMaxObjectCount)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_FindObjects, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_FindObjectsFinal(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_FindObjectsFinal, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_FindObjectsInit(hSession=%+v, pTemplate=%+v, ulCount=%+v)\n", hSession, pTemplate, ulCount)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_FindObjectsInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GenerateKey
func C_GenerateKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GenerateKey(hSession=%+v, pMechanism=%+v, pTemplate=%+v, ulCount=%+v)\n", hSession, pMechanism, pTemplate, ulCount)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GenerateKey, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG /*usPublicKeyAttributeCount C.CK_USHORT (v1.0)*/, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG /*usPrivateKeyAttributeCount C.CK_USHORT (v1.0)*/, phPrivateKey C.CK_OBJECT_HANDLE_PTR, phPublicKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GenerateKeyPair(hSession=%+v, pMechanism=%+v, ulPublic=%+v, ulPrivate=%+v)\n", hSession, pMechanism, ulPublicKeyAttributeCount, ulPrivateKeyAttributeCount)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GenerateKeyPair, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG /*usRandomLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GenerateRandom(hSession=%+v, ulRandomLen=%+v)\n", hSession, ulRandomLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GenerateRandom, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetAttributeValue(hSession=%+v, hObject=%+v, pTemplate=%+v, ulCount=%+v)\n", hSession, hObject, pTemplate, ulCount)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetAttributeValue, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_GetFunctionList(ppFunctionList=%+v)\n", ppFunctionList)

	if ppFunctionList == nil {
		fmt.Println("Function list pointer cannot be null.")
		return C.CKR_ARGUMENTS_BAD
	}

	*ppFunctionList = &functionList

	return C.CKR_OK
}

//export C_GetFunctionStatus
func C_GetFunctionStatus(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetFunctionStatus(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetFunctionStatus, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GetInfo
func C_GetInfo(pInfo C.CK_INFO_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetInfo(pInfo=%+v)\n", pInfo)

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetInfo, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GetInterface
func C_GetInterface(pInterfaceName C.CK_UTF8CHAR_PTR, pVersion C.CK_VERSION_PTR, ppInterface C.CK_INTERFACE_PTR_PTR, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_GetInterface(pInterfaceName=%+v, pVersion=%+v, flags=%+v)\n", pInterfaceName, pVersion, flags)

	var matchingInterface C.CK_INTERFACE_PTR

	for _, interfaceItem := range interfaces {
		var interfaceNameMatches bool = false
		var versionMatches bool = false
		var flagMatches bool = false

		if pInterfaceName == nil {
			interfaceNameMatches = true
		} else {
			interfaceName := (C.CK_UTF8CHAR_PTR)(interfaceItem.pInterfaceName)
			interfaceNameMatches = *pInterfaceName == *interfaceName
		}
		if pVersion == nil {
			versionMatches = true
		} else {
			version := (C.CK_VERSION_PTR)(interfaceItem.pFunctionList)
			interfaceNameMatches = (*pVersion).major == version.major && (*pVersion).minor == version.minor
		}
		if flags == 0x0 {
			flagMatches = true
		} else {
			flagMatches = flags == interfaceItem.flags
		}

		if interfaceNameMatches && versionMatches && flagMatches {
			matchingInterface = &interfaceItem
			break
		}
	}

	if matchingInterface != nil {
		*ppInterface = matchingInterface
		return C.CKR_OK
	}
	return C.CKR_ARGUMENTS_BAD
}

//export C_GetInterfaceList
func C_GetInterfaceList(pInterfaceList C.CK_INTERFACE_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_GetInterfaceList(pulCount=%+v)\n", pulCount)

	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	var INTERFACE_COUNT = len(interfaces)

	if pInterfaceList == nil {
		*pulCount = (C.CK_ULONG)(INTERFACE_COUNT)
		return C.CKR_OK
	}

	const CK_INTERFACE_SIZE = unsafe.Sizeof(new(C.CK_INTERFACE))

	*pulCount = (C.CK_ULONG)(INTERFACE_COUNT)
	if int(unsafe.Sizeof(*pInterfaceList)) < INTERFACE_COUNT*int(CK_INTERFACE_SIZE) {
		return C.CKR_BUFFER_TOO_SMALL
	}

	pointerAsSliceDestination := unsafe.Slice(pInterfaceList, INTERFACE_COUNT)
	copy(pointerAsSliceDestination, interfaces)

	return C.CKR_OK
}

//export C_GetMechanismInfo
func C_GetMechanismInfo(slotID C.CK_SLOT_ID, _type C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetMechanismInfo(slotID=%+v, type=%+v)\n", slotID, _type)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetMechanismInfo, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GetMechanismList
func C_GetMechanismList(slotID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR /*pusCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetMechanismList(slotID=%+v, pulCount=%+v)\n", slotID, pulCount)

	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeUnsignedLong(slotID))
	inBuffer.Write(EncodeByte(ConvertBooleanToByte(pMechanismList != nil)))
	inBuffer.Write(EncodeUnsignedLongAsLength(*pulCount))
	inputParameters := inBuffer.Bytes()

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetMechanismList, inputParameters)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GetObjectSize
func C_GetObjectSize(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pulSize C.CK_ULONG_PTR /*pusSize C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetObjectSize(hSession=%+v, hObject=%+v)\n", hSession, hObject)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetObjectSize, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GetOperationState
func C_GetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, pulOperationStateLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_GetOperationState(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetOperationState, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetSessionInfo(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetSessionInfo, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_GetSlotInfo
func C_GetSlotInfo(slotID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetSlotInfo(slotID=%+v)\n", slotID)

	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeUnsignedLong(slotID))
	inputParameters := inBuffer.Bytes()

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetSlotInfo, inputParameters)

	if outputParameters != nil {
		outBuffer := bytes.NewBuffer(outputParameters.([]byte))

		var slotInfoResponse [104]byte

		err := binary.Read(outBuffer, binary.BigEndian, &slotInfoResponse)
		if err != nil {
			fmt.Println("Slot info structure expected.")
			// Ignore error for now
			//return C.CKR_FUNCTION_FAILED
		}

		*pInfo = C.CK_SLOT_INFO{
			flags: C.CKF_TOKEN_PRESENT,
		}

		return (C.CK_RV)(returnCode)
	}

	fmt.Println("Expected output parameters")
	return C.CKR_FUNCTION_FAILED
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR /*pusCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetSlotList(tokenPresent=%+v, pulCount=%+v)\n", tokenPresent, pulCount)

	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeByte(tokenPresent))
	inBuffer.Write(EncodeByte(ConvertBooleanToByte(pSlotList != nil)))
	inBuffer.Write(EncodeUnsignedLongAsLength(*pulCount))
	inputParameters := inBuffer.Bytes()

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetSlotList, inputParameters)

	if outputParameters != nil {
		outBuffer := bytes.NewBuffer(outputParameters.([]byte))

		//TODO Improve

		var tokenPresentResponse C.CK_BBOOL
		var slotCountResponse uint32

		err := binary.Read(outBuffer, binary.BigEndian, &tokenPresentResponse)
		if err != nil {
			fmt.Println("Boolean byte expected.")
			return C.CKR_FUNCTION_FAILED
		}
		err = binary.Read(outBuffer, binary.BigEndian, &slotCountResponse)
		if err != nil {
			fmt.Println("32-bit integer expected.")
			return C.CKR_FUNCTION_FAILED
		}

		if tokenPresent != tokenPresentResponse {
			if tokenPresent != 0x00 {
				fmt.Println("Slot tokens expected but not present in response.")
			} else {
				fmt.Println("Slot tokens not expected but present in response.")
			}
			return C.CKR_FUNCTION_FAILED
		}

		*pulCount = C.CK_ULONG(slotCountResponse)

		if tokenPresentResponse != 0x00 {
			pointerAsSliceDestination := unsafe.Slice(pSlotList, slotCountResponse)

			for i := uint32(0); i < slotCountResponse; i++ {
				var slotInfo uint64

				err := binary.Read(outBuffer, binary.BigEndian, &slotInfo)
				if err != nil {
					fmt.Println("64-bit slot id expected.")
					return C.CKR_FUNCTION_FAILED
				}

				pointerAsSliceDestination[i] = C.CK_SLOT_ID(slotInfo)
			}
		}

		return (C.CK_RV)(returnCode)
	}

	fmt.Println("Expected output parameters")
	return C.CKR_FUNCTION_FAILED
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_GetTokenInfo(slotID=%+v)\n", slotID)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_GetTokenInfo, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR /*pReserved C.CK_VOID_PTR (v1.0,v2.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_Initialize(pInitArgs=%+v)\n", pInitArgs)

	inBuffer := new(bytes.Buffer)
	inBuffer.Write(EncodeByte(profileVersion))
	inputParameters := inBuffer.Bytes()

	_, _, returnCode := processKMIP(nil, PKCS_11FunctionC_Initialize, inputParameters)

	return (C.CK_RV)(returnCode)
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_UTF8CHAR_PTR /*pPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_InitPIN(hSession=%+v, ulPinLen=%+v)\n", hSession, ulPinLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_InitPIN, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_UTF8CHAR_PTR /*pPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/, pLabel C.CK_UTF8CHAR_PTR /*pLabel C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_InitToken(slotID=%+v, ulPinLen=%+v)\n", slotID, ulPinLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_InitToken, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR /*pPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_Login(hSession=%+v, userType=%+v, ulPinLen=%+v)\n", hSession, userType, ulPinLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_Login, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_LoginUser
func C_LoginUser(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pUsername C.CK_UTF8CHAR_PTR, ulUsernameLen C.CK_ULONG) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_LoginUser(hSession=%+v, userType=%+v, ulPinLen=%+v, ulUsernameLen=%+v)\n", hSession, userType, ulPinLen, ulUsernameLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_LoginUser, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_Logout(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_Logout, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_MessageDecryptFinal
func C_MessageDecryptFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_MessageDecryptFinal(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_MessageDecryptFinal, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_MessageDecryptInit
func C_MessageDecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_MessageDecryptInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_MessageDecryptInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_MessageEncryptFinal
func C_MessageEncryptFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_MessageEncryptFinal(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_MessageEncryptFinal, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_MessageEncryptInit
func C_MessageEncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_MessageEncryptInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_MessageEncryptInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_MessageSignFinal
func C_MessageSignFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_MessageSignFinal(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_MessageSignFinal, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_MessageSignInit
func C_MessageSignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_MessageSignInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_MessageSignInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_MessageVerifyFinal
func C_MessageVerifyFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_MessageVerifyFinal(hSession=%+v)\n", hSession)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_MessageVerifyFinal, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_MessageVerifyInit
func C_MessageVerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_MessageVerifyInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_MessageVerifyInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_OpenSession
func C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, Notify C.CK_NOTIFY /*CK_RV (*Notify)(CK_SESSION_HANDLE hSession, C.CK_NOTIFICATION event, C.CK_VOID_PTR pApplication) (v1.0)*/, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_OpenSession(slotID=%+v, flags=%+v)\n", slotID, flags)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_OpenSession, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG /*usSeedLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_SeedRandom(hSession=%+v, ulSeedLen=%+v)\n", hSession, ulSeedLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SeedRandom, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SessionCancel
func C_SessionCancel(hSession C.CK_SESSION_HANDLE, flags C.CK_FLAGS) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_SessionCancel(hSession=%+v, flags=%+v)\n", hSession, flags)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SessionCancel, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_SetAttributeValue(hSession=%+v, hObject=%+v, pTemplate=%+v, ulCount=%+v)\n", hSession, hObject, pTemplate, ulCount)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SetAttributeValue, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SetOperationState
func C_SetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, ulOperationStateLen C.CK_ULONG, hEncryptionKey C.CK_OBJECT_HANDLE, hAuthenticationKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_SetOperationState(hSession=%+v, ulOperationStateLen=%+v)\n", hSession, ulOperationStateLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SetOperationState, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_UTF8CHAR_PTR /*pOldPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulOldLen C.CK_ULONG /*usOldLen C.CK_USHORT (v1.0)*/, pNewPin C.CK_UTF8CHAR_PTR /*pNewPin C.CK_CHAR_PTR (v1.0,v2.0,v2.01,v2.10)*/, ulNewLen C.CK_ULONG /*usNewLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_SetPIN(hSession=%+v, ulOldLen=%+v, ulNewLen=%+v)\n", hSession, ulOldLen, ulNewLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SetPIN, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_Sign(hSession=%+v, pData=%+v, ulDataLen=%+v, pulSignatureLen=%+v)\n", hSession, pData, ulDataLen, pulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_Sign, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SignEncryptUpdate
func C_SignEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	fmt.Printf("Function called: C_SignEncryptUpdate(hSession=%+v, pPart=%+v, ulPartLen=%+v, pulEncryptedPartLen=%+v)\n", hSession, pPart, ulPartLen, pulEncryptedPartLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SignEncryptUpdate, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_SignFinal(hSession=%+v, pulSignatureLen=%+v)\n", hSession, pulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SignFinal, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_SignInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SignInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SignMessage
func C_SignMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_SignMessage(hSession=%+v, ulParameterLen=%+v, ulDataLen=%+v, pulSignatureLen=%+v)\n", hSession, ulParameterLen, ulDataLen, pulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SignMessage, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SignMessageBegin
func C_SignMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_SignMessageBegin(hSession=%+v, ulParameterLen=%+v)\n", hSession, ulParameterLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SignMessageBegin, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SignMessageNext
func C_SignMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pDataPart C.CK_BYTE_PTR, ulDataPartLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_SignMessageNext(hSession=%+v, ulParameterLen=%+v, ulDataPartLen=%+v, pulSignatureLen=%+v)\n", hSession, ulParameterLen, ulDataPartLen, pulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SignMessageNext, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SignRecover
func C_SignRecover(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_SignRecover(hSession=%+v, pData=%+v, ulDataLen=%+v, pulSignatureLen=%+v)\n", hSession, pData, ulDataLen, pulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SignRecover, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SignRecoverInit
func C_SignRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_SignRecoverInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SignRecoverInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_SignUpdate(hSession=%+v, pPart=%+v, ulPartLen=%+v)\n", hSession, pPart, ulPartLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_SignUpdate, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_UnwrapKey
func C_UnwrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, ulWrappedKeyLen C.CK_ULONG /*usWrappedKeyLen C.CK_USHORT (v1.0)*/, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG /*usAttributeCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_UnwrapKey(hSession=%+v, pMechanism=%+v, hUnwrappingKey=%+v, ulWrappedKeyLen=%+v, ulAttributeCount=%+v)\n", hSession, pMechanism, hUnwrappingKey, ulWrappedKeyLen, ulAttributeCount)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_UnwrapKey, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_Verify(hSession=%+v, pData=%+v, ulDataLen=%+v, pSignature=%+v, ulSignatureLen=%+v)\n", hSession, pData, ulDataLen, pSignature, ulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_Verify, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_VerifyFinal(hSession=%+v, pSignature=%+v, ulSignatureLen=%+v)\n", hSession, pSignature, ulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_VerifyFinal, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_VerifyInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_VerifyInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_VerifyMessage
func C_VerifyMessage(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_VerifyMessage(hSession=%+v, ulParameterLen=%+v, ulDataLen=%+v, ulSignatureLen=%+v)\n", hSession, ulParameterLen, ulDataLen, ulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_VerifyMessage, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_VerifyMessageBegin
func C_VerifyMessageBegin(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_VerifyMessageBegin(hSession=%+v, ulParameterLen=%+v)\n", hSession, ulParameterLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_VerifyMessageBegin, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_VerifyMessageNext
func C_VerifyMessageNext(hSession C.CK_SESSION_HANDLE, pParameter C.CK_VOID_PTR, ulParameterLen C.CK_ULONG, pDataPart C.CK_BYTE_PTR, ulDataPartLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV { // Since v3.0
	fmt.Printf("Function called: C_VerifyMessageNext(hSession=%+v, ulParameterLen=%+v, ulDataPartLen=%+v, ulSignatureLen=%+v)\n", hSession, ulParameterLen, ulDataPartLen, ulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_VerifyMessageNext, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_VerifyRecover
func C_VerifyRecover(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR /*pusDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_VerifyRecover(hSession=%+v, pSignature=%+v, ulSignatureLen=%+v)\n", hSession, pSignature, ulSignatureLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_VerifyRecover, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_VerifyRecoverInit(hSession=%+v, pMechanism=%+v, hKey=%+v)\n", hSession, pMechanism, hKey)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_VerifyRecoverInit, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_VerifyUpdate(hSession=%+v, pPart=%+v, ulPartLen=%+v)\n", hSession, pPart, ulPartLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_VerifyUpdate, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(flags C.CK_FLAGS, pSlot C.CK_SLOT_ID_PTR, pReserved C.CK_VOID_PTR) C.CK_RV { // Since v2.01
	fmt.Printf("Function called: C_WaitForSlotEvent(flags=%+v, pSlot=%+v, pReserved=%+v)\n", flags, pSlot, pReserved)

	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WrapKey
func C_WrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pulWrappedKeyLen C.CK_ULONG_PTR /*pusWrappedKeyLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	fmt.Printf("Function called: C_WrapKey(hSession=%+v, pMechanism=%+v, hWrappingKey=%+v, hKey=%+v, pulWrappedKeyLen=%+v)\n", hSession, pMechanism, hWrappingKey, hKey, pulWrappedKeyLen)

	// TODO Handle input parameters

	_, outputParameters, returnCode := processKMIP(nil, PKCS_11FunctionC_WrapKey, nil)

	if outputParameters != nil {
		// TODO Handle output parameters
	}

	return (C.CK_RV)(returnCode)
}
