package main

import "github.com/ovh/kmip-go"
import "github.com/ovh/kmip-go/ttlv"

const (
	OperationPKCS_11 kmip.Operation = 0x00000033
)

const (
	TagPKCS_11Interface        = 0x420159
	TagPKCS_11Function         = 0x42015A
	TagPKCS_11InputParameters  = 0x42015B
	TagPKCS_11OutputParameters = 0x42015C
	TagPKCS_11ReturnCode       = 0x42015D
)

type PKCS_11Function uint32

const (
	// Version 2.0 and later
	PKCS_11FunctionC_Initialize          PKCS_11Function = 0x00000001
	PKCS_11FunctionC_Finalize            PKCS_11Function = 0x00000002
	PKCS_11FunctionC_GetInfo             PKCS_11Function = 0x00000003
	PKCS_11FunctionC_GetFunctionList     PKCS_11Function = 0x00000004
	PKCS_11FunctionC_GetSlotList         PKCS_11Function = 0x00000005
	PKCS_11FunctionC_GetSlotInfo         PKCS_11Function = 0x00000006
	PKCS_11FunctionC_GetTokenInfo        PKCS_11Function = 0x00000007
	PKCS_11FunctionC_GetMechanismList    PKCS_11Function = 0x00000008
	PKCS_11FunctionC_GetMechanismInfo    PKCS_11Function = 0x00000009
	PKCS_11FunctionC_InitToken           PKCS_11Function = 0x0000000A
	PKCS_11FunctionC_InitPIN             PKCS_11Function = 0x0000000B
	PKCS_11FunctionC_SetPIN              PKCS_11Function = 0x0000000C
	PKCS_11FunctionC_OpenSession         PKCS_11Function = 0x0000000D
	PKCS_11FunctionC_CloseSession        PKCS_11Function = 0x0000000E
	PKCS_11FunctionC_CloseAllSessions    PKCS_11Function = 0x0000000F
	PKCS_11FunctionC_GetSessionInfo      PKCS_11Function = 0x00000010
	PKCS_11FunctionC_GetOperationState   PKCS_11Function = 0x00000011
	PKCS_11FunctionC_SetOperationState   PKCS_11Function = 0x00000012
	PKCS_11FunctionC_Login               PKCS_11Function = 0x00000013
	PKCS_11FunctionC_Logout              PKCS_11Function = 0x00000014
	PKCS_11FunctionC_CreateObject        PKCS_11Function = 0x00000015
	PKCS_11FunctionC_CopyObject          PKCS_11Function = 0x00000016
	PKCS_11FunctionC_DestroyObject       PKCS_11Function = 0x00000017
	PKCS_11FunctionC_GetObjectSize       PKCS_11Function = 0x00000018
	PKCS_11FunctionC_GetAttributeValue   PKCS_11Function = 0x00000019
	PKCS_11FunctionC_SetAttributeValue   PKCS_11Function = 0x0000001A
	PKCS_11FunctionC_FindObjectsInit     PKCS_11Function = 0x0000001B
	PKCS_11FunctionC_FindObjects         PKCS_11Function = 0x0000001C
	PKCS_11FunctionC_FindObjectsFinal    PKCS_11Function = 0x0000001D
	PKCS_11FunctionC_EncryptInit         PKCS_11Function = 0x0000001E
	PKCS_11FunctionC_Encrypt             PKCS_11Function = 0x0000001F
	PKCS_11FunctionC_EncryptUpdate       PKCS_11Function = 0x00000020
	PKCS_11FunctionC_EncryptFinal        PKCS_11Function = 0x00000021
	PKCS_11FunctionC_DecryptInit         PKCS_11Function = 0x00000022
	PKCS_11FunctionC_Decrypt             PKCS_11Function = 0x00000023
	PKCS_11FunctionC_DecryptUpdate       PKCS_11Function = 0x00000024
	PKCS_11FunctionC_DecryptFinal        PKCS_11Function = 0x00000025
	PKCS_11FunctionC_DigestInit          PKCS_11Function = 0x00000026
	PKCS_11FunctionC_Digest              PKCS_11Function = 0x00000027
	PKCS_11FunctionC_DigestUpdate        PKCS_11Function = 0x00000028
	PKCS_11FunctionC_DigestKey           PKCS_11Function = 0x00000029
	PKCS_11FunctionC_DigestFinal         PKCS_11Function = 0x0000002A
	PKCS_11FunctionC_SignInit            PKCS_11Function = 0x0000002B
	PKCS_11FunctionC_Sign                PKCS_11Function = 0x0000002C
	PKCS_11FunctionC_SignUpdate          PKCS_11Function = 0x0000002D
	PKCS_11FunctionC_SignFinal           PKCS_11Function = 0x0000002E
	PKCS_11FunctionC_SignRecoverInit     PKCS_11Function = 0x0000002F
	PKCS_11FunctionC_SignRecover         PKCS_11Function = 0x00000030
	PKCS_11FunctionC_VerifyInit          PKCS_11Function = 0x00000031
	PKCS_11FunctionC_Verify              PKCS_11Function = 0x00000032
	PKCS_11FunctionC_VerifyUpdate        PKCS_11Function = 0x00000033
	PKCS_11FunctionC_VerifyFinal         PKCS_11Function = 0x00000034
	PKCS_11FunctionC_VerifyRecoverInit   PKCS_11Function = 0x00000035
	PKCS_11FunctionC_VerifyRecover       PKCS_11Function = 0x00000036
	PKCS_11FunctionC_DigestEncryptUpdate PKCS_11Function = 0x00000037
	PKCS_11FunctionC_DecryptDigestUpdate PKCS_11Function = 0x00000038
	PKCS_11FunctionC_SignEncryptUpdate   PKCS_11Function = 0x00000039
	PKCS_11FunctionC_DecryptVerifyUpdate PKCS_11Function = 0x0000003A
	PKCS_11FunctionC_GenerateKey         PKCS_11Function = 0x0000003B
	PKCS_11FunctionC_GenerateKeyPair     PKCS_11Function = 0x0000003C
	PKCS_11FunctionC_WrapKey             PKCS_11Function = 0x0000003D
	PKCS_11FunctionC_UnwrapKey           PKCS_11Function = 0x0000003E
	PKCS_11FunctionC_DeriveKey           PKCS_11Function = 0x0000003F
	PKCS_11FunctionC_SeedRandom          PKCS_11Function = 0x00000040
	PKCS_11FunctionC_GenerateRandom      PKCS_11Function = 0x00000041
	PKCS_11FunctionC_GetFunctionStatus   PKCS_11Function = 0x00000042
	PKCS_11FunctionC_CancelFunction      PKCS_11Function = 0x00000043
	// Version 2.1 and later
	PKCS_11FunctionC_WaitForSlotEvent PKCS_11Function = 0x00000044
	// Version 3.0 and later
	PKCS_11FunctionC_GetInterfaceList    PKCS_11Function = 0x00000045
	PKCS_11FunctionC_GetInterface        PKCS_11Function = 0x00000046
	PKCS_11FunctionC_LoginUser           PKCS_11Function = 0x00000047
	PKCS_11FunctionC_SessionCancel       PKCS_11Function = 0x00000048
	PKCS_11FunctionC_MessageEncryptInit  PKCS_11Function = 0x00000049
	PKCS_11FunctionC_EncryptMessage      PKCS_11Function = 0x0000004A
	PKCS_11FunctionC_EncryptMessageBegin PKCS_11Function = 0x0000004B
	PKCS_11FunctionC_EncryptMessageNext  PKCS_11Function = 0x0000004C
	PKCS_11FunctionC_MessageEncryptFinal PKCS_11Function = 0x0000004D
	PKCS_11FunctionC_MessageDecryptInit  PKCS_11Function = 0x0000004E
	PKCS_11FunctionC_DecryptMessage      PKCS_11Function = 0x0000004F
	PKCS_11FunctionC_DecryptMessageBegin PKCS_11Function = 0x00000050
	PKCS_11FunctionC_DecryptMessageNext  PKCS_11Function = 0x00000051
	PKCS_11FunctionC_MessageDecryptFinal PKCS_11Function = 0x00000052
	PKCS_11FunctionC_MessageSignInit     PKCS_11Function = 0x00000053
	PKCS_11FunctionC_SignMessage         PKCS_11Function = 0x00000054
	PKCS_11FunctionC_SignMessageBegin    PKCS_11Function = 0x00000055
	PKCS_11FunctionC_SignMessageNext     PKCS_11Function = 0x00000056
	PKCS_11FunctionC_MessageSignFinal    PKCS_11Function = 0x00000057
	PKCS_11FunctionC_MessageVerifyInit   PKCS_11Function = 0x00000058
	PKCS_11FunctionC_VerifyMessage       PKCS_11Function = 0x00000059
	PKCS_11FunctionC_VerifyMessageBegin  PKCS_11Function = 0x0000005A
	PKCS_11FunctionC_VerifyMessageNext   PKCS_11Function = 0x0000005B
	PKCS_11FunctionC_MessageVerifyFinal  PKCS_11Function = 0x0000005C
)

type PKCS_11ReturnCode uint32

const (
	PKCS_11ReturnCodeOK              PKCS_11ReturnCode = 0x00000000
	PKCS_11ReturnCodeCANCEL          PKCS_11ReturnCode = 0x00000001
	PKCS_11ReturnCodeHOST_MEMORY     PKCS_11ReturnCode = 0x00000002
	PKCS_11ReturnCodeSLOT_ID_INVALID PKCS_11ReturnCode = 0x00000003

	PKCS_11ReturnCodeGENERAL_ERROR   PKCS_11ReturnCode = 0x00000005
	PKCS_11ReturnCodeFUNCTION_FAILED PKCS_11ReturnCode = 0x00000006

	PKCS_11ReturnCodeARGUMENTS_BAD          PKCS_11ReturnCode = 0x00000007
	PKCS_11ReturnCodeNO_EVENT               PKCS_11ReturnCode = 0x00000008
	PKCS_11ReturnCodeNEED_TO_CREATE_THREADS PKCS_11ReturnCode = 0x00000009
	PKCS_11ReturnCodeCANT_LOCK              PKCS_11ReturnCode = 0x0000000A

	PKCS_11ReturnCodeATTRIBUTE_READ_ONLY     PKCS_11ReturnCode = 0x00000010
	PKCS_11ReturnCodeATTRIBUTE_SENSITIVE     PKCS_11ReturnCode = 0x00000011
	PKCS_11ReturnCodeATTRIBUTE_TYPE_INVALID  PKCS_11ReturnCode = 0x00000012
	PKCS_11ReturnCodeATTRIBUTE_VALUE_INVALID PKCS_11ReturnCode = 0x00000013

	PKCS_11ReturnCodeACTION_PROHIBITED PKCS_11ReturnCode = 0x0000001B

	PKCS_11ReturnCodeDATA_INVALID             PKCS_11ReturnCode = 0x00000020
	PKCS_11ReturnCodeDATA_LEN_RANGE           PKCS_11ReturnCode = 0x00000021
	PKCS_11ReturnCodeDEVICE_ERROR             PKCS_11ReturnCode = 0x00000030
	PKCS_11ReturnCodeDEVICE_MEMORY            PKCS_11ReturnCode = 0x00000031
	PKCS_11ReturnCodeDEVICE_REMOVED           PKCS_11ReturnCode = 0x00000032
	PKCS_11ReturnCodeENCRYPTED_DATA_INVALID   PKCS_11ReturnCode = 0x00000040
	PKCS_11ReturnCodeENCRYPTED_DATA_LEN_RANGE PKCS_11ReturnCode = 0x00000041
	PKCS_11ReturnCodeAEAD_DECRYPT_FAILED      PKCS_11ReturnCode = 0x00000042
	PKCS_11ReturnCodeFUNCTION_CANCELED        PKCS_11ReturnCode = 0x00000050
	PKCS_11ReturnCodeFUNCTION_NOT_PARALLEL    PKCS_11ReturnCode = 0x00000051

	PKCS_11ReturnCodeFUNCTION_NOT_SUPPORTED PKCS_11ReturnCode = 0x00000054

	PKCS_11ReturnCodeKEY_HANDLE_INVALID PKCS_11ReturnCode = 0x00000060

	PKCS_11ReturnCodeKEY_SIZE_RANGE        PKCS_11ReturnCode = 0x00000062
	PKCS_11ReturnCodeKEY_TYPE_INCONSISTENT PKCS_11ReturnCode = 0x00000063

	PKCS_11ReturnCodeKEY_NOT_NEEDED             PKCS_11ReturnCode = 0x00000064
	PKCS_11ReturnCodeKEY_CHANGED                PKCS_11ReturnCode = 0x00000065
	PKCS_11ReturnCodeKEY_NEEDED                 PKCS_11ReturnCode = 0x00000066
	PKCS_11ReturnCodeKEY_INDIGESTIBLE           PKCS_11ReturnCode = 0x00000067
	PKCS_11ReturnCodeKEY_FUNCTION_NOT_PERMITTED PKCS_11ReturnCode = 0x00000068
	PKCS_11ReturnCodeKEY_NOT_WRAPPABLE          PKCS_11ReturnCode = 0x00000069
	PKCS_11ReturnCodeKEY_UNEXTRACTABLE          PKCS_11ReturnCode = 0x0000006A

	PKCS_11ReturnCodeMECHANISM_INVALID       PKCS_11ReturnCode = 0x00000070
	PKCS_11ReturnCodeMECHANISM_PARAM_INVALID PKCS_11ReturnCode = 0x00000071

	PKCS_11ReturnCodeOBJECT_HANDLE_INVALID     PKCS_11ReturnCode = 0x00000082
	PKCS_11ReturnCodeOPERATION_ACTIVE          PKCS_11ReturnCode = 0x00000090
	PKCS_11ReturnCodeOPERATION_NOT_INITIALIZED PKCS_11ReturnCode = 0x00000091
	PKCS_11ReturnCodePIN_INCORRECT             PKCS_11ReturnCode = 0x000000A0
	PKCS_11ReturnCodePIN_INVALID               PKCS_11ReturnCode = 0x000000A1
	PKCS_11ReturnCodePIN_LEN_RANGE             PKCS_11ReturnCode = 0x000000A2

	PKCS_11ReturnCodePIN_EXPIRED PKCS_11ReturnCode = 0x000000A3
	PKCS_11ReturnCodePIN_LOCKED  PKCS_11ReturnCode = 0x000000A4

	PKCS_11ReturnCodeSESSION_CLOSED                 PKCS_11ReturnCode = 0x000000B0
	PKCS_11ReturnCodeSESSION_COUNT                  PKCS_11ReturnCode = 0x000000B1
	PKCS_11ReturnCodeSESSION_HANDLE_INVALID         PKCS_11ReturnCode = 0x000000B3
	PKCS_11ReturnCodeSESSION_PARALLEL_NOT_SUPPORTED PKCS_11ReturnCode = 0x000000B4
	PKCS_11ReturnCodeSESSION_READ_ONLY              PKCS_11ReturnCode = 0x000000B5
	PKCS_11ReturnCodeSESSION_EXISTS                 PKCS_11ReturnCode = 0x000000B6

	PKCS_11ReturnCodeSESSION_READ_ONLY_EXISTS     PKCS_11ReturnCode = 0x000000B7
	PKCS_11ReturnCodeSESSION_READ_WRITE_SO_EXISTS PKCS_11ReturnCode = 0x000000B8

	PKCS_11ReturnCodeSIGNATURE_INVALID                PKCS_11ReturnCode = 0x000000C0
	PKCS_11ReturnCodeSIGNATURE_LEN_RANGE              PKCS_11ReturnCode = 0x000000C1
	PKCS_11ReturnCodeTEMPLATE_INCOMPLETE              PKCS_11ReturnCode = 0x000000D0
	PKCS_11ReturnCodeTEMPLATE_INCONSISTENT            PKCS_11ReturnCode = 0x000000D1
	PKCS_11ReturnCodeTOKEN_NOT_PRESENT                PKCS_11ReturnCode = 0x000000E0
	PKCS_11ReturnCodeTOKEN_NOT_RECOGNIZED             PKCS_11ReturnCode = 0x000000E1
	PKCS_11ReturnCodeTOKEN_WRITE_PROTECTED            PKCS_11ReturnCode = 0x000000E2
	PKCS_11ReturnCodeUNWRAPPING_KEY_HANDLE_INVALID    PKCS_11ReturnCode = 0x000000F0
	PKCS_11ReturnCodeUNWRAPPING_KEY_SIZE_RANGE        PKCS_11ReturnCode = 0x000000F1
	PKCS_11ReturnCodeUNWRAPPING_KEY_TYPE_INCONSISTENT PKCS_11ReturnCode = 0x000000F2
	PKCS_11ReturnCodeUSER_ALREADY_LOGGED_IN           PKCS_11ReturnCode = 0x00000100
	PKCS_11ReturnCodeUSER_NOT_LOGGED_IN               PKCS_11ReturnCode = 0x00000101
	PKCS_11ReturnCodeUSER_PIN_NOT_INITIALIZED         PKCS_11ReturnCode = 0x00000102
	PKCS_11ReturnCodeUSER_TYPE_INVALID                PKCS_11ReturnCode = 0x00000103

	PKCS_11ReturnCodeUSER_ANOTHER_ALREADY_LOGGED_IN PKCS_11ReturnCode = 0x00000104
	PKCS_11ReturnCodeUSER_TOO_MANY_TYPES            PKCS_11ReturnCode = 0x00000105

	PKCS_11ReturnCodeWRAPPED_KEY_INVALID            PKCS_11ReturnCode = 0x00000110
	PKCS_11ReturnCodeWRAPPED_KEY_LEN_RANGE          PKCS_11ReturnCode = 0x00000112
	PKCS_11ReturnCodeWRAPPING_KEY_HANDLE_INVALID    PKCS_11ReturnCode = 0x00000113
	PKCS_11ReturnCodeWRAPPING_KEY_SIZE_RANGE        PKCS_11ReturnCode = 0x00000114
	PKCS_11ReturnCodeWRAPPING_KEY_TYPE_INCONSISTENT PKCS_11ReturnCode = 0x00000115
	PKCS_11ReturnCodeRANDOM_SEED_NOT_SUPPORTED      PKCS_11ReturnCode = 0x00000120

	PKCS_11ReturnCodeRANDOM_NO_RNG PKCS_11ReturnCode = 0x00000121

	PKCS_11ReturnCodeDOMAIN_PARAMS_INVALID PKCS_11ReturnCode = 0x00000130

	PKCS_11ReturnCodeCURVE_NOT_SUPPORTED PKCS_11ReturnCode = 0x00000140

	PKCS_11ReturnCodeBUFFER_TOO_SMALL      PKCS_11ReturnCode = 0x00000150
	PKCS_11ReturnCodeSAVED_STATE_INVALID   PKCS_11ReturnCode = 0x00000160
	PKCS_11ReturnCodeINFORMATION_SENSITIVE PKCS_11ReturnCode = 0x00000170
	PKCS_11ReturnCodeSTATE_UNSAVEABLE      PKCS_11ReturnCode = 0x00000180

	PKCS_11ReturnCodeCRYPTOKI_NOT_INITIALIZED     PKCS_11ReturnCode = 0x00000190
	PKCS_11ReturnCodeCRYPTOKI_ALREADY_INITIALIZED PKCS_11ReturnCode = 0x00000191
	PKCS_11ReturnCodeMUTEX_BAD                    PKCS_11ReturnCode = 0x000001A0
	PKCS_11ReturnCodeMUTEX_NOT_LOCKED             PKCS_11ReturnCode = 0x000001A1

	PKCS_11ReturnCodeNEW_PIN_MODE PKCS_11ReturnCode = 0x000001B0
	PKCS_11ReturnCodeNEXT_OTP     PKCS_11ReturnCode = 0x000001B1

	PKCS_11ReturnCodeEXCEEDED_MAX_ITERATIONS PKCS_11ReturnCode = 0x000001B5
	PKCS_11ReturnCodeFIPS_SELF_TEST_FAILED   PKCS_11ReturnCode = 0x000001B6
	PKCS_11ReturnCodeLIBRARY_LOAD_FAILED     PKCS_11ReturnCode = 0x000001B7
	PKCS_11ReturnCodePIN_TOO_WEAK            PKCS_11ReturnCode = 0x000001B8
	PKCS_11ReturnCodePUBLIC_KEY_INVALID      PKCS_11ReturnCode = 0x000001B9

	PKCS_11ReturnCodeFUNCTION_REJECTED       PKCS_11ReturnCode = 0x00000200
	PKCS_11ReturnCodeTOKEN_RESOURCE_EXCEEDED PKCS_11ReturnCode = 0x00000201
	PKCS_11ReturnCodeOPERATION_CANCEL_FAILED PKCS_11ReturnCode = 0x00000202
	PKCS_11ReturnCodeKEY_EXHAUSTED           PKCS_11ReturnCode = 0x00000203
)

func init() {
	ttlv.RegisterEnum(kmip.TagOperation, map[kmip.Operation]string{
		OperationPKCS_11: "PKCS_11",
	})

	ttlv.RegisterTag("PKCS_11Interface", TagPKCS_11Interface)
	ttlv.RegisterTag("PKCS_11Function", TagPKCS_11Function)
	ttlv.RegisterTag("PKCS_11InputParameters", TagPKCS_11InputParameters)
	ttlv.RegisterTag("PKCS_11OutputParameters", TagPKCS_11OutputParameters)
	ttlv.RegisterTag("PKCS_11ReturnCode", TagPKCS_11ReturnCode)

	ttlv.RegisterEnum(TagPKCS_11Function, map[PKCS_11Function]string{
		// Version 2.0 and later
		PKCS_11FunctionC_Initialize:          "C_Initialize",
		PKCS_11FunctionC_Finalize:            "C_Finalize",
		PKCS_11FunctionC_GetInfo:             "C_GetInfo",
		PKCS_11FunctionC_GetFunctionList:     "C_GetFunctionList",
		PKCS_11FunctionC_GetSlotList:         "C_GetSlotList",
		PKCS_11FunctionC_GetSlotInfo:         "C_GetSlotInfo",
		PKCS_11FunctionC_GetTokenInfo:        "C_GetTokenInfo",
		PKCS_11FunctionC_GetMechanismList:    "C_GetMechanismList",
		PKCS_11FunctionC_GetMechanismInfo:    "C_GetMechanismInfo",
		PKCS_11FunctionC_InitToken:           "C_InitToken",
		PKCS_11FunctionC_InitPIN:             "C_InitPIN",
		PKCS_11FunctionC_SetPIN:              "C_SetPIN",
		PKCS_11FunctionC_OpenSession:         "C_OpenSession",
		PKCS_11FunctionC_CloseSession:        "C_CloseSession",
		PKCS_11FunctionC_CloseAllSessions:    "C_CloseAllSessions",
		PKCS_11FunctionC_GetSessionInfo:      "C_GetSessionInfo",
		PKCS_11FunctionC_GetOperationState:   "C_GetOperationState",
		PKCS_11FunctionC_SetOperationState:   "C_SetOperationState",
		PKCS_11FunctionC_Login:               "C_Login",
		PKCS_11FunctionC_Logout:              "C_Logout",
		PKCS_11FunctionC_CreateObject:        "C_CreateObject",
		PKCS_11FunctionC_CopyObject:          "C_CopyObject",
		PKCS_11FunctionC_DestroyObject:       "C_DestroyObject",
		PKCS_11FunctionC_GetObjectSize:       "C_GetObjectSize",
		PKCS_11FunctionC_GetAttributeValue:   "C_GetAttributeValue",
		PKCS_11FunctionC_SetAttributeValue:   "C_SetAttributeValue",
		PKCS_11FunctionC_FindObjectsInit:     "C_FindObjectsInit",
		PKCS_11FunctionC_FindObjects:         "C_FindObjects",
		PKCS_11FunctionC_FindObjectsFinal:    "C_FindObjectsFinal",
		PKCS_11FunctionC_EncryptInit:         "C_EncryptInit",
		PKCS_11FunctionC_Encrypt:             "C_Encrypt",
		PKCS_11FunctionC_EncryptUpdate:       "C_EncryptUpdate",
		PKCS_11FunctionC_EncryptFinal:        "C_EncryptFinal",
		PKCS_11FunctionC_DecryptInit:         "C_DecryptInit",
		PKCS_11FunctionC_Decrypt:             "C_Decrypt",
		PKCS_11FunctionC_DecryptUpdate:       "C_DecryptUpdate",
		PKCS_11FunctionC_DecryptFinal:        "C_DecryptFinal",
		PKCS_11FunctionC_DigestInit:          "C_DigestInit",
		PKCS_11FunctionC_Digest:              "C_Digest",
		PKCS_11FunctionC_DigestUpdate:        "C_DigestUpdate",
		PKCS_11FunctionC_DigestKey:           "C_DigestKey",
		PKCS_11FunctionC_DigestFinal:         "C_DigestFinal",
		PKCS_11FunctionC_SignInit:            "C_SignInit",
		PKCS_11FunctionC_Sign:                "C_Sign",
		PKCS_11FunctionC_SignUpdate:          "C_SignUpdate",
		PKCS_11FunctionC_SignFinal:           "C_SignFinal",
		PKCS_11FunctionC_SignRecoverInit:     "C_SignRecoverInit",
		PKCS_11FunctionC_SignRecover:         "C_SignRecover",
		PKCS_11FunctionC_VerifyInit:          "C_VerifyInit",
		PKCS_11FunctionC_Verify:              "C_Verify",
		PKCS_11FunctionC_VerifyUpdate:        "C_VerifyUpdate",
		PKCS_11FunctionC_VerifyFinal:         "C_VerifyFinal",
		PKCS_11FunctionC_VerifyRecoverInit:   "C_VerifyRecoverInit",
		PKCS_11FunctionC_VerifyRecover:       "C_VerifyRecover",
		PKCS_11FunctionC_DigestEncryptUpdate: "C_DigestEncryptUpdate",
		PKCS_11FunctionC_DecryptDigestUpdate: "C_DecryptDigestUpdate",
		PKCS_11FunctionC_SignEncryptUpdate:   "C_SignEncryptUpdate",
		PKCS_11FunctionC_DecryptVerifyUpdate: "C_DecryptVerifyUpdate",
		PKCS_11FunctionC_GenerateKey:         "C_GenerateKey",
		PKCS_11FunctionC_GenerateKeyPair:     "C_GenerateKeyPair",
		PKCS_11FunctionC_WrapKey:             "C_WrapKey",
		PKCS_11FunctionC_UnwrapKey:           "C_UnwrapKey",
		PKCS_11FunctionC_DeriveKey:           "C_DeriveKey",
		PKCS_11FunctionC_SeedRandom:          "C_SeedRandom",
		PKCS_11FunctionC_GenerateRandom:      "C_GenerateRandom",
		PKCS_11FunctionC_GetFunctionStatus:   "C_GetFunctionStatus",
		PKCS_11FunctionC_CancelFunction:      "C_CancelFunction",
		// Version 2.1 and later
		PKCS_11FunctionC_WaitForSlotEvent: "C_WaitForSlotEvent",
		// Version 3.0 and later
		PKCS_11FunctionC_GetInterfaceList:    "C_GetInterfaceList",
		PKCS_11FunctionC_GetInterface:        "C_GetInterface",
		PKCS_11FunctionC_LoginUser:           "C_LoginUser",
		PKCS_11FunctionC_SessionCancel:       "C_SessionCancel",
		PKCS_11FunctionC_MessageEncryptInit:  "C_MessageEncryptInit",
		PKCS_11FunctionC_EncryptMessage:      "C_EncryptMessage",
		PKCS_11FunctionC_EncryptMessageBegin: "C_EncryptMessageBegin",
		PKCS_11FunctionC_EncryptMessageNext:  "C_EncryptMessageNext",
		PKCS_11FunctionC_MessageEncryptFinal: "C_MessageEncryptFinal",
		PKCS_11FunctionC_MessageDecryptInit:  "C_MessageDecryptInit",
		PKCS_11FunctionC_DecryptMessage:      "C_DecryptMessage",
		PKCS_11FunctionC_DecryptMessageBegin: "C_DecryptMessageBegin",
		PKCS_11FunctionC_DecryptMessageNext:  "C_DecryptMessageNext",
		PKCS_11FunctionC_MessageDecryptFinal: "C_MessageDecryptFinal",
		PKCS_11FunctionC_MessageSignInit:     "C_MessageSignInit",
		PKCS_11FunctionC_SignMessage:         "C_SignMessage",
		PKCS_11FunctionC_SignMessageBegin:    "C_SignMessageBegin",
		PKCS_11FunctionC_SignMessageNext:     "C_SignMessageNext",
		PKCS_11FunctionC_MessageSignFinal:    "C_MessageSignFinal",
		PKCS_11FunctionC_MessageVerifyInit:   "C_MessageVerifyInit",
		PKCS_11FunctionC_VerifyMessage:       "C_VerifyMessage",
		PKCS_11FunctionC_VerifyMessageBegin:  "C_VerifyMessageBegin",
		PKCS_11FunctionC_VerifyMessageNext:   "C_VerifyMessageNext",
		PKCS_11FunctionC_MessageVerifyFinal:  "C_MessageVerifyFinal",
	})

	ttlv.RegisterEnum(TagPKCS_11ReturnCode, map[PKCS_11ReturnCode]string{
		PKCS_11ReturnCodeOK:              "OK",
		PKCS_11ReturnCodeCANCEL:          "CANCEL",
		PKCS_11ReturnCodeHOST_MEMORY:     "HOST_MEMORY",
		PKCS_11ReturnCodeSLOT_ID_INVALID: "SLOT_ID_INVALID",

		PKCS_11ReturnCodeGENERAL_ERROR:   "GENERAL_ERROR",
		PKCS_11ReturnCodeFUNCTION_FAILED: "FUNCTION_FAILED",

		PKCS_11ReturnCodeARGUMENTS_BAD:          "ARGUMENTS_BAD",
		PKCS_11ReturnCodeNO_EVENT:               "NO_EVENT",
		PKCS_11ReturnCodeNEED_TO_CREATE_THREADS: "NEED_TO_CREATE_THREADS",
		PKCS_11ReturnCodeCANT_LOCK:              "CANT_LOCK",

		PKCS_11ReturnCodeATTRIBUTE_READ_ONLY:     "ATTRIBUTE_READ_ONLY",
		PKCS_11ReturnCodeATTRIBUTE_SENSITIVE:     "ATTRIBUTE_SENSITIVE",
		PKCS_11ReturnCodeATTRIBUTE_TYPE_INVALID:  "ATTRIBUTE_TYPE_INVALID",
		PKCS_11ReturnCodeATTRIBUTE_VALUE_INVALID: "ATTRIBUTE_VALUE_INVALID",

		PKCS_11ReturnCodeACTION_PROHIBITED: "ACTION_PROHIBITED",

		PKCS_11ReturnCodeDATA_INVALID:             "DATA_INVALID",
		PKCS_11ReturnCodeDATA_LEN_RANGE:           "DATA_LEN_RANGE",
		PKCS_11ReturnCodeDEVICE_ERROR:             "DEVICE_ERROR",
		PKCS_11ReturnCodeDEVICE_MEMORY:            "DEVICE_MEMORY",
		PKCS_11ReturnCodeDEVICE_REMOVED:           "DEVICE_REMOVED",
		PKCS_11ReturnCodeENCRYPTED_DATA_INVALID:   "ENCRYPTED_DATA_INVALID",
		PKCS_11ReturnCodeENCRYPTED_DATA_LEN_RANGE: "ENCRYPTED_DATA_LEN_RANGE",
		PKCS_11ReturnCodeAEAD_DECRYPT_FAILED:      "AEAD_DECRYPT_FAILED",
		PKCS_11ReturnCodeFUNCTION_CANCELED:        "FUNCTION_CANCELED",
		PKCS_11ReturnCodeFUNCTION_NOT_PARALLEL:    "FUNCTION_NOT_PARALLEL",

		PKCS_11ReturnCodeFUNCTION_NOT_SUPPORTED: "FUNCTION_NOT_SUPPORTED",

		PKCS_11ReturnCodeKEY_HANDLE_INVALID: "KEY_HANDLE_INVALID",

		PKCS_11ReturnCodeKEY_SIZE_RANGE:        "KEY_SIZE_RANGE",
		PKCS_11ReturnCodeKEY_TYPE_INCONSISTENT: "KEY_TYPE_INCONSISTENT",

		PKCS_11ReturnCodeKEY_NOT_NEEDED:             "KEY_NOT_NEEDED",
		PKCS_11ReturnCodeKEY_CHANGED:                "KEY_CHANGED",
		PKCS_11ReturnCodeKEY_NEEDED:                 "KEY_NEEDED",
		PKCS_11ReturnCodeKEY_INDIGESTIBLE:           "KEY_INDIGESTIBLE",
		PKCS_11ReturnCodeKEY_FUNCTION_NOT_PERMITTED: "KEY_FUNCTION_NOT_PERMITTED",
		PKCS_11ReturnCodeKEY_NOT_WRAPPABLE:          "KEY_NOT_WRAPPABLE",
		PKCS_11ReturnCodeKEY_UNEXTRACTABLE:          "KEY_UNEXTRACTABLE",

		PKCS_11ReturnCodeMECHANISM_INVALID:       "MECHANISM_INVALID",
		PKCS_11ReturnCodeMECHANISM_PARAM_INVALID: "MECHANISM_PARAM_INVALID",

		PKCS_11ReturnCodeOBJECT_HANDLE_INVALID:     "OBJECT_HANDLE_INVALID",
		PKCS_11ReturnCodeOPERATION_ACTIVE:          "OPERATION_ACTIVE",
		PKCS_11ReturnCodeOPERATION_NOT_INITIALIZED: "OPERATION_NOT_INITIALIZED",
		PKCS_11ReturnCodePIN_INCORRECT:             "PIN_INCORRECT",
		PKCS_11ReturnCodePIN_INVALID:               "PIN_INVALID",
		PKCS_11ReturnCodePIN_LEN_RANGE:             "PIN_LEN_RANGE",

		PKCS_11ReturnCodePIN_EXPIRED: "PIN_EXPIRED",
		PKCS_11ReturnCodePIN_LOCKED:  "PIN_LOCKED",

		PKCS_11ReturnCodeSESSION_CLOSED:                 "SESSION_CLOSED",
		PKCS_11ReturnCodeSESSION_COUNT:                  "SESSION_COUNT",
		PKCS_11ReturnCodeSESSION_HANDLE_INVALID:         "SESSION_HANDLE_INVALID",
		PKCS_11ReturnCodeSESSION_PARALLEL_NOT_SUPPORTED: "SESSION_PARALLEL_NOT_SUPPORTED",
		PKCS_11ReturnCodeSESSION_READ_ONLY:              "SESSION_READ_ONLY",
		PKCS_11ReturnCodeSESSION_EXISTS:                 "SESSION_EXISTS",

		PKCS_11ReturnCodeSESSION_READ_ONLY_EXISTS:     "SESSION_READ_ONLY_EXISTS",
		PKCS_11ReturnCodeSESSION_READ_WRITE_SO_EXISTS: "SESSION_READ_WRITE_SO_EXISTS",

		PKCS_11ReturnCodeSIGNATURE_INVALID:                "SIGNATURE_INVALID",
		PKCS_11ReturnCodeSIGNATURE_LEN_RANGE:              "SIGNATURE_LEN_RANGE",
		PKCS_11ReturnCodeTEMPLATE_INCOMPLETE:              "TEMPLATE_INCOMPLETE",
		PKCS_11ReturnCodeTEMPLATE_INCONSISTENT:            "TEMPLATE_INCONSISTENT",
		PKCS_11ReturnCodeTOKEN_NOT_PRESENT:                "TOKEN_NOT_PRESENT",
		PKCS_11ReturnCodeTOKEN_NOT_RECOGNIZED:             "TOKEN_NOT_RECOGNIZED",
		PKCS_11ReturnCodeTOKEN_WRITE_PROTECTED:            "TOKEN_WRITE_PROTECTED",
		PKCS_11ReturnCodeUNWRAPPING_KEY_HANDLE_INVALID:    "UNWRAPPING_KEY_HANDLE_INVALID",
		PKCS_11ReturnCodeUNWRAPPING_KEY_SIZE_RANGE:        "UNWRAPPING_KEY_SIZE_RANGE",
		PKCS_11ReturnCodeUNWRAPPING_KEY_TYPE_INCONSISTENT: "UNWRAPPING_KEY_TYPE_INCONSISTENT",
		PKCS_11ReturnCodeUSER_ALREADY_LOGGED_IN:           "USER_ALREADY_LOGGED_IN",
		PKCS_11ReturnCodeUSER_NOT_LOGGED_IN:               "USER_NOT_LOGGED_IN",
		PKCS_11ReturnCodeUSER_PIN_NOT_INITIALIZED:         "USER_PIN_NOT_INITIALIZED",
		PKCS_11ReturnCodeUSER_TYPE_INVALID:                "USER_TYPE_INVALID",

		PKCS_11ReturnCodeUSER_ANOTHER_ALREADY_LOGGED_IN: "USER_ANOTHER_ALREADY_LOGGED_IN",
		PKCS_11ReturnCodeUSER_TOO_MANY_TYPES:            "USER_TOO_MANY_TYPES",

		PKCS_11ReturnCodeWRAPPED_KEY_INVALID:            "WRAPPED_KEY_INVALID",
		PKCS_11ReturnCodeWRAPPED_KEY_LEN_RANGE:          "WRAPPED_KEY_LEN_RANGE",
		PKCS_11ReturnCodeWRAPPING_KEY_HANDLE_INVALID:    "WRAPPING_KEY_HANDLE_INVALID",
		PKCS_11ReturnCodeWRAPPING_KEY_SIZE_RANGE:        "WRAPPING_KEY_SIZE_RANGE",
		PKCS_11ReturnCodeWRAPPING_KEY_TYPE_INCONSISTENT: "WRAPPING_KEY_TYPE_INCONSISTENT",
		PKCS_11ReturnCodeRANDOM_SEED_NOT_SUPPORTED:      "RANDOM_SEED_NOT_SUPPORTED",

		PKCS_11ReturnCodeRANDOM_NO_RNG: "RANDOM_NO_RNG",

		PKCS_11ReturnCodeDOMAIN_PARAMS_INVALID: "DOMAIN_PARAMS_INVALID",

		PKCS_11ReturnCodeCURVE_NOT_SUPPORTED: "CURVE_NOT_SUPPORTED",

		PKCS_11ReturnCodeBUFFER_TOO_SMALL:      "BUFFER_TOO_SMALL",
		PKCS_11ReturnCodeSAVED_STATE_INVALID:   "SAVED_STATE_INVALID",
		PKCS_11ReturnCodeINFORMATION_SENSITIVE: "INFORMATION_SENSITIVE",
		PKCS_11ReturnCodeSTATE_UNSAVEABLE:      "STATE_UNSAVEABLE",

		PKCS_11ReturnCodeCRYPTOKI_NOT_INITIALIZED:     "CRYPTOKI_NOT_INITIALIZED",
		PKCS_11ReturnCodeCRYPTOKI_ALREADY_INITIALIZED: "CRYPTOKI_ALREADY_INITIALIZED",
		PKCS_11ReturnCodeMUTEX_BAD:                    "MUTEX_BAD",
		PKCS_11ReturnCodeMUTEX_NOT_LOCKED:             "MUTEX_NOT_LOCKED",

		PKCS_11ReturnCodeNEW_PIN_MODE: "NEW_PIN_MODE",
		PKCS_11ReturnCodeNEXT_OTP:     "NEXT_OTP",

		PKCS_11ReturnCodeEXCEEDED_MAX_ITERATIONS: "EXCEEDED_MAX_ITERATIONS",
		PKCS_11ReturnCodeFIPS_SELF_TEST_FAILED:   "FIPS_SELF_TEST_FAILED",
		PKCS_11ReturnCodeLIBRARY_LOAD_FAILED:     "LIBRARY_LOAD_FAILED",
		PKCS_11ReturnCodePIN_TOO_WEAK:            "PIN_TOO_WEAK",
		PKCS_11ReturnCodePUBLIC_KEY_INVALID:      "PUBLIC_KEY_INVALID",

		PKCS_11ReturnCodeFUNCTION_REJECTED:       "FUNCTION_REJECTED",
		PKCS_11ReturnCodeTOKEN_RESOURCE_EXCEEDED: "TOKEN_RESOURCE_EXCEEDED",
		PKCS_11ReturnCodeOPERATION_CANCEL_FAILED: "OPERATION_CANCEL_FAILED",
		PKCS_11ReturnCodeKEY_EXHAUSTED:           "KEY_EXHAUSTED",
	})
}
