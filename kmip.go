package main

// #include "cgo.h"
import "C"
import "context"
import "crypto/tls"
import "errors"
import "fmt"
import "os"
import "time"
import "github.com/google/uuid"
import "github.com/ovh/kmip-go"
import "github.com/ovh/kmip-go/kmipclient"
import "github.com/ovh/kmip-go/ttlv"

func getKMIPClient() (*kmipclient.Client, error) {
	if kmipClient != nil {
		return kmipClient, nil
	}

	kmip_server := getKMIPServer()

	if kmip_server == "" {
		return nil, errors.New("Missing KMIP server address.")
	}

	var err error

	middlewares := []kmipclient.Middleware{
		kmipclient.CorrelationValueMiddleware(uuid.NewString),
		kmipclient.TimeoutMiddleware(3000 * time.Millisecond),
	}

	if getDebugMode() >= 2 {
		middlewares = append(middlewares, kmipclient.DebugMiddleware(os.Stdout, nil))
	}

	kmipClient, err = kmipclient.Dial(
		kmip_server,
		kmipclient.WithTlsConfig(&tls.Config{
			InsecureSkipVerify: true,
		}),
		kmipclient.WithMiddlewares(middlewares...),
	)

	if kmipClient == nil && err == nil {
		err = errors.New("Client failed to connect earlier.")
	}

	return kmipClient, err
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
		return nil, nil, C.CKR_TOKEN_NOT_PRESENT
	}

	request := createKMIPRequest(pkcs1Interface, pkcs11Function, pkcs11InputParameters)

	response, err := client.Request(context.Background(), request)
	if err != nil {
		kmipClient = nil
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
		fmt.Println("Response does not contain a function.")
		return nil, nil, C.CKR_FUNCTION_FAILED
	}
	if fieldReturnCode == nil {
		fmt.Println("Response does not contain a return value.")
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
