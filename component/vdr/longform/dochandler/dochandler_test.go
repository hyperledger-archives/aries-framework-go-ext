/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package dochandler

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/document"
	"github.com/trustbloc/sidetree-go/pkg/encoder"
	"github.com/trustbloc/sidetree-go/pkg/mocks"
	"github.com/trustbloc/sidetree-go/pkg/versions/1_0/model"
)

const (
	namespace = "did:ion"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		require.Equal(t, namespace, lfh.Namespace())
	})

	t.Run("success - with protocol versions", func(t *testing.T) {
		lfh, err := New(namespace,
			WithProtocolVersions([]string{v1}),
			WithCurrentProtocolVersion(v1))
		require.NoError(t, err)
		require.NotNil(t, lfh)
	})

	t.Run("error - without protocol versions", func(t *testing.T) {
		lfh, err := New(namespace,
			WithProtocolVersions([]string{}))
		require.Nil(t, lfh)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to create version provider: must provide at least one client version")
	})
}

func TestResolve(t *testing.T) {
	longFormDID := fmt.Sprintf("%s:%s:%s", namespace, didSuffix, requestJCS)

	t.Run("success", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		doc, err := lfh.ResolveDocument(longFormDID)
		require.NoError(t, err)
		require.NotNil(t, doc)

		docBytes, err := json.Marshal(doc.Document)
		require.NoError(t, err)

		err = prettyPrint(doc.Document)
		require.NoError(t, err)

		var didDoc document.DIDDocument
		err = json.Unmarshal(docBytes, &didDoc)
		require.NoError(t, err)

		var expectedIONDoc document.DIDDocument
		err = json.Unmarshal([]byte(ionDIDDoc), &expectedIONDoc)
		require.NoError(t, err)

		require.Equal(t, doc.Document.ID(), expectedIONDoc.ID())
		require.Equal(t, len(expectedIONDoc.Services()), len(didDoc.Services()))
		require.Equal(t, len(expectedIONDoc.PublicKeys()), len(didDoc.PublicKeys()))
		require.Equal(t, didDoc[document.KeyPurposeAssertionMethod], expectedIONDoc[document.KeyPurposeAssertionMethod])
		require.Equal(t, didDoc[document.KeyPurposeAuthentication], expectedIONDoc[document.KeyPurposeAuthentication])
		require.Equal(t, didDoc[document.KeyPurposeCapabilityDelegation], expectedIONDoc[document.KeyPurposeCapabilityDelegation])
		require.Equal(t, didDoc[document.KeyPurposeCapabilityInvocation], expectedIONDoc[document.KeyPurposeCapabilityInvocation])
		require.Equal(t, didDoc[document.KeyPurposeKeyAgreement], expectedIONDoc[document.KeyPurposeKeyAgreement])

		require.Equal(t, didDoc.VerificationMethods()[0].Controller(), expectedIONDoc.VerificationMethods()[0].Controller())
		require.Equal(t, didDoc.VerificationMethods()[0].ID(), expectedIONDoc.VerificationMethods()[0].ID())
		require.Equal(t, didDoc.VerificationMethods()[0].PublicKeyJwk(), expectedIONDoc.VerificationMethods()[0].PublicKeyJwk())

		require.Equal(t, didDoc.Context()[0], expectedIONDoc.Context()[0])
		require.Equal(t, didDoc.Context()[1], expectedIONDoc.Context()[1])
	})

	t.Run("success - with protocol versions", func(t *testing.T) {
		lfh, err := New(namespace,
			WithProtocolVersions([]string{v1}),
			WithCurrentProtocolVersion(v1))
		require.NoError(t, err)

		doc, err := lfh.ResolveDocument(longFormDID)
		require.NoError(t, err)
		require.NotNil(t, doc)
	})

	t.Run("error - protocol client error", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		mockProtocolClient := mocks.NewMockProtocolClient()
		mockProtocolClient.Err = fmt.Errorf("protocol client error")

		lfh.protocolClient = mockProtocolClient

		doc, err := lfh.ResolveDocument(longFormDID)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "protocol client error")
	})

	t.Run("error - parse operation fails due to invalid request JCS", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		// create invalid request JCS
		reqBytes, err := json.Marshal(&model.CreateRequest{})
		require.NoError(t, err)

		invalidRequestJCS := encoder.EncodeToString(reqBytes)

		longFormDIDWithInvalidJCS := fmt.Sprintf("%s:%s:%s", namespace, didSuffix, invalidRequestJCS)

		doc, err := lfh.ResolveDocument(longFormDIDWithInvalidJCS)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "bad request: missing suffix data")
	})

	t.Run("error - wrong namespace", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		didWithInvalidNamespace := fmt.Sprintf("did:whatever:%s:%s", didSuffix, requestJCS)

		doc, err := lfh.ResolveDocument(didWithInvalidNamespace)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "bad request: did must start with configured namespace[did:ion]")
	})

	t.Run("error - missing create request", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		didWithoutRequestJCS := fmt.Sprintf("%s:%s", namespace, didSuffix)

		doc, err := lfh.ResolveDocument(didWithoutRequestJCS)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "bad request: missing create request")
	})

	t.Run("error - DID mismatch", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		longFormDIDWithInvalidSuffix := fmt.Sprintf("%s:%s:%s", namespace, "invalid", requestJCS)

		doc, err := lfh.ResolveDocument(longFormDIDWithInvalidSuffix)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "bad request: provided did doesn't match did created from initial state")
	})
}

func TestProcess(t *testing.T) {
	t.Run("success - ion request", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		opBytes, err := encoder.DecodeString(requestJCS)
		require.NoError(t, err)

		doc, err := lfh.ProcessOperation(opBytes)
		require.NoError(t, err)
		require.NotNil(t, doc)

		err = prettyPrint(doc)
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf("%s:%s:%s", namespace, didSuffix, requestJCS), doc.Document.ID())
	})

	t.Run("success - local did", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		doc, err := lfh.ProcessOperation([]byte(request))
		require.NoError(t, err)
		require.NotNil(t, doc)

		resolutionResult, err := lfh.ResolveDocument(doc.Document.ID())
		require.NoError(t, err)
		require.NotNil(t, resolutionResult)
	})

	t.Run("error - invalid create request", func(t *testing.T) {
		lfh, err := New(namespace)
		require.NoError(t, err)

		// create invalid create request
		reqBytes, err := json.Marshal(&model.CreateRequest{})
		require.NoError(t, err)

		doc, err := lfh.ProcessOperation(reqBytes)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "bad request: parse operation: operation type [] not supported")
	})
}

func prettyPrint(result interface{}) error {
	b, err := json.MarshalIndent(result, "", " ")
	if err != nil {
		return err
	}

	fmt.Println(string(b))

	return nil
}

const didSuffix = `EiD9H4OHw5X4ctS1Q1G9LxmyEed9WDBW_QZ4VMpuOtRciw`
const requestJCS = `eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWduaW5nS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6IndkRGZEakwxRlFET3NwcC1xdmRLUUtyNzllbTdOczJFNVNBVWE5aElRaTQiLCJ5IjoiUGZmc0hEYXA1X0t3UlZwNzgtaUJaQm5XQTZMS3p6bGIxSXJ3VWhFakpuOCJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCIsImNhcGFiaWxpdHlJbnZvY2F0aW9uIiwiY2FwYWJpbGl0eURlbGVnYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOltdfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBazRmbkFKSTJuZ1Z5ZjhrZ05fbUI5emhmX2FKcmdwa2tlalVIbTR1X3gzQSJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQVRaWi1jclh5OXFYeGhGdkFFZElhU0pLY0tTWTVubkZ5bkJCSWtsODF5N1EiLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUFOOHQ3UHlZYmtONFc3ZEVZX1JZX25YWUNlc1JPQl9mUWxzdWx3eVNyYVF3In0sInR5cGUiOiJjcmVhdGUifQ`

const ionDIDDoc = `
{
  "id": "did:ion:EiD9H4OHw5X4ctS1Q1G9LxmyEed9WDBW_QZ4VMpuOtRciw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWduaW5nS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6IndkRGZEakwxRlFET3NwcC1xdmRLUUtyNzllbTdOczJFNVNBVWE5aElRaTQiLCJ5IjoiUGZmc0hEYXA1X0t3UlZwNzgtaUJaQm5XQTZMS3p6bGIxSXJ3VWhFakpuOCJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCIsImNhcGFiaWxpdHlJbnZvY2F0aW9uIiwiY2FwYWJpbGl0eURlbGVnYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOltdfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBazRmbkFKSTJuZ1Z5ZjhrZ05fbUI5emhmX2FKcmdwa2tlalVIbTR1X3gzQSJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQVRaWi1jclh5OXFYeGhGdkFFZElhU0pLY0tTWTVubkZ5bkJCSWtsODF5N1EiLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUFOOHQ3UHlZYmtONFc3ZEVZX1JZX25YWUNlc1JPQl9mUWxzdWx3eVNyYVF3In0sInR5cGUiOiJjcmVhdGUifQ",
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "@base": "did:ion:EiD9H4OHw5X4ctS1Q1G9LxmyEed9WDBW_QZ4VMpuOtRciw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWduaW5nS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6IndkRGZEakwxRlFET3NwcC1xdmRLUUtyNzllbTdOczJFNVNBVWE5aElRaTQiLCJ5IjoiUGZmc0hEYXA1X0t3UlZwNzgtaUJaQm5XQTZMS3p6bGIxSXJ3VWhFakpuOCJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCIsImNhcGFiaWxpdHlJbnZvY2F0aW9uIiwiY2FwYWJpbGl0eURlbGVnYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOltdfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBazRmbkFKSTJuZ1Z5ZjhrZ05fbUI5emhmX2FKcmdwa2tlalVIbTR1X3gzQSJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQVRaWi1jclh5OXFYeGhGdkFFZElhU0pLY0tTWTVubkZ5bkJCSWtsODF5N1EiLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUFOOHQ3UHlZYmtONFc3ZEVZX1JZX25YWUNlc1JPQl9mUWxzdWx3eVNyYVF3In0sInR5cGUiOiJjcmVhdGUifQ"
    }
  ],
  "service": [],
  "verificationMethod": [
    {
      "id": "#signingKey",
      "controller": "did:ion:EiD9H4OHw5X4ctS1Q1G9LxmyEed9WDBW_QZ4VMpuOtRciw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWduaW5nS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6IndkRGZEakwxRlFET3NwcC1xdmRLUUtyNzllbTdOczJFNVNBVWE5aElRaTQiLCJ5IjoiUGZmc0hEYXA1X0t3UlZwNzgtaUJaQm5XQTZMS3p6bGIxSXJ3VWhFakpuOCJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCIsImNhcGFiaWxpdHlJbnZvY2F0aW9uIiwiY2FwYWJpbGl0eURlbGVnYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOltdfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBazRmbkFKSTJuZ1Z5ZjhrZ05fbUI5emhmX2FKcmdwa2tlalVIbTR1X3gzQSJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQVRaWi1jclh5OXFYeGhGdkFFZElhU0pLY0tTWTVubkZ5bkJCSWtsODF5N1EiLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUFOOHQ3UHlZYmtONFc3ZEVZX1JZX25YWUNlc1JPQl9mUWxzdWx3eVNyYVF3In0sInR5cGUiOiJjcmVhdGUifQ",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "publicKeyJwk": {
        "crv": "secp256k1",
        "kty": "EC",
        "x": "wdDfDjL1FQDOspp-qvdKQKr79em7Ns2E5SAUa9hIQi4",
        "y": "PffsHDap5_KwRVp78-iBZBnWA6LKzzlb1IrwUhEjJn8"
      }
    }
  ],
  "authentication": [
    "#signingKey"
  ],
  "assertionMethod": [
    "#signingKey"
  ],
  "capabilityInvocation": [
    "#signingKey"
  ],
  "capabilityDelegation": [
    "#signingKey"
  ],
  "keyAgreement": [
    "#signingKey"
  ]
}`

const request = `{"delta":{"patches":[{"action":"add-services","services":[{"id":"svc","priority":0,"serviceEndpoint":[{"uri":"https://example.com"}],"type":"type"}]}],"updateCommitment":"EiDGHZRmMumPeTuIlUfQvhyexN7F_ygx84oUX17RMwbGRA"},"suffixData":{"deltaHash":"EiC3qJy6QQwwDuPlL38QR0IY0lkqnZ1wPA160uEir43_Zg","recoveryCommitment":"EiBIv4HoV0L5B13jAuOMBTOaGnP_Lx6uW5YFvzma6cJVVQ"},"type":"create"}`
