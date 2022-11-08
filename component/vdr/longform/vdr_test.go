/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package longform

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockldstore "github.com/hyperledger/aries-framework-go/pkg/mock/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/create"
)

const (
	p256KeyType       = "P256"
	p384KeyType       = "P384"
	bls12381G2KeyType = "Bls12381G2"
	ed25519KeyType    = "Ed25519"

	notImplemented = "not implemented"
)

func TestVDRI_Accept(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)
		require.True(t, v.Accept(defaultDIDMethod))
	})

	t.Run("test return false", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)
		require.False(t, v.Accept("did:different"))
	})
}

func TestVDRI_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)
		require.True(t, v.Accept(defaultDIDMethod))

		err = v.Close()
		require.NoError(t, err)
	})
}

func TestVDRI_Options(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		docLoader := createTestDocLoader(t)

		v, err := New(WithDIDMethod("did:different"), WithDocumentLoader(docLoader))
		require.NoError(t, err)
		require.False(t, v.Accept(defaultDIDMethod))
		require.True(t, v.Accept("did:different"))

		err = v.Close()
		require.NoError(t, err)
	})
}

func TestVDRI_Read(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		longFormDID := fmt.Sprintf("%s:%s:%s", defaultDIDMethod, didSuffix, requestJCS)

		docResolution, err := v.Read(longFormDID)
		require.NoError(t, err)
		require.NotNil(t, docResolution)

		err = prettyPrint(docResolution)
		require.NoError(t, err)

		didDoc := docResolution.DIDDocument

		require.Equal(t, longFormDID, didDoc.ID)
		require.Equal(t, 1, len(didDoc.VerificationMethod))
		require.Equal(t, fmt.Sprintf("%s#signingKey", longFormDID), didDoc.VerificationMethod[0].ID)
		require.Equal(t, longFormDID, didDoc.VerificationMethod[0].Controller)

		require.Equal(t, 1, len(didDoc.AssertionMethod))
		require.Equal(t, 1, len(didDoc.Authentication))
		require.Equal(t, 1, len(didDoc.CapabilityInvocation))
		require.Equal(t, 1, len(didDoc.CapabilityDelegation))
		require.Equal(t, 1, len(didDoc.KeyAgreement))

		require.Equal(t, docResolution.DocumentMetadata.EquivalentID[0], fmt.Sprintf("%s:%s", defaultDIDMethod, didSuffix))
	})

	t.Run("test sidetree document handler error", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		v.sidetreeDocHandler = &mockDocHandler{Err: fmt.Errorf("document handler error")}

		longFormDID := fmt.Sprintf("%s:%s:%s", defaultDIDMethod, didSuffix, requestJCS)

		docResolution, err := v.Read(longFormDID)
		require.Error(t, err)
		require.Nil(t, docResolution)
		require.Contains(t, err.Error(), "document handler error")
	})

	t.Run("test parsing sidetree resolution result", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		v.sidetreeDocHandler = &mockDocHandler{ResolutionResult: &document.ResolutionResult{}}

		longFormDID := fmt.Sprintf("%s:%s:%s", defaultDIDMethod, didSuffix, requestJCS)

		docResolution, err := v.Read(longFormDID)
		require.Error(t, err)
		require.Nil(t, docResolution)
		require.Contains(t, err.Error(), "document payload is not provided")
	})
}

func TestVDRI_Create(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didDoc := &ariesdid.Doc{}

	vm, err := createVerificationMethod(ed25519KeyType, pubKey, "abc", "Ed25519VerificationKey2020")
	require.NoError(t, err)

	didDoc.Authentication = append(didDoc.Authentication,
		*ariesdid.NewReferencedVerification(vm, ariesdid.Authentication))

	didDoc.AssertionMethod = append(didDoc.AssertionMethod,
		*ariesdid.NewReferencedVerification(vm, ariesdid.AssertionMethod))

	didDoc.CapabilityDelegation = append(didDoc.CapabilityDelegation,
		*ariesdid.NewReferencedVerification(vm, ariesdid.CapabilityDelegation))

	didDoc.CapabilityInvocation = append(didDoc.CapabilityInvocation,
		*ariesdid.NewReferencedVerification(vm, ariesdid.CapabilityInvocation))

	// Note: ion doesn't support publicKeyBase58 property
	vm2 := ariesdid.NewVerificationMethodFromBytes("xyz", "Ed25519VerificationKey2018", "", pubKey)
	didDoc.AssertionMethod = append(didDoc.AssertionMethod,
		*ariesdid.NewReferencedVerification(vm2, ariesdid.AssertionMethod))

	didDoc.Service = append(didDoc.Service,
		ariesdid.Service{
			ID:   "svc",
			Type: "type",
			// Note: ion doesn't support an array of service endpoints - do NOT use V2
			ServiceEndpoint: model.NewDIDCommV1Endpoint("https://example.com"),
		})

	// Note: ion doesn't support also-known-as patch
	// didDoc.AlsoKnownAs = []string{"https://myblog.example/"}

	t.Run("test success", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		recoveryKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		updateKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		docResolution, err := v.Create(didDoc, vdrapi.WithOption(UpdatePublicKeyOpt, updateKey),
			vdrapi.WithOption(RecoveryPublicKeyOpt, recoveryKey))
		require.NoError(t, err)
		require.NotEmpty(t, docResolution.DIDDocument.ID)

		err = prettyPrint(docResolution)
		require.NoError(t, err)

		didResolution, err := v.Read(docResolution.DIDDocument.ID)
		require.NoError(t, err)
		require.NotNil(t, didResolution)

		err = prettyPrint(didResolution)
		require.NoError(t, err)
	})

	t.Run("test success - simple did (one public key only)", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		recoveryKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		updateKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		testVM, err := createVerificationMethod(ed25519KeyType, pubKey, "abc", "Ed25519VerificationKey2020")
		require.NoError(t, err)

		simpleDoc := &ariesdid.Doc{}

		simpleDoc.Authentication = append(simpleDoc.Authentication,
			*ariesdid.NewReferencedVerification(testVM, ariesdid.Authentication))

		simpleDoc.AssertionMethod = append(simpleDoc.AssertionMethod,
			*ariesdid.NewReferencedVerification(testVM, ariesdid.AssertionMethod))

		docResolution, err := v.Create(simpleDoc, vdrapi.WithOption(UpdatePublicKeyOpt, updateKey),
			vdrapi.WithOption(RecoveryPublicKeyOpt, recoveryKey))
		require.NoError(t, err)
		require.NotEmpty(t, docResolution.DIDDocument.ID)

		err = prettyPrint(docResolution)
		require.NoError(t, err)

		didResolution, err := v.Read(docResolution.DIDDocument.ID)
		require.NoError(t, err)
		require.NotNil(t, didResolution)

		err = prettyPrint(didResolution)
		require.NoError(t, err)
	})

	t.Run("test success - simple did (one service only)", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		recoveryKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		updateKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		simpleDoc := &ariesdid.Doc{}

		simpleDoc.Service = append(simpleDoc.Service,
			ariesdid.Service{
				ID:              "svc",
				Type:            "type",
				ServiceEndpoint: model.NewDIDCommV1Endpoint("https://example.com"),
			})

		docResolution, err := v.Create(simpleDoc, vdrapi.WithOption(UpdatePublicKeyOpt, updateKey),
			vdrapi.WithOption(RecoveryPublicKeyOpt, recoveryKey))
		require.NoError(t, err)
		require.NotEmpty(t, docResolution.DIDDocument.ID)

		err = prettyPrint(docResolution)
		require.NoError(t, err)

		didResolution, err := v.Read(docResolution.DIDDocument.ID)
		require.NoError(t, err)
		require.NotNil(t, didResolution)

		err = prettyPrint(didResolution)
		require.NoError(t, err)
	})

	t.Run("test sidetree client error", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{Err: fmt.Errorf("sidetree client error")}

		recoveryKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		updateKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		docResolution, err := v.Create(didDoc, vdrapi.WithOption(UpdatePublicKeyOpt, updateKey),
			vdrapi.WithOption(RecoveryPublicKeyOpt, recoveryKey))
		require.Error(t, err)
		require.Nil(t, docResolution)
		require.Contains(t, err.Error(), "sidetree client error")
	})

	t.Run("test sidetree document handler error", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		v.sidetreeDocHandler = &mockDocHandler{Err: fmt.Errorf("sidetree document handler error")}

		recoveryKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		updateKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		docResolution, err := v.Create(didDoc, vdrapi.WithOption(UpdatePublicKeyOpt, updateKey),
			vdrapi.WithOption(RecoveryPublicKeyOpt, recoveryKey))
		require.Error(t, err)
		require.Nil(t, docResolution)
		require.Contains(t, err.Error(), "sidetree document handler error")
	})

	t.Run("test invalid key", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		updateKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		recoveryKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		invalidVM := ariesdid.NewVerificationMethodFromBytes("xyz", "Ed25519VerificationKey2018", "", pubKey)
		invalidVM.Value = nil

		invalidDoc := &ariesdid.Doc{}

		invalidDoc.Authentication = append(didDoc.Authentication,
			*ariesdid.NewReferencedVerification(invalidVM, ariesdid.Authentication))

		docResolution, err := v.Create(invalidDoc, vdrapi.WithOption(UpdatePublicKeyOpt, updateKey),
			vdrapi.WithOption(RecoveryPublicKeyOpt, recoveryKey))
		require.Error(t, err)
		require.Nil(t, docResolution)

		require.Contains(t, err.Error(), "verificationMethod needs either JSONWebKey or Base58 key")
	})

	t.Run("test update public key opt is empty", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		doc, err := v.Create(didDoc, vdrapi.WithOption(RecoveryPublicKeyOpt, []byte{}))
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "updatePublicKey opt is empty")
	})

	t.Run("test recovery public key opt is empty", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)

		doc, err := v.Create(didDoc, vdrapi.WithOption(UpdatePublicKeyOpt, []byte{}))
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "recoveryPublicKey opt is empty")
	})
}

func TestVDRI_Update(t *testing.T) {
	t.Run("error - function not implemented", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)
		require.NotNil(t, v)

		err = v.Update(&ariesdid.Doc{})
		require.Error(t, err)
		require.Contains(t, err.Error(), notImplemented)
	})
}

func TestVDRI_Deactivated(t *testing.T) {
	t.Run("error - function not implemented", func(t *testing.T) {
		v, err := New()
		require.NoError(t, err)
		require.NotNil(t, v)

		err = v.Deactivate("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), notImplemented)
	})
}

type mockSidetreeClient struct {
	DocResolution *ariesdid.DocResolution
	Err           error
}

func (m *mockSidetreeClient) CreateDID(_ ...create.Option) (*ariesdid.DocResolution, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.DocResolution, nil
}

type mockDocHandler struct {
	Err              error
	ResolutionResult *document.ResolutionResult
}

func (dh *mockDocHandler) ResolveDocument(_ string, _ ...document.ResolutionOption) (*document.ResolutionResult, error) {
	if dh.Err != nil {
		return nil, dh.Err
	}

	return dh.ResolutionResult, nil
}

func (dh *mockDocHandler) ProcessOperation(_ []byte) (*document.ResolutionResult, error) {
	if dh.Err != nil {
		return nil, dh.Err
	}

	return dh.ResolutionResult, nil
}

type mockLDStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (m *mockLDStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return m.ContextStore
}

func (m *mockLDStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return m.RemoteProviderStore
}

func createTestDocLoader(t *testing.T) *ld.DocumentLoader {
	t.Helper()

	p := &mockLDStoreProvider{
		ContextStore:        mockldstore.NewMockContextStore(),
		RemoteProviderStore: mockldstore.NewMockRemoteProviderStore(),
	}

	loader, err := ld.NewDocumentLoader(p)
	require.NoError(t, err)

	return loader
}

func prettyPrint(result interface{}) error {
	b, err := json.MarshalIndent(result, "", " ")
	if err != nil {
		return err
	}

	fmt.Println(string(b))

	return nil
}

func createVerificationMethod(keyType string, pubKey []byte, kid,
	signatureSuite string) (*ariesdid.VerificationMethod, error) {
	var j *jwk.JWK

	var err error

	switch keyType {
	case p256KeyType:
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey)

		j, err = jwksupport.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()})
		if err != nil {
			return nil, err
		}
	case p384KeyType:
		x, y := elliptic.Unmarshal(elliptic.P384(), pubKey)

		j, err = jwksupport.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P384()})
		if err != nil {
			return nil, err
		}
	case bls12381G2KeyType:
		pk, e := bbs12381g2pub.UnmarshalPublicKey(pubKey)
		if e != nil {
			return nil, e
		}

		j, err = jwksupport.JWKFromKey(pk)
		if err != nil {
			return nil, err
		}
	default:
		j, err = jwksupport.JWKFromKey(ed25519.PublicKey(pubKey))
		if err != nil {
			return nil, err
		}
	}

	return ariesdid.NewVerificationMethodFromJWK(kid, signatureSuite, "", j)
}

const didSuffix = `EiD9H4OHw5X4ctS1Q1G9LxmyEed9WDBW_QZ4VMpuOtRciw`
const requestJCS = `eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWduaW5nS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6IndkRGZEakwxRlFET3NwcC1xdmRLUUtyNzllbTdOczJFNVNBVWE5aElRaTQiLCJ5IjoiUGZmc0hEYXA1X0t3UlZwNzgtaUJaQm5XQTZMS3p6bGIxSXJ3VWhFakpuOCJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiIsImFzc2VydGlvbk1ldGhvZCIsImNhcGFiaWxpdHlJbnZvY2F0aW9uIiwiY2FwYWJpbGl0eURlbGVnYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOltdfX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlBazRmbkFKSTJuZ1Z5ZjhrZ05fbUI5emhmX2FKcmdwa2tlalVIbTR1X3gzQSJ9LCJzdWZmaXhEYXRhIjp7ImRlbHRhSGFzaCI6IkVpQVRaWi1jclh5OXFYeGhGdkFFZElhU0pLY0tTWTVubkZ5bkJCSWtsODF5N1EiLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUFOOHQ3UHlZYmtONFc3ZEVZX1JZX25YWUNlc1JPQl9mUWxzdWx3eVNyYVF3In0sInR5cGUiOiJjcmVhdGUifQ`
