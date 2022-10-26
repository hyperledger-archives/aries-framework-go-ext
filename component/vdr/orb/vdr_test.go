/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// nolint: testpackage
package orb

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/api"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/create"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/deactivate"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/recovery"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/update"
)

// nolint: lll
const validDocResolution = `
{
   "@context":"https://w3id.org/did-resolution/v1",
   "didDocument": ` + validDoc + `,
   "didDocumentMetadata":{
      "canonicalId":"did:ex:123333",
      "method":{
         "published":true,
         "recoveryCommitment":"EiB1u5HnTYKVHrmemOpZtrGlc6BoaWWHwNAd-k7CrLKHOg",
         "updateCommitment":"EiAiTB0QR_Skh3i-fzDSeFgjVoMEDsXYoVIsA56-GUsKjg",
         "unpublishedOperations": [
          {
            "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
            "protocolVersion": 0,
            "transactionTime": 1635519155,
            "type": "create"
           }
        ]
      }
   }
}
`

// nolint: lll
const validDocResolutionCachedUpdate = `
{
   "@context":"https://w3id.org/did-resolution/v1",
   "didDocument": ` + validDoc + `,
   "didDocumentMetadata":{
      "canonicalId":"did:ex:123333",
      "method":{
         "published":true,
         "recoveryCommitment":"EiB1u5HnTYKVHrmemOpZtrGlc6BoaWWHwNAd-k7CrLKHOg",
         "updateCommitment":"EiAiTB0QR_Skh3i-fzDSeFgjVoMEDsXYoVIsA56-GUsKjg",
         "unpublishedOperations": [
          {
            "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
            "protocolVersion": 0,
            "transactionTime": 1635519155,
            "type": "update"
           }
        ]
      }
   }
}
`

//nolint:lll
const validDoc = `{
  "@context": ["https://w3id.org/did/v1"],
  "id": "did:example:21tDAKCERh95uGgKbJNHYp",
  "alsoKnownAs": ["https://myblog.example/"],
  "verificationMethod": [
    {
      "id": "did:example:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:example:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "controller": "did:example:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    }
  ],
  "authentication": [
    "did:example:123456789abcdefghi#keys-1",
    {
      "id": "did:example:123456789abcdefghs#key3",
      "type": "RsaVerificationKey2018",
      "controller": "did:example:123456789abcdefghs",
      "publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
    }
  ],
  "service": [
    {
      "id": "did:example:123456789abcdefghi#inbox",
      "type": "SocialWebInboxService",
      "serviceEndpoint": "https://social.example.com/83hfh37dj",
      "spamCost": {
        "amount": "0.50",
        "currency": "USD"
      }
    },
    {
      "id": "did:example:123456789abcdefghi#did-communication",
      "type": "did-communication",
      "serviceEndpoint": "https://agent.example.com/",
      "priority" : 0,
      "recipientKeys" : ["did:example:123456789abcdefghi#key2"],
      "routingKeys" : ["did:example:123456789abcdefghi#key2"]
    }
  ]
}`

func TestVDRI_Accept(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)
		require.True(t, v.Accept(DIDMethod))
	})

	t.Run("test return false", func(t *testing.T) {
		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)
		require.False(t, v.Accept("bloc1"))
	})
}

func TestVDRI_Create(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.getHTTPVDR = httpVdrFunc(&did.DocResolution{
			DIDDocument:      &did.Doc{ID: "did"},
			DocumentMetadata: &did.DocumentMetadata{Method: &did.MethodMetadata{Published: true}},
		}, nil)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		vm2 := did.NewVerificationMethodFromBytes("id2", "", "", pk)

		ver := did.NewReferencedVerification(vm, did.Authentication)
		ver2 := did.NewReferencedVerification(vm2, did.AssertionMethod)

		verAssertionMethod := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"}, did.AssertionMethod)
		verKeyAgreement := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"}, did.KeyAgreement)
		verCapabilityDelegation := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"},
			did.CapabilityDelegation)
		verCapabilityInvocation := did.NewReferencedVerification(&did.VerificationMethod{ID: "id2"},
			did.CapabilityInvocation)

		sleepTime := 1 * time.Second

		docResolution, err := v.Create(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			AlsoKnownAs: []string{"https://myblog.example/"},
			Authentication: []did.Verification{
				*ver,
				*ver2,
				*verAssertionMethod,
				*verKeyAgreement,
				*verCapabilityDelegation,
				*verCapabilityInvocation,
			},
		}, vdrapi.WithOption(UpdatePublicKeyOpt, []byte{}),
			vdrapi.WithOption(RecoveryPublicKeyOpt, []byte{}),
			vdrapi.WithOption(AnchorOriginOpt, "origin.com"),
			vdrapi.WithOption(CheckDIDAnchored, &ResolveDIDRetry{MaxNumber: 2, SleepTime: &sleepTime}),
			vdrapi.WithOption(ResolutionEndpointsOpt, []string{"url"}))
		require.NoError(t, err)
		require.Equal(t, "did", docResolution.DIDDocument.ID)
	})

	t.Run("test create did and did not published", func(t *testing.T) {
		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.getHTTPVDR = httpVdrFunc(&did.DocResolution{
			DIDDocument:      &did.Doc{ID: "did"},
			DocumentMetadata: &did.DocumentMetadata{Method: &did.MethodMetadata{Published: false}},
		}, nil)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		vm2 := did.NewVerificationMethodFromBytes("id2", "", "", pk)

		ver := did.NewReferencedVerification(vm, did.Authentication)
		ver2 := did.NewReferencedVerification(vm2, did.AssertionMethod)

		verAssertionMethod := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"}, did.AssertionMethod)
		verKeyAgreement := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"}, did.KeyAgreement)
		verCapabilityDelegation := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"},
			did.CapabilityDelegation)
		verCapabilityInvocation := did.NewReferencedVerification(&did.VerificationMethod{ID: "id2"},
			did.CapabilityInvocation)

		sleepTime := 1 * time.Second

		_, err = v.Create(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{
				*ver,
				*ver2,
				*verAssertionMethod,
				*verKeyAgreement,
				*verCapabilityDelegation,
				*verCapabilityInvocation,
			},
		}, vdrapi.WithOption(UpdatePublicKeyOpt, []byte{}),
			vdrapi.WithOption(RecoveryPublicKeyOpt, []byte{}),
			vdrapi.WithOption(AnchorOriginOpt, "origin.com"),
			vdrapi.WithOption(CheckDIDAnchored, &ResolveDIDRetry{MaxNumber: 2, SleepTime: &sleepTime}),
			vdrapi.WithOption(ResolutionEndpointsOpt, []string{"url"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "did is not published")
	})

	t.Run("test create did and resolve return error", func(t *testing.T) {
		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.getHTTPVDR = httpVdrFunc(nil, fmt.Errorf("failed to resolve"))

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		vm2 := did.NewVerificationMethodFromBytes("id2", "", "", pk)

		ver := did.NewReferencedVerification(vm, did.Authentication)
		ver2 := did.NewReferencedVerification(vm2, did.AssertionMethod)

		verAssertionMethod := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"}, did.AssertionMethod)
		verKeyAgreement := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"}, did.KeyAgreement)
		verCapabilityDelegation := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"},
			did.CapabilityDelegation)
		verCapabilityInvocation := did.NewReferencedVerification(&did.VerificationMethod{ID: "id2"},
			did.CapabilityInvocation)

		sleepTime := 1 * time.Second

		_, err = v.Create(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{
				*ver,
				*ver2,
				*verAssertionMethod,
				*verKeyAgreement,
				*verCapabilityDelegation,
				*verCapabilityInvocation,
			},
		}, vdrapi.WithOption(UpdatePublicKeyOpt, []byte{}),
			vdrapi.WithOption(RecoveryPublicKeyOpt, []byte{}),
			vdrapi.WithOption(AnchorOriginOpt, "origin.com"),
			vdrapi.WithOption(CheckDIDAnchored, &ResolveDIDRetry{MaxNumber: 2, SleepTime: &sleepTime}),
			vdrapi.WithOption(ResolutionEndpointsOpt, []string{"url"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve did")
	})

	t.Run("test update public key opt is empty", func(t *testing.T) {
		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		_, err = v.Create(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver},
		}, vdrapi.WithOption(OperationEndpointsOpt, []string{"url"}),
			vdrapi.WithOption(RecoveryPublicKeyOpt, []byte{}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "updatePublicKey opt is empty")
	})

	t.Run("test recovery public key opt is empty", func(t *testing.T) {
		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		_, err = v.Create(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver},
		}, vdrapi.WithOption(OperationEndpointsOpt, []string{"url"}),
			vdrapi.WithOption(UpdatePublicKeyOpt, []byte{}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "recoveryPublicKey opt is empty")
	})

	t.Run("test anchor origin opt is empty", func(t *testing.T) {
		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		_, err = v.Create(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver},
		}, vdrapi.WithOption(OperationEndpointsOpt, []string{"url"}),
			vdrapi.WithOption(UpdatePublicKeyOpt, []byte{}),
			vdrapi.WithOption(RecoveryPublicKeyOpt, []byte{}))
		require.NoError(t, err)
	})

	t.Run("test anchor origin opt is not string", func(t *testing.T) {
		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		_, err = v.Create(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver},
		}, vdrapi.WithOption(OperationEndpointsOpt, []string{"url"}),
			vdrapi.WithOption(UpdatePublicKeyOpt, []byte{}),
			vdrapi.WithOption(RecoveryPublicKeyOpt, []byte{}),
			vdrapi.WithOption(AnchorOriginOpt, true))
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchorOrigin is not string")
	})
}

func TestVDRI_Deactivate(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{}

		err = v.Deactivate("did:ex:domain:123", vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}))
		require.NoError(t, err)
	})

	t.Run("test error from get did doc", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{}

		err = v.Deactivate("", vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve did")
	})
}

func TestVDRI_Close(t *testing.T) {
	v, err := New(nil)
	require.NoError(t, err)

	require.Nil(t, v.Close())
}

func TestVDRI_Update(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		vm1, err := did.NewVerificationMethodFromJWK("did:example:123456789abcdefghi#keys-1", "k1", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		ver1 := did.NewReferencedVerification(vm1, did.Authentication)

		err = v.Update(&did.Doc{
			AlsoKnownAs: []string{"https://other-blog.example/"},
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver, *ver1},
		}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}))
		require.NoError(t, err)
	})

	t.Run("test update and max retry number is zero", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{getNextUpdatePublicKey: func(didID, commitment string) (crypto.PublicKey, error) {
			pk, _, err := ed25519.GenerateKey(rand.Reader)

			return pk, err
		}}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		vm1, err := did.NewVerificationMethodFromJWK("did:example:123456789abcdefghi#keys-1", "k1", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		ver1 := did.NewReferencedVerification(vm1, did.Authentication)

		err = v.Update(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver, *ver1},
		}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(CheckDIDUpdated, &ResolveDIDRetry{MaxNumber: 0}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve did retry max number is less than one")
	})

	t.Run("test update and resolve sleep time is nil", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{getNextUpdatePublicKey: func(didID, commitment string) (crypto.PublicKey, error) {
			pk, _, err := ed25519.GenerateKey(rand.Reader)

			return pk, err
		}}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		vm1, err := did.NewVerificationMethodFromJWK("did:example:123456789abcdefghi#keys-1", "k1", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		ver1 := did.NewReferencedVerification(vm1, did.Authentication)

		err = v.Update(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver, *ver1},
		}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(CheckDIDUpdated, &ResolveDIDRetry{MaxNumber: 1}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve did retry sleep time is nil")
	})

	t.Run("test update and resolve check did not updated", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{getNextUpdatePublicKey: func(didID, commitment string) (crypto.PublicKey, error) {
			pk, _, err := ed25519.GenerateKey(rand.Reader)

			return pk, err
		}}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.getHTTPVDR = httpVdrFunc(&did.DocResolution{
			DIDDocument:      &did.Doc{ID: "did"},
			DocumentMetadata: &did.DocumentMetadata{Method: &did.MethodMetadata{Published: true}},
		}, nil)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		vm1, err := did.NewVerificationMethodFromJWK("did:example:123456789abcdefghi#keys-1", "k1", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		ver1 := did.NewReferencedVerification(vm1, did.Authentication)

		sleepTime := 1 * time.Second

		err = v.Update(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver, *ver1},
		}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(CheckDIDUpdated, &ResolveDIDRetry{MaxNumber: 1, SleepTime: &sleepTime}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "did is not updated")
	})

	t.Run("test update and resolve max retry is zero", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		vm1, err := did.NewVerificationMethodFromJWK("did:example:123456789abcdefghi#keys-1", "k1", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		ver1 := did.NewReferencedVerification(vm1, did.Authentication)

		err = v.Update(&did.Doc{
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver, *ver1},
		}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}))
		require.NoError(t, err)
	})

	t.Run("test error from get did doc", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		err = v.Update(&did.Doc{}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve did")
	})

	t.Run("test failed to get next update public key", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{getNextUpdatePublicKey: func(didID,
			commitment string) (crypto.PublicKey, error) {
			return nil, fmt.Errorf("failed to get next update public key")
		}}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)
		err = v.Update(&did.Doc{}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next update public key")
	})

	t.Run("test failed to get signing key", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{getSigner: func(didID string, ot OperationType,
			commitment string) (api.Signer, error) {
			return nil, fmt.Errorf("failed to get signing key")
		}}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)
		err = v.Update(&did.Doc{}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get signing key")
	})
}

func TestVDRI_Recover(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}}

		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("id", "", "", jwk)
		require.NoError(t, err)

		ver := did.NewReferencedVerification(vm, did.Authentication)

		err = v.Update(&did.Doc{
			AlsoKnownAs: []string{"https://recover.example/"},
			Service: []did.Service{
				{ID: "svc"},
			},
			Authentication: []did.Verification{*ver},
		}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(RecoverOpt, true))
		require.NoError(t, err)
	})

	t.Run("test error get sidetree public keys", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.sidetreeClient = &mockSidetreeClient{createDIDValue: &did.DocResolution{
			DIDDocument: &did.Doc{ID: "did"},
		}}

		verAuthentication := did.NewReferencedVerification(&did.VerificationMethod{ID: "id"}, did.Authentication)

		err = v.Update(&did.Doc{
			Service:        []did.Service{{ID: "svc"}},
			Authentication: []did.Verification{*verAuthentication},
		},
			vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(RecoverOpt, true),
			vdrapi.WithOption(AnchorOriginOpt, "origin.com"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "verificationMethod needs either JSONWebKey or Base58 key")

		verAuthentication.Relationship = did.VerificationRelationshipGeneral

		err = v.Update(&did.Doc{
			Service:        []did.Service{{ID: "svc"}},
			Authentication: []did.Verification{*verAuthentication},
		},
			vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(RecoverOpt, true),
			vdrapi.WithOption(AnchorOriginOpt, "origin.com"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "vm relationship 0 not supported")
	})

	t.Run("test anchor origin is not string", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(nil, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		err = v.Update(&did.Doc{}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(RecoverOpt, true),
			vdrapi.WithOption(AnchorOriginOpt, true))
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchorOrigin is not string")
	})

	t.Run("test failed to get next update public key", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{getNextUpdatePublicKey: func(didID string,
			commitment string) (crypto.PublicKey, error) {
			return nil, fmt.Errorf("failed to get next update public key")
		}}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)
		err = v.Update(&did.Doc{}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(RecoverOpt, true),
			vdrapi.WithOption(AnchorOriginOpt, "origin.com"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next update public key")
	})

	t.Run("test failed to get next recovery public key", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{getNextRecoveryPublicKeyFunc: func(didID,
			commitment string) (crypto.PublicKey, error) {
			return nil, fmt.Errorf("failed to get next recovery public key")
		}}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)
		err = v.Update(&did.Doc{}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(RecoverOpt, true),
			vdrapi.WithOption(AnchorOriginOpt, "origin.com"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next recovery public key")
	})

	t.Run("test failed to get signing key", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/did+ld+json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, validDocResolution)
		}))
		defer cServ.Close()

		v, err := New(&mockKeyRetriever{getSigner: func(didID string, ot OperationType,
			commitment string) (api.Signer, error) {
			return nil, fmt.Errorf("failed to get signing key")
		}}, WithHTTPClient(&http.Client{}))
		require.NoError(t, err)
		err = v.Update(&did.Doc{}, vdrapi.WithOption(ResolutionEndpointsOpt, []string{cServ.URL}),
			vdrapi.WithOption(RecoverOpt, true),
			vdrapi.WithOption(AnchorOriginOpt, "origin.com"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get signing key")
	})
}

func httpVdrFunc(doc *did.DocResolution, err error) func(url string) (v vdr, err error) {
	return func(url string) (v vdr, e error) {
		return &mockvdr.MockVDR{
			ReadFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return doc, err
			},
		}, nil
	}
}

func TestVDRI_Read(t *testing.T) {
	t.Run("test error from get http vdri for resolver url", func(t *testing.T) {
		v, err := New(nil)
		require.NoError(t, err)

		_, err = v.getHTTPVDR("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty url")

		v.getHTTPVDR = func(url string) (v vdr, err error) {
			return nil, fmt.Errorf("get http vdri error")
		}

		doc, err := v.Read("did", vdrapi.WithOption(ResolutionEndpointsOpt, []string{"url"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get http vdri error")
		require.Nil(t, doc)
	})

	t.Run("test error from get endpoint from ipns", func(t *testing.T) {
		v, err := New(nil, WithAuthTokenProvider(&tokenProvider{}))
		require.NoError(t, err)

		v.discoveryService = &mockDiscoveryService{getEndpointAnchorOriginFunc: func(did string) (*models.Endpoint, error) {
			return nil, fmt.Errorf("failed to get endpoint ipns")
		}}

		_, err = v.getHTTPVDR("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty url")

		v.getHTTPVDR = func(url string) (v vdr, err error) {
			return nil, fmt.Errorf("get http vdri error")
		}

		doc, err := v.Read("did:orb:ipfs:aaa:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoint ipns")
		require.Nil(t, doc)
	})

	t.Run("test success for resolver url", func(t *testing.T) {
		v, err := New(nil)
		require.NoError(t, err)

		v.getHTTPVDR = httpVdrFunc(&did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}, nil)

		doc, err := v.Read("did", vdrapi.WithOption(ResolutionEndpointsOpt, []string{"url"}))
		require.NoError(t, err)
		require.Equal(t, "did", doc.DIDDocument.ID)
	})

	t.Run("test failed to fetch endpoint without domain", func(t *testing.T) {
		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-type", "application/json")
			w.WriteHeader(http.StatusOK)
		}))
		defer cServ.Close()

		v, err := New(nil, WithIPFSEndpoint(cServ.URL), WithHTTPClient(&http.Client{}))
		require.NoError(t, err)

		v.getHTTPVDR = httpVdrFunc(&did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}, nil)

		_, err = v.Read("did:orb:hl:uEiDQ7jDgtU_HbF_CJWK79GFUylwRlS7AeaqwNiXXf3dVng:uoQ-BeEJpcGZzOi8vYmFma3JlaWdxNX" +
			"l5b2Jua3B5NXdmN3FyZm1rNTdpeWt1empvYmRmam95YjQydm1id2V4bHg2NTJ2dHk:EiBRNTUwbxYTOHMKbt9oYtn71GZLKPQ1Co" +
			"iw2_DgoTdooQ")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})

	t.Run("test success for fetch endpoint from https hint", func(t *testing.T) {
		v, err := New(nil, WithDomain("d1"))
		require.NoError(t, err)

		v.getHTTPVDR = httpVdrFunc(&did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}, nil)
		v.discoveryService = &mockDiscoveryService{getEndpointFunc: func(domain string) (*models.Endpoint, error) {
			return &models.Endpoint{ResolutionEndpoints: []string{"example.com", "url2"}, MinResolvers: 2}, nil
		}}

		doc, err := v.Read("did:orb:https:example.com:uAAA:EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA")
		require.NoError(t, err)
		require.Equal(t, "did", doc.DIDDocument.ID)
	})

	t.Run("test error different doc returned", func(t *testing.T) {
		v, err := New(nil, WithDomain("d1"))
		require.NoError(t, err)

		c := 1

		v.getHTTPVDR = func(url string) (v vdr, e error) {
			return &mockvdr.MockVDR{
				ReadFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					c++
					if c == 2 {
						return &did.DocResolution{DIDDocument: &did.Doc{ID: "did"}}, nil
					}

					return did.ParseDocumentResolution([]byte(validDocResolution))
				},
			}, nil
		}

		v.discoveryService = &mockDiscoveryService{getEndpointFunc: func(domain string) (*models.Endpoint, error) {
			return &models.Endpoint{ResolutionEndpoints: []string{"url1", "url2"}, MinResolvers: 2}, nil
		}}

		_, err = v.Read("did:ex:domain:1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to fetch correct did from min resolvers")
	})

	t.Run("test unanchored did reach max time", func(t *testing.T) {
		v, err := New(nil, WithDomain("d1"), WithUnanchoredMaxLifeTime(2*time.Second))
		require.NoError(t, err)

		didDoc, err := did.ParseDocumentResolution([]byte(validDocResolution))
		require.NoError(t, err)

		didDoc.DocumentMetadata.Method.UnpublishedOperations[0].TransactionTime = time.Now().Unix()
		didDoc.DIDDocument.ID = "did:orb:uAAA:domain:1234"

		v.getHTTPVDR = func(url string) (v vdr, e error) {
			return &mockvdr.MockVDR{
				ReadFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					return didDoc, nil
				},
			}, nil
		}

		v.discoveryService = &mockDiscoveryService{getEndpointFunc: func(domain string) (*models.Endpoint, error) {
			return &models.Endpoint{ResolutionEndpoints: []string{"url1", "url2"}, MinResolvers: 1}, nil
		}}

		v.verifier = &mockVerifierResolutionResult{}

		_, err = v.Read("did:orb:uAAA:domain:1234")
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		_, err = v.Read("did:orb:uAAA:domain:1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unanchored DID reach max time for usage")
	})

	t.Run("test cached updated did reach max time", func(t *testing.T) {
		v, err := New(nil, WithDomain("d1"), WithUnanchoredMaxLifeTime(2*time.Second))
		require.NoError(t, err)

		didDoc, err := did.ParseDocumentResolution([]byte(validDocResolutionCachedUpdate))
		require.NoError(t, err)

		didDoc.DocumentMetadata.Method.UnpublishedOperations[0].TransactionTime = time.Now().Unix()
		didDoc.DIDDocument.ID = "did:orb:uAAA:domain:1234"

		v.getHTTPVDR = func(url string) (v vdr, e error) {
			return &mockvdr.MockVDR{
				ReadFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					return didDoc, nil
				},
			}, nil
		}

		v.discoveryService = &mockDiscoveryService{getEndpointFunc: func(domain string) (*models.Endpoint, error) {
			return &models.Endpoint{ResolutionEndpoints: []string{"url1", "url2"}, MinResolvers: 1}, nil
		}}

		v.verifier = &mockVerifierResolutionResult{}

		_, err = v.Read("did:orb:uAAA:domain:1234")
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		_, err = v.Read("did:orb:uAAA:domain:1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "cached updated DID reach max time for usage")
	})

	t.Run("test error from fetch endpoint from domain", func(t *testing.T) {
		v, err := New(nil, WithDomain("d1"))
		require.NoError(t, err)

		v.getHTTPVDR = httpVdrFunc(nil, fmt.Errorf("failed to resolve"))
		v.discoveryService = &mockDiscoveryService{getEndpointFunc: func(domain string) (*models.Endpoint, error) {
			return &models.Endpoint{ResolutionEndpoints: []string{"url1"}, MinResolvers: 1}, nil
		}}

		_, err = v.Read("did:ex:domain:1234")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve")
	})

	t.Run("test fetch endpoints from did not not supported", func(t *testing.T) {
		v, err := New(nil, WithDomain("d1"))
		require.NoError(t, err)

		_, err = v.Read("did:orb:domain:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoints: failed to get key[d1] from endpoints cache")
	})

	t.Run("test wrong type OperationEndpointsOpt", func(t *testing.T) {
		v, err := New(nil)
		require.NoError(t, err)

		_, err = v.Read("did", vdrapi.WithOption(ResolutionEndpointsOpt, "url"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolutionEndpointsOpt not array of string")
	})
}

type mockSidetreeClient struct {
	createDIDValue *did.DocResolution
}

func (m *mockSidetreeClient) CreateDID(opts ...create.Option) (*did.DocResolution, error) {
	return m.createDIDValue, nil
}

func (m *mockSidetreeClient) UpdateDID(didID string, opts ...update.Option) error {
	return nil
}

func (m *mockSidetreeClient) RecoverDID(didID string, opts ...recovery.Option) error {
	return nil
}

func (m *mockSidetreeClient) DeactivateDID(didID string, opts ...deactivate.Option) error {
	return nil
}

type mockKeyRetriever struct {
	getNextRecoveryPublicKeyFunc func(didID, commitment string) (crypto.PublicKey, error)
	getNextUpdatePublicKey       func(didID, commitment string) (crypto.PublicKey, error)
	getSigner                    func(didID string, ot OperationType, commitment string) (api.Signer, error)
}

func (m *mockKeyRetriever) GetNextRecoveryPublicKey(didID, commitment string) (crypto.PublicKey, error) {
	if m.getNextRecoveryPublicKeyFunc != nil {
		return m.getNextRecoveryPublicKeyFunc(didID, commitment)
	}

	return nil, nil
}

func (m *mockKeyRetriever) GetNextUpdatePublicKey(didID, commitment string) (crypto.PublicKey, error) {
	if m.getNextUpdatePublicKey != nil {
		return m.getNextUpdatePublicKey(didID, commitment)
	}

	return nil, nil
}

func (m *mockKeyRetriever) GetSigner(didID string, ot OperationType, commitment string) (api.Signer, error) {
	if m.getSigner != nil {
		return m.getSigner(didID, ot, commitment)
	}

	return nil, nil
}

type mockDiscoveryService struct {
	getEndpointFunc             func(domain string) (*models.Endpoint, error)
	getEndpointAnchorOriginFunc func(did string) (*models.Endpoint, error)
}

func (m *mockDiscoveryService) GetEndpoint(domain string) (*models.Endpoint, error) {
	if m.getEndpointFunc != nil {
		return m.getEndpointFunc(domain)
	}

	return nil, nil
}

func (m *mockDiscoveryService) GetEndpointFromAnchorOrigin(didURI string) (*models.Endpoint, error) {
	if m.getEndpointAnchorOriginFunc != nil {
		return m.getEndpointAnchorOriginFunc(didURI)
	}

	return nil, nil
}

type mockVerifierResolutionResult struct{}

func (m *mockVerifierResolutionResult) Verify(input *document.ResolutionResult) error {
	return nil
}

type tokenProvider struct{}

func (t *tokenProvider) AuthToken() (string, error) {
	return "newTK", nil
}
