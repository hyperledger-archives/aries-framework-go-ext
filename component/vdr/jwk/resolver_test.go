/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/jwk"
)

func TestReadInvalidDID(t *testing.T) {
	t.Run("validate an invalid did", func(t *testing.T) {
		v := jwk.New()

		doc, err := v.Read("whatever")
		require.Error(t, err)
		require.Contains(t, err.Error(), "jwk-vdr read: failed to parse DID: invalid did")
		require.Nil(t, doc)
	})

	t.Run("validate an invalid did method", func(t *testing.T) {
		v := jwk.New()

		doc, err := v.Read("did:different:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
		require.Error(t, err)
		require.Contains(t, err.Error(), "jwk-vdr read: invalid method: different")
		require.Nil(t, doc)
	})

	t.Run("get JWK from method specific ID - unmarshal error", func(t *testing.T) {
		v := jwk.New()

		doc, err := v.Read("did:jwk:invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"jwk-vdr read: failed to get key: failed to unmarshal key: invalid character")
		require.Nil(t, doc)
	})

	t.Run("get JWK from method specific ID - decode error", func(t *testing.T) {
		v := jwk.New()

		doc, err := v.Read("did:jwk:1-2-3")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"jwk-vdr read: failed to get key: failed to decode key: illegal base64 data")
		require.Nil(t, doc)
	})
}

func TestReadP256(t *testing.T) {
	v := jwk.New()

	t.Run("success", func(t *testing.T) {
		docResolution, err := v.Read(p256JWK)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		didDoc := docResolution.DIDDocument
		err = prettyPrint(didDoc)
		require.NoError(t, err)

		expectedDoc, err := did.ParseDocument([]byte(expectedP256DIDDocument))
		require.NoError(t, err)

		require.Equal(t, didDoc.ID, expectedDoc.ID)

		require.Equal(t, 1, len(didDoc.VerificationMethod))
		require.Equal(t, expectedDoc.VerificationMethod[0].ID, didDoc.VerificationMethod[0].ID)
		require.Equal(t, expectedDoc.VerificationMethod[0].Controller, didDoc.VerificationMethod[0].Controller)
		require.Equal(t, expectedDoc.VerificationMethod[0].Type, didDoc.VerificationMethod[0].Type)
		require.Equal(t, expectedDoc.VerificationMethod[0].JSONWebKey().Kty, didDoc.VerificationMethod[0].JSONWebKey().Kty)
		require.Equal(t, expectedDoc.VerificationMethod[0].JSONWebKey().Crv, didDoc.VerificationMethod[0].JSONWebKey().Crv)
		require.Equal(t, expectedDoc.VerificationMethod[0].JSONWebKey().Use, didDoc.VerificationMethod[0].JSONWebKey().Use)

		require.Equal(t, 1, len(didDoc.AssertionMethod))
		require.Equal(t, expectedDoc.AssertionMethod[0], didDoc.AssertionMethod[0])
		require.Equal(t, 1, len(didDoc.Authentication))
		require.Equal(t, expectedDoc.Authentication[0], didDoc.Authentication[0])
		require.Equal(t, 1, len(didDoc.CapabilityDelegation))
		require.Equal(t, expectedDoc.CapabilityDelegation[0], didDoc.CapabilityDelegation[0])
		require.Equal(t, 1, len(didDoc.CapabilityInvocation))
		require.Equal(t, expectedDoc.CapabilityInvocation[0], didDoc.CapabilityInvocation[0])
		require.Equal(t, 1, len(didDoc.KeyAgreement))
		require.Equal(t, expectedDoc.KeyAgreement[0], didDoc.KeyAgreement[0])

		canonicalDIDDoc, err := canonicalizer.MarshalCanonical(didDoc)
		require.NoError(t, err)
		canonicalExpectedDoc, err := canonicalizer.MarshalCanonical(expectedDoc)
		require.NoError(t, err)

		require.Equal(t, string(canonicalExpectedDoc), string(canonicalDIDDoc))
	})
}

func TestReadX25519(t *testing.T) {
	v := jwk.New()

	t.Run("success", func(t *testing.T) {
		docResolution, err := v.Read(x25519)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		didDoc := docResolution.DIDDocument

		err = prettyPrint(didDoc)
		require.NoError(t, err)

		expectedDoc, err := did.ParseDocument([]byte(expectedX25519Document))
		require.NoError(t, err)

		require.Equal(t, didDoc.ID, expectedDoc.ID)

		require.Equal(t, 1, len(didDoc.VerificationMethod))
		require.Equal(t, expectedDoc.VerificationMethod[0].ID, didDoc.VerificationMethod[0].ID)
		require.Equal(t, expectedDoc.VerificationMethod[0].Controller, didDoc.VerificationMethod[0].Controller)
		require.Equal(t, expectedDoc.VerificationMethod[0].Type, didDoc.VerificationMethod[0].Type)
		require.Equal(t, expectedDoc.VerificationMethod[0].JSONWebKey().Kty, didDoc.VerificationMethod[0].JSONWebKey().Kty)
		require.Equal(t, expectedDoc.VerificationMethod[0].JSONWebKey().Crv, didDoc.VerificationMethod[0].JSONWebKey().Crv)
		require.Equal(t, expectedDoc.VerificationMethod[0].JSONWebKey().Use, didDoc.VerificationMethod[0].JSONWebKey().Use)

		require.Equal(t, 0, len(didDoc.AssertionMethod))
		require.Equal(t, 0, len(didDoc.Authentication))
		require.Equal(t, 0, len(didDoc.CapabilityDelegation))
		require.Equal(t, 0, len(didDoc.CapabilityInvocation))
		require.Equal(t, 1, len(didDoc.KeyAgreement))
		require.Equal(t, expectedDoc.KeyAgreement[0], didDoc.KeyAgreement[0])

		canonicalDIDDoc, err := canonicalizer.MarshalCanonical(didDoc)
		require.NoError(t, err)
		canonicalExpectedDoc, err := canonicalizer.MarshalCanonical(expectedDoc)
		require.NoError(t, err)

		require.Equal(t, string(canonicalExpectedDoc), string(canonicalDIDDoc))
	})
}

func TestCreateJsonWeKey(t *testing.T) {
	t.Run("test invalid code", func(t *testing.T) {
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

const p256JWK = `did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9`

const x25519 = `did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9`

const expectedP256DIDDocument = `
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
  "verificationMethod": [
    {
      "id": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0",
      "type": "JsonWebKey2020",
      "controller": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
      "publicKeyJwk": {
        "crv": "P-256",
        "kty": "EC",
        "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
        "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
      }
    }
  ],
  "assertionMethod": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
  "authentication": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
  "capabilityInvocation": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
  "capabilityDelegation": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
  "keyAgreement": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"]
}`

const expectedX25519Document = `
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9",
  "verificationMethod": [
    {
      "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0",
      "type": "JsonWebKey2020",
      "controller": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9",
      "publicKeyJwk": {
        "kty":"OKP",
        "crv":"X25519",
        "use":"enc",
        "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
      }
    }
  ],
  "keyAgreement": ["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0"]
}`
