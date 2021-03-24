/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package didconfiguration

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

const (
	keyJSON = `{
  "kty": "OKP",
  "kid": "key1",
  "d": "CSLczqR1ly2lpyBcWne9gFKnsjaKJw0dKfoSQu7lNvg",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`
	testDoc = `{
  "@context": ["https://w3id.org/did/v1"],
  "verificationMethod": [{
    "id": "did:example:123456789abcdefghi#key-2",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyJwk":{
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "8rfXFZNHZs9GYzGbQLYDasGUAm1brAgTLI0jrD4KheU"
    },
    "type":"JwsVerificationKey2020"
  }],
  "id": "did:example:123456789abcdefghi",
  "authentication": [
    {
      "id": "did:example:123456789abcdefghi#key-1",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyJwk":{
		"kty": "OKP",
		"crv": "Ed25519",
	    "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
	  },
      "type":"JwsVerificationKey2020"
    }
  ],
  "service": []
}`
)

func TestCreateDIDConfiguration(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		conf, err := CreateDIDConfiguration("domain.website", "did:example:123abc", 0, &sigKey)
		require.NoError(t, err)

		require.Len(t, conf.Entries, 1)
		require.Equal(t, conf.Entries[0].DID, "did:example:123abc")
	})

	t.Run("failure", func(t *testing.T) {
		keyJSON := `{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`

		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		_, err = CreateDIDConfiguration("domain.website", "did:example:123abc", 0, &sigKey)
		require.Error(t, err)

		require.Contains(t, err.Error(), "can't create")
	})
}

func TestCreateDomainLinkageAssertion(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		dla, err := createDomainLinkageAssertion("domain.website", "did:example:123abc", 0, &sigKey)
		require.NoError(t, err)

		require.Equal(t, dla.DID, "did:example:123abc")
	})

	t.Run("failure - bad key", func(t *testing.T) {
		keyJSON := `{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "badKey"
}`

		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		_, err = createDomainLinkageAssertion("domain.website", "did:example:123abc", 0, &sigKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "can't construct signer")
	})
}

func TestVerifyDIDConfiguration(t *testing.T) {
	t.Run("successful verification", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		doc, err := did.ParseDocument([]byte(testDoc))
		require.NoError(t, err)

		claims := models.DomainLinkageAssertionClaims{
			ISS:    "did:example:123456789abcdefghi",
			Domain: "domain.website",
			Exp:    99999999999999999,
		}

		claimsBytes, err := json.Marshal(claims)
		require.NoError(t, err)

		sigKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: key}
		signer, err := jose.NewSigner(sigKey, nil)
		require.NoError(t, err)

		jws, err := signer.Sign(claimsBytes)
		require.NoError(t, err)

		jwsCompact, err := jws.CompactSerialize()
		require.NoError(t, err)

		dla := models.DomainLinkageAssertion{
			DID: "did:example:123456789abcdefghi",
			JWT: jwsCompact,
		}

		didConfig := models.DIDConfiguration{Entries: []models.DomainLinkageAssertion{
			dla,
		}}

		dids, err := VerifyDIDConfiguration("domain.website", &didConfig, doc)
		require.NoError(t, err)
		require.Len(t, dids, 1)
		require.Contains(t, dids, "did:example:123456789abcdefghi")
	})

	t.Run("failed verification", func(t *testing.T) {
		dla := models.DomainLinkageAssertion{
			DID: "did:example:123456789abcdefghi",
			JWT: "bad data %$^&*(",
		}

		didConfig := models.DIDConfiguration{Entries: []models.DomainLinkageAssertion{
			dla,
		}}

		_, err := VerifyDIDConfiguration("domain.website", &didConfig, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "assertions invalid for domain")
	})
}

func TestValidateDomainLinkageAssertion(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		doc, err := did.ParseDocument([]byte(testDoc))
		require.NoError(t, err)

		claims := models.DomainLinkageAssertionClaims{
			ISS:    "did:example:123456789abcdefghi",
			Domain: "domain.website",
			Exp:    99999999999999999,
		}

		claimsBytes, err := json.Marshal(claims)
		require.NoError(t, err)

		sigKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: key}
		signer, err := jose.NewSigner(sigKey, nil)
		require.NoError(t, err)

		jws, err := signer.Sign(claimsBytes)
		require.NoError(t, err)

		jwsCompact, err := jws.CompactSerialize()
		require.NoError(t, err)

		dla := models.DomainLinkageAssertion{
			DID: "did:example:123456789abcdefghi",
			JWT: jwsCompact,
		}

		err = ValidateDomainLinkageAssertion("domain.website", dla, doc)
		require.NoError(t, err)
	})

	t.Run("failure - can't parse jwt", func(t *testing.T) {
		dla := models.DomainLinkageAssertion{
			DID: "did:example:123456789abcdefghi",
			JWT: "bad data %$^&*(",
		}

		err := ValidateDomainLinkageAssertion("domain.website", dla, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot parse assertion JWT")
	})

	t.Run("failure - can't parse claims", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: key}
		signer, err := jose.NewSigner(sigKey, nil)
		require.NoError(t, err)

		jws, err := signer.Sign([]byte("$BadData"))
		require.NoError(t, err)

		jwsCompact, err := jws.CompactSerialize()
		require.NoError(t, err)

		dla := models.DomainLinkageAssertion{
			DID: "did:example:123456789abcdefghi",
			JWT: jwsCompact,
		}

		err = ValidateDomainLinkageAssertion("domain.website", dla, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse assertion JWT claims")
	})

	t.Run("failure - DID does not match", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		claims := models.DomainLinkageAssertionClaims{
			ISS:    "did:example:123456789abcdefghi",
			Domain: "domain.website",
			Exp:    99999999999999999,
		}

		claimsBytes, err := json.Marshal(claims)
		require.NoError(t, err)

		sigKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: key}
		signer, err := jose.NewSigner(sigKey, nil)
		require.NoError(t, err)

		jws, err := signer.Sign(claimsBytes)
		require.NoError(t, err)

		jwsCompact, err := jws.CompactSerialize()
		require.NoError(t, err)

		dla := models.DomainLinkageAssertion{
			DID: "did:example:ThisIsADifferentDID",
			JWT: jwsCompact,
		}

		err = ValidateDomainLinkageAssertion("domain.website", dla, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "DID does not match")
	})

	t.Run("failure - domain does not match", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		claims := models.DomainLinkageAssertionClaims{
			ISS:    "did:example:123456789abcdefghi",
			Domain: "domain.website",
			Exp:    99999999999999999,
		}

		claimsBytes, err := json.Marshal(claims)
		require.NoError(t, err)

		sigKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: key}
		signer, err := jose.NewSigner(sigKey, nil)
		require.NoError(t, err)

		jws, err := signer.Sign(claimsBytes)
		require.NoError(t, err)

		jwsCompact, err := jws.CompactSerialize()
		require.NoError(t, err)

		dla := models.DomainLinkageAssertion{
			DID: "did:example:123456789abcdefghi",
			JWT: jwsCompact,
		}

		err = ValidateDomainLinkageAssertion("wrong.domain", dla, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "domain does not match")
	})

	t.Run("failure - expired assertion", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		doc, err := did.ParseDocument([]byte(testDoc))
		require.NoError(t, err)

		claims := models.DomainLinkageAssertionClaims{
			ISS:    "did:example:123456789abcdefghi",
			Domain: "domain.website",
			Exp:    1,
		}

		claimsBytes, err := json.Marshal(claims)
		require.NoError(t, err)

		sigKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: key}
		signer, err := jose.NewSigner(sigKey, nil)
		require.NoError(t, err)

		jws, err := signer.Sign(claimsBytes)
		require.NoError(t, err)

		jwsCompact, err := jws.CompactSerialize()
		require.NoError(t, err)

		dla := models.DomainLinkageAssertion{
			DID: "did:example:123456789abcdefghi",
			JWT: jwsCompact,
		}

		err = ValidateDomainLinkageAssertion("domain.website", dla, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "assertion has expired")
	})

	t.Run("failure - doc does not authenticate", func(t *testing.T) {
		testDoc := `{
  "@context": ["https://w3id.org/did/v1"],
  "publicKey": [],
  "id": "did:example:123456789abcdefghi",
  "authentication": [],
  "service": []
}`

		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		doc, err := did.ParseDocument([]byte(testDoc))
		require.NoError(t, err)

		claims := models.DomainLinkageAssertionClaims{
			ISS:    "did:example:123456789abcdefghi",
			Domain: "domain.website",
			Exp:    99999999999999999,
		}

		claimsBytes, err := json.Marshal(claims)
		require.NoError(t, err)

		sigKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: key}
		signer, err := jose.NewSigner(sigKey, nil)
		require.NoError(t, err)

		jws, err := signer.Sign(claimsBytes)
		require.NoError(t, err)

		jwsCompact, err := jws.CompactSerialize()
		require.NoError(t, err)

		dla := models.DomainLinkageAssertion{
			DID: "did:example:123456789abcdefghi",
			JWT: jwsCompact,
		}

		err = ValidateDomainLinkageAssertion("domain.website", dla, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify")
	})
}

func TestVerifyDIDSignature(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		doc, err := did.ParseDocument([]byte(testDoc))
		require.NoError(t, err)

		claims := models.DomainLinkageAssertionClaims{
			ISS:    "did:example:123456789abcdefghi",
			Domain: "domain.website",
			Exp:    99999999999999999,
		}

		claimsBytes, err := json.Marshal(claims)
		require.NoError(t, err)

		sigKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: key}
		signer, err := jose.NewSigner(sigKey, nil)
		require.NoError(t, err)

		jws, err := signer.Sign(claimsBytes)
		require.NoError(t, err)

		_, err = VerifyDIDSignature(jws, doc)
		require.NoError(t, err)
	})

	t.Run("failure - doc has no keys, can't authenticate", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		testDoc := `{
  "@context": ["https://w3id.org/did/v1"],
  "publicKey": [],
  "id": "did:example:123456789abcdefghi",
  "authentication": [],
  "service": []
}`

		doc, err := did.ParseDocument([]byte(testDoc))
		require.NoError(t, err)

		claims := models.DomainLinkageAssertionClaims{
			ISS:    "did:example:123456789abcdefghi",
			Domain: "domain.website",
			Exp:    99999999999999999,
		}

		claimsBytes, err := json.Marshal(claims)
		require.NoError(t, err)

		sigKey := jose.SigningKey{Algorithm: jose.EdDSA, Key: key}
		signer, err := jose.NewSigner(sigKey, nil)
		require.NoError(t, err)

		jws, err := signer.Sign(claimsBytes)
		require.NoError(t, err)

		_, err = VerifyDIDSignature(jws, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify")
	})
}
