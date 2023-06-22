/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	jwkapi "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/jwk"
)

func TestCreate(t *testing.T) {
	t.Run("success - P256 key from spec", func(t *testing.T) {
		var key jwkapi.JWK

		err := json.Unmarshal([]byte(testP256), &key)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("", "JsonWebKey2020", "", &key)
		require.NoError(t, err)

		testDoc := &did.Doc{}
		testDoc.VerificationMethod = []did.VerificationMethod{*vm}

		v := jwk.New()
		result, err := v.Create(testDoc)
		require.NoError(t, err)
		require.NotNil(t, result)

		didDoc := result.DIDDocument

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

	t.Run("success - test X25519 from spec", func(t *testing.T) {
		var key jwkapi.JWK

		err := json.Unmarshal([]byte(testX25519), &key)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("", "JsonWebKey2020", "", &key)
		require.NoError(t, err)

		testDoc := &did.Doc{}
		testDoc.VerificationMethod = []did.VerificationMethod{*vm}

		v := jwk.New()
		result, err := v.Create(testDoc)
		require.NoError(t, err)
		require.NotNil(t, result)

		didDoc := result.DIDDocument

		err = prettyPrint(didDoc)
		require.NoError(t, err)

		expectedDoc, err := did.ParseDocument([]byte(expectedX25519Document))
		require.NoError(t, err)

		// this test example from spec did not use JCS so ID will be different;
		// hence we cannot check for ID equality

		require.Equal(t, 1, len(didDoc.VerificationMethod))
		require.Equal(t, expectedDoc.VerificationMethod[0].Type, didDoc.VerificationMethod[0].Type)
		require.Equal(t, expectedDoc.VerificationMethod[0].JSONWebKey().Kty, didDoc.VerificationMethod[0].JSONWebKey().Kty)
		require.Equal(t, expectedDoc.VerificationMethod[0].JSONWebKey().Crv, didDoc.VerificationMethod[0].JSONWebKey().Crv)
		require.Equal(t, expectedDoc.VerificationMethod[0].JSONWebKey().Use, didDoc.VerificationMethod[0].JSONWebKey().Use)

		require.Equal(t, 0, len(didDoc.AssertionMethod))
		require.Equal(t, 0, len(didDoc.Authentication))
		require.Equal(t, 0, len(didDoc.CapabilityDelegation))
		require.Equal(t, 0, len(didDoc.CapabilityInvocation))
		require.Equal(t, 1, len(didDoc.KeyAgreement))
	})

	t.Run("test create - generated Ed25519 key", func(t *testing.T) {
		_, pk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		key, err := jwksupport.JWKFromKey(pk)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("", "JsonWebKey2020", "", key)
		require.NoError(t, err)

		testDoc := &did.Doc{}
		testDoc.VerificationMethod = []did.VerificationMethod{*vm}

		v := jwk.New()
		result, err := v.Create(testDoc)
		require.NoError(t, err)
		require.NotNil(t, result)

		didDoc := result.DIDDocument

		err = prettyPrint(didDoc)
		require.NoError(t, err)
	})

	t.Run("error - missing verification method", func(t *testing.T) {
		testDoc := &did.Doc{}
		testDoc.VerificationMethod = []did.VerificationMethod{}

		v := jwk.New()
		result, err := v.Create(testDoc)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "missing verification method")
	})

	t.Run("error - more than one verification method", func(t *testing.T) {
		var key jwkapi.JWK

		err := json.Unmarshal([]byte(testX25519), &key)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("", "JsonWebKey2020", "", &key)
		require.NoError(t, err)

		testDoc := &did.Doc{}
		testDoc.VerificationMethod = []did.VerificationMethod{*vm, *vm}

		v := jwk.New()
		result, err := v.Create(testDoc)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "found more than one verification method")
	})

	t.Run("error - wrong verification method type", func(t *testing.T) {
		var key jwkapi.JWK

		err := json.Unmarshal([]byte(testP256), &key)
		require.NoError(t, err)

		vm, err := did.NewVerificationMethodFromJWK("", "not-supported", "", &key)
		require.NoError(t, err)

		testDoc := &did.Doc{}
		testDoc.VerificationMethod = []did.VerificationMethod{*vm}

		v := jwk.New()
		result, err := v.Create(testDoc)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "verification method type[not-supported] is not supported")
	})

	t.Run("error - verification method is not JWK", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		vm := did.NewVerificationMethodFromBytes("", "JsonWebKey2020", "", pubKey)

		testDoc := &did.Doc{}
		testDoc.VerificationMethod = []did.VerificationMethod{*vm}

		v := jwk.New()
		result, err := v.Create(testDoc)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "missing JWK")
	})
}

const testP256 = `{
	"crv": "P-256",
	"kty": "EC",
	"x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
	"y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
}`

const testX25519 = `{
	"kty":"OKP",
	"crv":"X25519",
	"use":"enc",
	"x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
}`
