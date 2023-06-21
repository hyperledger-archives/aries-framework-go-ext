/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	vdrapi "github.com/hyperledger/aries-framework-go/component/vdr/api"
)

const (
	schemaResV1    = "https://w3id.org/did-resolution/v1"
	schemaDIDV1    = "https://www.w3.org/ns/did/v1"
	jwsSuiteV1     = "https://w3id.org/security/suites/jws-2020/v1"
	jsonWebKey2020 = "JsonWebKey2020"
)

// Read expands did:jwk value to a DID document.
func (v *VDR) Read(didJWK string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	parsed, err := did.Parse(didJWK)
	if err != nil {
		return nil, fmt.Errorf("jwk-vdr read: failed to parse DID: %w", err)
	}

	if parsed.Method != DIDMethod {
		return nil, fmt.Errorf("jwk-vdr read: invalid method: %s", parsed.Method)
	}

	key, err := getJWK(parsed.MethodSpecificID)
	if err != nil {
		return nil, fmt.Errorf("jwk-vdr read: failed to get key: %w", err)
	}

	return createJWKResolutionResult(didJWK, key)
}

func createJWKResolutionResult(didJWK string, key *jwk.JWK) (*did.DocResolution, error) {
	vm, err := did.NewVerificationMethodFromJWK(fmt.Sprintf("%s#0", didJWK), jsonWebKey2020, didJWK, key)
	if err != nil {
		return nil, fmt.Errorf("generate resolution result: error creating verification method: %w", err)
	}

	didDoc := createDoc(vm, didJWK)

	return &did.DocResolution{Context: []string{schemaResV1}, DIDDocument: didDoc}, nil
}

func createDoc(pubKey *did.VerificationMethod, didJWK string) *did.Doc {
	didDoc := &did.Doc{ //nolint:exhaustruct
		Context:            []string{schemaDIDV1, jwsSuiteV1},
		ID:                 didJWK,
		VerificationMethod: []did.VerificationMethod{*pubKey},
	}

	if pubKey.JSONWebKey().Use == "" || pubKey.JSONWebKey().Use == "sig" {
		didDoc.Authentication = []did.Verification{*did.NewReferencedVerification(pubKey, did.Authentication)}
		didDoc.AssertionMethod = []did.Verification{*did.NewReferencedVerification(pubKey, did.AssertionMethod)}
		didDoc.CapabilityDelegation = []did.Verification{*did.NewReferencedVerification(pubKey, did.CapabilityDelegation)}
		didDoc.CapabilityInvocation = []did.Verification{*did.NewReferencedVerification(pubKey, did.CapabilityInvocation)}
	}

	if pubKey.JSONWebKey().Use == "" || pubKey.JSONWebKey().Use == "enc" {
		didDoc.KeyAgreement = []did.Verification{*did.NewReferencedVerification(pubKey, did.KeyAgreement)}
	}

	return didDoc
}

func getJWK(jwkMethodID string) (*jwk.JWK, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(jwkMethodID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	var key jwk.JWK

	err = json.Unmarshal(decoded, &key)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}

	return &key, nil
}
