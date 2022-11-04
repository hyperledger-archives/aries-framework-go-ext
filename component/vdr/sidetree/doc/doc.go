/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package doc implements sidetree document
package doc

import (
	"bytes"
	"encoding/json"
	"fmt"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
)

const (
	jsonldID            = "id"
	jsonldType          = "type"
	jsonldPurposes      = "purposes"
	jsonldServicePoint  = "serviceEndpoint"
	jsonldRecipientKeys = "recipientKeys"
	jsonldRoutingKeys   = "routingKeys"
	jsonldPriority      = "priority"
	jsonldAccept        = "accept"

	jsonldPublicKeyJwk    = "publicKeyJwk"
	jsonldPublicKeyBase58 = "publicKeyBase58"

	// KeyPurposeAuthentication defines key purpose as authentication key.
	KeyPurposeAuthentication = "authentication"
	// KeyPurposeAssertionMethod defines key purpose as assertion key.
	KeyPurposeAssertionMethod = "assertionMethod"
	// KeyPurposeKeyAgreement defines key purpose as agreement key.
	KeyPurposeKeyAgreement = "keyAgreement"
	// KeyPurposeCapabilityDelegation defines key purpose as delegation key.
	KeyPurposeCapabilityDelegation = "capabilityDelegation"
	// KeyPurposeCapabilityInvocation defines key purpose as invocation key.
	KeyPurposeCapabilityInvocation = "capabilityInvocation"

	// JWSVerificationKey2020 defines key type signature.
	JWSVerificationKey2020 = "JwsVerificationKey2020"

	// JWK2020Type defines key type for JWK public keys.
	JWK2020Type = "JsonWebKey2020"

	// Ed25519VerificationKey2018 define key type signature.
	Ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

type rawDoc struct {
	PublicKey   []map[string]interface{} `json:"publicKey,omitempty"`
	Service     []map[string]interface{} `json:"service,omitempty"`
	AlsoKnownAs []interface{}            `json:"alsoKnownAs,omitempty"`
}

// Doc DID Document definition.
type Doc struct {
	PublicKey   []PublicKey
	Service     []docdid.Service
	AlsoKnownAs []string
}

// PublicKey struct.
type PublicKey struct {
	ID       string
	Type     string
	Purposes []string
	JWK      jwk.JWK
	B58Key   string
}

// JSONBytes converts document to json bytes.
func (doc *Doc) JSONBytes() ([]byte, error) {
	publicKeys, err := PopulateRawPublicKeys(doc.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Public Key failed: %w", err)
	}

	services, err := PopulateRawServices(doc.Service)
	if err != nil {
		return nil, err
	}

	alsoKnownAs := PopulateRawAlsoKnownAs(doc.AlsoKnownAs)

	raw := &rawDoc{
		PublicKey:   publicKeys,
		Service:     services,
		AlsoKnownAs: alsoKnownAs,
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of document failed: %w", err)
	}

	return byteDoc, nil
}

// PopulateRawPublicKeys populate raw public keys.
func PopulateRawPublicKeys(pks []PublicKey) ([]map[string]interface{}, error) {
	rawPKs := make([]map[string]interface{}, 0)

	for i := range pks {
		publicKey, err := populateRawPublicKey(&pks[i])
		if err != nil {
			return nil, err
		}

		rawPKs = append(rawPKs, publicKey)
	}

	return rawPKs, nil
}

func populateRawPublicKey(pk *PublicKey) (map[string]interface{}, error) {
	rawPK := make(map[string]interface{})
	rawPK[jsonldID] = pk.ID
	rawPK[jsonldType] = pk.Type
	rawPK[jsonldPurposes] = pk.Purposes

	jwkBytes, err := pk.JWK.MarshalJSON()

	switch {
	case err == nil:
		rawJWK := make(map[string]interface{})
		if err := json.Unmarshal(jwkBytes, &rawJWK); err != nil {
			return nil, err
		}

		rawPK[jsonldPublicKeyJwk] = rawJWK
	case pk.Type == JWK2020Type:
		return nil, fmt.Errorf("no valid jwk in JsonWebKey2020 key")
	case pk.B58Key != "":
		rawPK[jsonldPublicKeyBase58] = pk.B58Key
	default:
		return nil, fmt.Errorf("public key must contain either a jwk or base58 key")
	}

	return rawPK, nil
}

// PopulateRawServices populate raw services.
func PopulateRawServices(services []docdid.Service) ([]map[string]interface{}, error) {
	rawServices := make([]map[string]interface{}, 0)

	for i := range services {
		rawService := make(map[string]interface{})

		for k, v := range services[i].Properties {
			rawService[k] = v
		}

		rawService[jsonldID] = services[i].ID
		rawService[jsonldType] = services[i].Type

		serviceEndpoint, err := services[i].ServiceEndpoint.MarshalJSON()
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(serviceEndpoint, []byte("null")) {
			rawService[jsonldServicePoint] = json.RawMessage(serviceEndpoint)
		}

		if services[i].Priority != nil {
			rawService[jsonldPriority] = services[i].Priority
		}

		if len(services[i].RecipientKeys) > 0 {
			rawService[jsonldRecipientKeys] = services[i].RecipientKeys
		}

		if len(services[i].RoutingKeys) > 0 {
			rawService[jsonldRoutingKeys] = services[i].RoutingKeys
		}

		if len(services[i].Accept) > 0 {
			rawService[jsonldAccept] = services[i].Accept
		}

		rawServices = append(rawServices, rawService)
	}

	return rawServices, nil
}

// PopulateRawAlsoKnownAs populates raw also known as.
func PopulateRawAlsoKnownAs(alsoKnownAs []string) []interface{} {
	values := make([]interface{}, len(alsoKnownAs))
	for i, v := range alsoKnownAs {
		values[i] = v
	}

	return values
}
