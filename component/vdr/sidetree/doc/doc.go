/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package doc implements sidetree document
//
package doc

import (
	"encoding/json"
	"fmt"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
)

const (
	jsonldID            = "id"
	jsonldType          = "type"
	jsonldPurposes      = "purposes"
	jsonldServicePoint  = "serviceEndpoint"
	jsonldRecipientKeys = "recipientKeys"
	jsonldRoutingKeys   = "routingKeys"
	jsonldPriority      = "priority"

	jsonldPublicKeyjwk = "publicKeyJwk"

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

	// Ed25519VerificationKey2018 define key type signature.
	Ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

type rawDoc struct {
	PublicKey []map[string]interface{} `json:"publicKey,omitempty"`
	Service   []map[string]interface{} `json:"service,omitempty"`
}

// Doc DID Document definition.
type Doc struct {
	PublicKey []PublicKey
	Service   []docdid.Service
}

// PublicKey struct.
type PublicKey struct {
	ID       string
	Type     string
	Purposes []string
	JWK      jose.JWK
}

// JSONBytes converts document to json bytes.
func (doc *Doc) JSONBytes() ([]byte, error) {
	publicKeys, err := PopulateRawPublicKeys(doc.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Public Key failed: %w", err)
	}

	raw := &rawDoc{
		PublicKey: publicKeys,
		Service:   PopulateRawServices(doc.Service),
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
	if err != nil {
		return nil, err
	}

	rawJWK := make(map[string]interface{})
	if err := json.Unmarshal(jwkBytes, &rawJWK); err != nil {
		return nil, err
	}

	rawPK[jsonldPublicKeyjwk] = rawJWK

	return rawPK, nil
}

// PopulateRawServices populate raw services.
func PopulateRawServices(services []docdid.Service) []map[string]interface{} {
	rawServices := make([]map[string]interface{}, 0)

	for i := range services {
		rawService := make(map[string]interface{})

		for k, v := range services[i].Properties {
			rawService[k] = v
		}

		rawService[jsonldID] = services[i].ID
		rawService[jsonldType] = services[i].Type
		rawService[jsonldServicePoint] = services[i].ServiceEndpoint
		rawService[jsonldRecipientKeys] = services[i].RecipientKeys
		rawService[jsonldRoutingKeys] = services[i].RoutingKeys
		rawService[jsonldPriority] = services[i].Priority

		rawServices = append(rawServices, rawService)
	}

	return rawServices
}
