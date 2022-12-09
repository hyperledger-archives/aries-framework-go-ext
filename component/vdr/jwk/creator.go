/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk

import (
	"encoding/base64"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
)

// Create new DID document for didDoc.
func (v *VDR) Create(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	// make sure there is one verification method
	if len(didDoc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("missing verification method")
	}

	if len(didDoc.VerificationMethod) > 1 {
		return nil, fmt.Errorf("found more than one verification method")
	}

	if didDoc.VerificationMethod[0].Type != jsonWebKey2020 {
		return nil, fmt.Errorf("verification method type[%s] is not supported", didDoc.VerificationMethod[0].Type)
	}

	key := didDoc.VerificationMethod[0].JSONWebKey()

	didJWK, err := createDID(key)
	if err != nil {
		return nil, fmt.Errorf("error creating DID: %w", err)
	}

	return createJWKResolutionResult(didJWK, key)
}

func createDID(key *jwk.JWK) (string, error) {
	if key == nil {
		return "", fmt.Errorf("missing JWK")
	}

	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("marshal key: %w", err)
	}

	canonicalBytes, err := canonicalizer.MarshalCanonical(keyBytes)
	if err != nil {
		return "", fmt.Errorf("marshal canonical: %w", err)
	}

	didJWK := fmt.Sprintf("did:%s:%s", DIDMethod, base64.RawURLEncoding.EncodeToString(canonicalBytes))

	return didJWK, nil
}
