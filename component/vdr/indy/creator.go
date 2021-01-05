/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
)

// Build builds a new DID Doc.
func (r *VDR) Build(pubKey *vdrapi.PubKey, opts ...vdrapi.DocOpts) (*did.Doc, error) {
	if pubKey.Type != keyType {
		return nil, fmt.Errorf("only %s key type supported", keyType)
	}

	docOpts := &vdrapi.CreateDIDOpts{}

	for _, opt := range opts {
		opt(docOpts)
	}

	pubKeyValue := base58.Decode(string(pubKey.Value))
	methodID := base58.Encode(pubKeyValue[0:16])
	didKey := fmt.Sprintf("did:%s:%s", r.MethodName, methodID)

	publicKey := did.NewVerificationMethodFromBytes(pubKey.ID, keyType, "#id", pubKey.Value)

	var service []did.Service

	if docOpts.DefaultServiceType != "" {
		s := did.Service{
			ID:              "#agent",
			Type:            docOpts.DefaultServiceType,
			ServiceEndpoint: docOpts.DefaultServiceEndpoint,
		}

		if docOpts.DefaultServiceType == vdrapi.DIDCommServiceType {
			s.RecipientKeys = []string{string(pubKey.Value)}
			s.Priority = 0
		}

		service = append(service, s)
	}

	// Created/Updated time
	t := time.Now()
	doc := did.BuildDoc(
		did.WithVerificationMethod([]did.VerificationMethod{*publicKey}),
		did.WithService(service),
		did.WithCreatedTime(t),
		did.WithUpdatedTime(t),
		did.WithAuthentication([]did.Verification{{
			VerificationMethod: *publicKey,
			Relationship:       did.Authentication,
		}}),
		did.WithAssertion([]did.Verification{{
			VerificationMethod: *publicKey,
			Relationship:       did.AssertionMethod,
		}}),
	)

	doc.ID = didKey

	return doc, nil
}
