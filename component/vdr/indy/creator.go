/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

const (
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

// Create builds a new DID Doc.
func (v *VDR) Create(didDoc *did.Doc, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	docOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}
	// Apply options
	for _, opt := range opts {
		opt(docOpts)
	}

	docResolution, err := build(didDoc, docOpts)
	if err != nil {
		return nil, fmt.Errorf("create %s DID : %w", v.MethodName, err)
	}

	didDoc = docResolution.DIDDocument

	pubKeyValue := base58.Decode(string(didDoc.VerificationMethod[0].Value))
	methodID := base58.Encode(pubKeyValue[0:16])
	didKey := fmt.Sprintf("did:%s:%s", v.MethodName, methodID)

	didDoc.ID = didKey

	return &did.DocResolution{DIDDocument: didDoc}, nil
}

func build(didDoc *did.Doc, docOpts *vdrapi.DIDMethodOpts) (*did.DocResolution, error) {
	if len(didDoc.VerificationMethod) == 0 && len(didDoc.KeyAgreement) == 0 {
		return nil, fmt.Errorf("verification method and key agreement are empty, at least one should be set")
	}

	mainVM, err := buildDIDVMs(didDoc)
	if err != nil {
		return nil, err
	}

	// Service model to be included only if service type is provided through opts
	service, err := getServices(didDoc, docOpts)
	if err != nil {
		return nil, err
	}

	// Created/Updated time
	t := time.Now()

	assertion := []did.Verification{{
		VerificationMethod: *mainVM,
		Relationship:       did.AssertionMethod,
	}}

	authentication := []did.Verification{{
		VerificationMethod: *mainVM,
		Relationship:       did.Authentication,
	}}

	verificationMethods := []did.VerificationMethod{*mainVM}

	didDoc, err = newDoc(
		verificationMethods,
		did.WithService(service),
		did.WithCreatedTime(t),
		did.WithUpdatedTime(t),
		did.WithAuthentication(authentication),
		did.WithAssertion(assertion),
	)
	if err != nil {
		return nil, err
	}

	return &did.DocResolution{DIDDocument: didDoc}, nil
}

func getServices(didDoc *did.Doc, docOpts *vdrapi.DIDMethodOpts) ([]did.Service, error) {
	if len(didDoc.Service) == 0 {
		return nil, nil
	}

	services := make([]did.Service, len(didDoc.Service))

	for i := range didDoc.Service {
		service, err := configServices(&didDoc.Service[i], &didDoc.VerificationMethod[0], docOpts)
		if err != nil {
			return nil, err
		}

		services[i] = *service
	}

	return services, nil
}

func configServices(service *did.Service, verificationMethod *did.VerificationMethod,
	docOpts *vdrapi.DIDMethodOpts) (*did.Service, error) {
	if service.ID == "" {
		service.ID = uuid.New().String()
	}

	if service.Type == "" && docOpts.Values[DefaultServiceType] != nil {
		v, ok := docOpts.Values[DefaultServiceType].(string)
		if !ok {
			return nil, fmt.Errorf("defaultServiceType not string")
		}

		service.Type = v
	}

	if service.ServiceEndpoint == "" && docOpts.Values[DefaultServiceEndpoint] != nil {
		v, ok := docOpts.Values[DefaultServiceEndpoint].(string)
		if !ok {
			return nil, fmt.Errorf("defaultServiceEndpoint not string")
		}

		service.ServiceEndpoint = v
	}

	if service.Type == vdrapi.DIDCommServiceType {
		didKey, _ := fingerprint.CreateDIDKey(verificationMethod.Value)
		service.RecipientKeys = []string{didKey}
		service.Priority = 0
	}

	return service, nil
}

func buildDIDVMs(didDoc *did.Doc) (*did.VerificationMethod, error) {
	var mainVM *did.VerificationMethod

	if len(didDoc.VerificationMethod) != 0 {
		switch didDoc.VerificationMethod[0].Type {
		case ed25519VerificationKey2018:
			mainVM = did.NewVerificationMethodFromBytes(didDoc.VerificationMethod[0].ID, ed25519VerificationKey2018,
				"#id", didDoc.VerificationMethod[0].Value)

		default:
			return nil, fmt.Errorf("not supported VerificationMethod public key type: %s",
				didDoc.VerificationMethod[0].Type)
		}
	}

	return mainVM, nil
}

func newDoc(publicKey []did.VerificationMethod, opts ...did.DocOption) (*did.Doc, error) {
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("the did:peer genesis version must include public keys and authentication")
	}

	// build DID Doc
	doc := did.BuildDoc(append([]did.DocOption{did.WithVerificationMethod(publicKey)}, opts...)...)

	// Create a did doc based on the mandatory value: publicKeys & authentication
	if len(doc.Authentication) == 0 || len(doc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("the did must include public keys and authentication")
	}

	return doc, nil
}
