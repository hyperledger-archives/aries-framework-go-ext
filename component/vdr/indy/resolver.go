/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
)

const (
	schemaV1 = "https://w3id.org/did/v1"
	keyType  = "Ed25519VerificationKey2018"
)

type indyPubkey struct {
	verkey  string
	pubKey  *diddoc.VerificationMethod
	txnTime time.Time
}

func (v *VDR) Read(did string, opts ...vdrapi.DIDMethodOption) (*diddoc.DocResolution, error) {
	parsedDID, err := diddoc.Parse(did)
	if err != nil {
		return nil, fmt.Errorf("parsing did failed in indy resolver: (%w)", err)
	}

	if parsedDID.Method != v.MethodName {
		return nil, fmt.Errorf("invalid indy method name: %s", parsedDID.MethodSpecificID)
	}

	resOpts := &vdrapi.DIDMethodOpts{}

	for _, opt := range opts {
		opt(resOpts)
	}

	res, err := v.getPubKey(parsedDID)
	if err != nil {
		return nil, err
	}

	verMethod := diddoc.NewReferencedVerification(res.pubKey, diddoc.Authentication)

	var svc []diddoc.Service

	serviceEndpoint, err := v.getEndpoint(parsedDID.MethodSpecificID)
	if err == nil {
		s := diddoc.Service{
			ID:              "#agent",
			Type:            vdrapi.DIDCommServiceType,
			ServiceEndpoint: serviceEndpoint,
			Priority:        0,
			RecipientKeys:   []string{res.verkey},
		}

		svc = append(svc, s)
	}

	doc := &diddoc.Doc{
		Context:            []string{schemaV1},
		ID:                 did,
		VerificationMethod: []diddoc.VerificationMethod{*res.pubKey},
		Authentication:     []diddoc.Verification{*verMethod},
		Service:            svc,
		Created:            &res.txnTime,
		Updated:            &res.txnTime,
	}

	return &diddoc.DocResolution{DIDDocument: doc}, nil
}

func (v *VDR) getPubKey(did *diddoc.DID) (*indyPubkey, error) {
	rply, err := v.Client.GetNym(did.MethodSpecificID)
	if err != nil {
		return nil, err
	}

	if rply.Data == nil {
		return nil, errors.New("couldn't resolve did")
	}

	m := map[string]interface{}{}

	err = json.Unmarshal([]byte(rply.Data.(string)), &m)
	if err != nil {
		return nil, err
	}

	verkey, ok := m["verkey"].(string)
	if !ok {
		return nil, errors.New("invalid response from ledger, no verkey")
	}

	pubKeyValue := base58.Decode(verkey)

	KID, err := localkms.CreateKID(pubKeyValue, kms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("unable to create key ID: %v", err)
	}

	pubKey := diddoc.NewVerificationMethodFromBytes("#"+KID, keyType, "#id", pubKeyValue)

	txnTime := time.Unix(int64(rply.TxnTime), 0)

	return &indyPubkey{
		verkey:  verkey,
		pubKey:  pubKey,
		txnTime: txnTime,
	}, nil
}

func (v *VDR) getEndpoint(did string) (string, error) {
	rply, err := v.Client.GetEndpoint(did)
	if err != nil || rply.Data == nil {
		return "", errors.New("not found")
	}

	m := map[string]interface{}{}

	err = json.Unmarshal([]byte(rply.Data.(string)), &m)
	if err != nil {
		return "", err
	}

	mm, ok := m["endpoint"].(map[string]interface{})
	if !ok {
		return "", errors.New("not found")
	}

	ep, ok := mm["endpoint"].(string)
	if !ok {
		return "", errors.New("not found")
	}

	return ep, nil
}
