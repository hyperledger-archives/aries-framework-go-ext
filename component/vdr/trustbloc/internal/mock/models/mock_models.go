/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package models implement models
//
package models

import (
	"encoding/base64"
	"encoding/json"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

// DummyJWSWrap wraps a config JSON in a dummy JWS.
func DummyJWSWrap(data string) string {
	dataB64 := base64.RawURLEncoding.EncodeToString([]byte(data))

	return `{"payload":"` + dataB64 + `","signatures":[{"header":{"kid":""}, "signature":""}]}`
}

// DummyConsortium creates a default consortium object.
func DummyConsortium(consortiumDomain string, stakeholders []*models.StakeholderListElement) *models.Consortium {
	cc := &models.Consortium{
		Domain:   consortiumDomain,
		Policy:   models.ConsortiumPolicy{Cache: models.CacheControl{MaxAge: 0}},
		Members:  stakeholders,
		Previous: "",
	}

	return cc
}

// DummyConsortiumJSON creates a dummy consortium JSON config.
func DummyConsortiumJSON(consortiumDomain string, stakeholders []*models.StakeholderListElement) (string, error) {
	out, err := json.Marshal(DummyConsortium(consortiumDomain, stakeholders))
	if err != nil {
		return "", err
	}

	return DummyJWSWrap(string(out)), nil
}

// WrapConsortium marshals a consortium to JSON and wraps it in a dummy JWS.
func WrapConsortium(consortium *models.Consortium) (string, error) {
	out, err := json.Marshal(consortium)
	if err != nil {
		return "", err
	}

	return DummyJWSWrap(string(out)), nil
}

// WrapStakeholder marshals a stakeholder to JSON and wraps it in a dummy JWS.
func WrapStakeholder(stakeholder *models.Stakeholder) (string, error) {
	out, err := json.Marshal(stakeholder)
	if err != nil {
		return "", err
	}

	return DummyJWSWrap(string(out)), nil
}

// DummyStakeholder creates a dummy stakeholder JSON config.
func DummyStakeholder(stakeholderDomain string, endpoints []string) *models.Stakeholder {
	return &models.Stakeholder{
		Domain:    stakeholderDomain,
		DID:       "",
		Policy:    models.StakeholderSettings{Cache: models.CacheControl{MaxAge: 0}},
		Endpoints: endpoints,
		Previous:  "",
	}
}

// DummyStakeholderJSON creates a dummy stakeholder JSON config.
func DummyStakeholderJSON(stakeholderDomain string, endpoints []string) (string, error) {
	sc := DummyStakeholder(stakeholderDomain, endpoints)

	out, err := json.Marshal(sc)
	if err != nil {
		return "", err
	}

	return DummyJWSWrap(string(out)), nil
}
