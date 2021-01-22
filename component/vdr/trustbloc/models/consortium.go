/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package models implement models
//
package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/square/go-jose/v3"
)

/*
A consortium config file is a JWS, signed by the stakeholders,
with the payload being a JSON object containing:
  - The domain name of the consortium
  - Consortium policy configuration settings
  - A list of stakeholders - containing, for each stakeholder:
    - The web domain where its configuration can be found
    - The did:trustbloc DID of the stakeholder
  - The hash of the previous version of this config file
*/

// Consortium holds the configuration for a consortium, which is signed by stakeholders.
type Consortium struct {
	// Domain is the domain name of the consortium
	Domain string `json:"domain,omitempty"`
	// Policy contains the consortium policy configuration
	Policy ConsortiumPolicy `json:"policy"`
	// Members is a list containing references to the stakeholders on this consortium
	Members []*StakeholderListElement `json:"members"`
	// Previous contains a hashlink to the previous version of this file. Optional.
	Previous string `json:"previous,omitempty"`
}

// ConsortiumPolicy holds consortium policy configuration.
type ConsortiumPolicy struct {
	Cache      CacheControl `json:"cache"`
	NumQueries int          `json:"numQueries"`
}

// CacheControl holds cache settings for this file,
//  indicating to the recipient how long until they should check for a new version of the file.
type CacheControl struct {
	MaxAge uint32 `json:"maxAge"`
}

// StakeholderListElement holds the domain and DID of a stakeholder within the consortium.
type StakeholderListElement struct {
	// Domain is the domain name of the stakeholder
	Domain string `json:"domain,omitempty"`
	// DID is the DID of the stakeholder
	DID string `json:"did,omitempty"`
	// PublicKey is the verification key DID URL and public key
	PublicKey PublicKey `json:"publicKey,omitempty"`
}

// PublicKey is the verification key DID URL and public key.
type PublicKey struct {
	// ID  verification public key DID URL
	ID string `json:"id,omitempty"`
	// JWK verification public key in JWK format}
	JWK json.RawMessage `json:"jwk,omitempty"`
}

// ConsortiumFileData holds the data within a consortium config file.
type ConsortiumFileData struct {
	Config *Consortium
	JWS    *jose.JSONWebSignature
}

// CacheLifetime returns the cache lifetime of the consortium file before it needs to be checked for an update.
func (c ConsortiumFileData) CacheLifetime() (time.Duration, error) {
	if c.Config == nil {
		return 0, fmt.Errorf("missing config object")
	}

	return time.Duration(c.Config.Policy.Cache.MaxAge) * time.Second, nil
}

// ParseConsortium parses the contents of a consortium file into a ConsortiumFileData object.
func ParseConsortium(data []byte) (*ConsortiumFileData, error) {
	jws, err := jose.ParseSigned(string(data))
	if err != nil {
		return nil, errors.New("consortium config data should be a JWS")
	}

	configBytes := jws.UnsafePayloadWithoutVerification()

	var config Consortium

	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, err
	}

	return &ConsortiumFileData{
		Config: &config,
		JWS:    jws,
	}, nil
}
