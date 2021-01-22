/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/square/go-jose/v3"
)

/*
A stakeholder's config file is a JWS, signed by the stakeholder,
with the payload being a JSON object containing:
- The stakeholder's domain
- The stakeholder's DID (did:trustbloc)
- Stakeholder custom configuration settings
- The stakeholder's Sidetree endpoints
- the hash of the previous version of this config file
*/

// Stakeholder holds the configuration for a stakeholder.
type Stakeholder struct {
	// Domain is the domain name of the stakeholder organisation,
	//   where the primary copy of the stakeholder config can be found
	Domain string `json:"domain,omitempty"`
	// DID is the DID of this stakeholder
	DID string `json:"did,omitempty"`
	// Policy contains stakeholder-specific configuration settings
	Policy StakeholderSettings `json:"policy"`
	// Endpoints is a list of sidetree endpoints owned by this stakeholder organization
	Endpoints []string `json:"endpoints"`
	// Previous is a hashlink to the previous version of this file
	Previous string `json:"previous,omitempty"`
}

// StakeholderSettings holds the stakeholder settings.
type StakeholderSettings struct {
	Cache CacheControl `json:"cache"`
}

// StakeholderFileData holds a stakeholder config file, with the original JWS and the unpacked payload.
type StakeholderFileData struct {
	Config *Stakeholder
	JWS    *jose.JSONWebSignature
}

// CacheLifetime returns the cache lifetime of the stakeholder file before it needs to be checked for an update.
func (s StakeholderFileData) CacheLifetime() (time.Duration, error) {
	if s.Config == nil {
		return 0, fmt.Errorf("missing config object")
	}

	return time.Duration(s.Config.Policy.Cache.MaxAge) * time.Second, nil
}

// ParseStakeholder parses a stakeholder config within a JWS.
func ParseStakeholder(data []byte) (*StakeholderFileData, error) {
	jws, err := jose.ParseSigned(string(data))
	if err != nil {
		return nil, errors.New("stakeholder config data should be a JWS")
	}

	configBytes := jws.UnsafePayloadWithoutVerification()

	var config Stakeholder

	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, err
	}

	return &StakeholderFileData{
		Config: &config,
		JWS:    jws,
	}, nil
}
