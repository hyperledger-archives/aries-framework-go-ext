/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package didconfiguration implement didconfiguration
//
package didconfiguration

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// MockDIDConfigService implements a mock DID configuration verification service.
type MockDIDConfigService struct {
	VerifyStakeholderFunc func(domain string, doc *did.Doc) error
}

// VerifyStakeholder fetch and verify a did configuration for a given stakeholder.
func (m *MockDIDConfigService) VerifyStakeholder(domain string, doc *did.Doc) error {
	if m.VerifyStakeholderFunc != nil {
		return m.VerifyStakeholderFunc(domain, doc)
	}

	return nil
}
