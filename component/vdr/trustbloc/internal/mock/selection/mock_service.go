/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package discovery implement discovery
//
package discovery

import (
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

// MockSelectionService implements a mock selection service.
type MockSelectionService struct {
	SelectEndpointsFunc func(domain string, endpoints []*models.Endpoint) ([]*models.Endpoint, error)
}

// SelectEndpoints select endpoints.
func (m *MockSelectionService) SelectEndpoints(domain string, endpoints []*models.Endpoint) ([]*models.Endpoint, error) { // nolint: lll
	if m.SelectEndpointsFunc != nil {
		return m.SelectEndpointsFunc(domain, endpoints)
	}

	return nil, nil
}
