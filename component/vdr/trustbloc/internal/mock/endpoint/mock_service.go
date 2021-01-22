/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package endpoint implement mock endpoint
//
package endpoint

import (
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

// MockEndpointService implements a mock endpoint service.
type MockEndpointService struct {
	GetEndpointsFunc func(domain string) ([]*models.Endpoint, error)
}

// GetEndpoints discover endpoints for a consortium domain.
func (m *MockEndpointService) GetEndpoints(domain string) ([]*models.Endpoint, error) {
	if m.GetEndpointsFunc != nil {
		return m.GetEndpointsFunc(domain)
	}

	return nil, nil
}
