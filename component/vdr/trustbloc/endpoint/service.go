/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package endpoint implement endpoint service
//
package endpoint

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

type discovery interface {
	GetEndpoints(domain string) ([]*models.Endpoint, error)
}

type selection interface {
	SelectEndpoints(domain string, endpoints []*models.Endpoint) ([]*models.Endpoint, error)
}

// EndpointService uses discovery service and selection service to fetch and filter endpoints.
type EndpointService struct { // nolint: golint
	discovery discovery
	selection selection
}

// NewService create new EndpointService.
func NewService(d discovery, s selection) *EndpointService {
	endpointService := &EndpointService{
		discovery: d,
		selection: s,
	}

	return endpointService
}

// GetEndpoints get a list of endpoints to use from a consortium at a given domain.
func (es *EndpointService) GetEndpoints(domain string) ([]*models.Endpoint, error) {
	eps, err := es.discovery.GetEndpoints(domain)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}

	out, err := es.selection.SelectEndpoints(domain, eps)
	if err != nil {
		return nil, fmt.Errorf("selection: %w", err)
	}

	return out, nil
}
