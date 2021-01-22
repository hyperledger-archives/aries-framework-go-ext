/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package staticdiscovery implement staticdiscovery
//
package staticdiscovery

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

type config interface {
	GetConsortium(url, domain string) (*models.ConsortiumFileData, error)
	GetStakeholder(url, domain string) (*models.StakeholderFileData, error)
}

// DiscoveryService fetches endpoints for a consortium.
type DiscoveryService struct {
	config config
}

// NewService create new DiscoveryService.
func NewService(c config) *DiscoveryService {
	endpointService := &DiscoveryService{
		config: c,
	}

	return endpointService
}

// GetEndpoints get a list of endpoints to use from a consortium domain.
func (ds *DiscoveryService) GetEndpoints(consortiumDomain string) ([]*models.Endpoint, error) {
	consortiumData, err := ds.config.GetConsortium(consortiumDomain, consortiumDomain)
	if err != nil {
		return nil, fmt.Errorf("getting consortium: %w", err)
	}

	consortium := consortiumData.Config
	if consortium == nil {
		return nil, fmt.Errorf("consortium config is nil")
	}

	stakeholders, err := ds.getStakeholderConfigs(consortium)
	if err != nil {
		return nil, fmt.Errorf("stakeholder config: %w", err)
	}

	return ds.getEndpointsFromStakeholders(stakeholders), nil
}

// getStakeholderConfigs gets the list of stakeholder configs.
func (ds *DiscoveryService) getStakeholderConfigs(consortium *models.Consortium) ([]models.StakeholderFileData, error) { // nolint: lll
	stakeholders := make([]models.StakeholderFileData, 0)

	for _, s := range consortium.Members {
		stakeholderConfig, err := ds.config.GetStakeholder(s.Domain, s.Domain)
		if err != nil {
			return nil, err
		}

		stakeholders = append(stakeholders, *stakeholderConfig)
	}

	return stakeholders, nil
}

// getEndpointsFromStakeholders constructs the list of endpoints from the data in the list of stakeholders.
func (ds *DiscoveryService) getEndpointsFromStakeholders(stakeholders []models.StakeholderFileData) []*models.Endpoint {
	var endpoints []*models.Endpoint

	for _, stakeholderConfig := range stakeholders {
		for _, ep := range stakeholderConfig.Config.Endpoints {
			endpoints = append(endpoints, &models.Endpoint{
				URL:    ep,
				Domain: stakeholderConfig.Config.Domain,
			})
		}
	}

	return endpoints
}
