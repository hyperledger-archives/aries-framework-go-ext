/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package config implement config
//
package config

import (
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

// MockConfigService implements a mock config service.
type MockConfigService struct {
	GetConsortiumFunc     func(string, string) (*models.ConsortiumFileData, error)
	GetStakeholderFunc    func(string, string) (*models.StakeholderFileData, error)
	GetSidetreeConfigFunc func(string) (*models.SidetreeConfig, error)
}

// GetConsortium get the consortium config file for a given domain from the given url.
func (m *MockConfigService) GetConsortium(url, domain string) (*models.ConsortiumFileData, error) {
	if m.GetConsortiumFunc != nil {
		return m.GetConsortiumFunc(url, domain)
	}

	return nil, nil
}

// GetStakeholder get the stakeholder config file for a given domain from the given url.
func (m *MockConfigService) GetStakeholder(url, domain string) (*models.StakeholderFileData, error) {
	if m.GetStakeholderFunc != nil {
		return m.GetStakeholderFunc(url, domain)
	}

	return nil, nil
}

// GetSidetreeConfig get the sidetree config.
func (m *MockConfigService) GetSidetreeConfig(url string) (*models.SidetreeConfig, error) {
	if m.GetSidetreeConfigFunc != nil {
		return m.GetSidetreeConfigFunc(url)
	}

	return nil, nil
}
