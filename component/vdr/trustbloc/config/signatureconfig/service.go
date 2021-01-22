/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package signatureconfig

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

type config interface {
	GetConsortium(string, string) (*models.ConsortiumFileData, error)
	GetStakeholder(string, string) (*models.StakeholderFileData, error)
	GetSidetreeConfig(url string) (*models.SidetreeConfig, error)
}

// ConfigService fetches consortium and stakeholder configs over http.
type ConfigService struct {
	config config
}

// NewService create new ConfigService.
func NewService(config config) *ConfigService {
	configService := &ConfigService{config: config}

	return configService
}

// GetConsortium fetches and parses the consortium file at the given domain.
func (cs *ConfigService) GetConsortium(url, domain string) (*models.ConsortiumFileData, error) {
	consortiumData, err := cs.config.GetConsortium(url, domain)
	if err != nil {
		return nil, fmt.Errorf("wrapped config service: %w", err)
	}

	consortium := consortiumData.Config
	if consortium == nil {
		return nil, fmt.Errorf("consortium is nil")
	}

	err = VerifyConsortiumSignatures(consortiumData, consortium)
	if err != nil {
		return nil, err
	}

	return consortiumData, nil
}

// GetStakeholder returns the stakeholder config file fetched by the wrapped config service.
func (cs *ConfigService) GetStakeholder(url, domain string) (*models.StakeholderFileData, error) {
	return cs.config.GetStakeholder(url, domain)
}

// GetSidetreeConfig get sidetree config.
func (cs *ConfigService) GetSidetreeConfig(url string) (*models.SidetreeConfig, error) {
	return cs.config.GetSidetreeConfig(url)
}
