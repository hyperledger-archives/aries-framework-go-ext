/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package updatevalidationconfig implement updatevalidationconfig
//
package updatevalidationconfig

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/config/signatureconfig"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

type config interface {
	GetConsortium(string, string) (*models.ConsortiumFileData, error)
	GetStakeholder(string, string) (*models.StakeholderFileData, error)
	GetSidetreeConfig(url string) (*models.SidetreeConfig, error)
}

// ConfigService fetches consortium and stakeholder configs
// Caches the current consortium config, and when updating, uses signature validation to verify that the updated
// consortium config is a valid update to the current one.
type ConfigService struct {
	config    config
	consortia map[stringPair]*models.ConsortiumFileData
}

// NewService create new ConfigService.
func NewService(config config) *ConfigService {
	configService := &ConfigService{config: config}

	configService.consortia = map[stringPair]*models.ConsortiumFileData{}

	return configService
}

// GetConsortium fetches and parses the consortium file at the given domain, validating it against a cached version
// of the file. Validation passes if the retrieved file is either:
//     a) the same as the cached file
//  or b) a valid successor, endorsed by the cached file.
func (cs *ConfigService) GetConsortium(url, domain string) (*models.ConsortiumFileData, error) {
	key := stringPair{domain: domain, url: url}

	cachedConsortium, ok := cs.consortia[key]
	if !ok || cachedConsortium == nil {
		return nil, fmt.Errorf("cached config missing from cache")
	}

	consortium := cachedConsortium.Config
	if consortium == nil {
		return nil, fmt.Errorf("cached consortium is nil")
	}

	// if we're here, the cached consortium has expired and we must refresh or update, and validate

	consortiumData, err := cs.config.GetConsortium(url, domain)
	if err != nil {
		return nil, fmt.Errorf("wrapped config service: %w", err)
	}

	// if they're the same, return
	if cachedConsortium.JWS.FullSerialize() == consortiumData.JWS.FullSerialize() {
		return cachedConsortium, nil
	}

	// validate new fetched data against old's signatures
	err = signatureconfig.VerifyConsortiumSignatures(consortiumData, consortium)
	if err != nil {
		return nil, fmt.Errorf("config update signature does not verify: %w", err)
	}

	cs.consortia[key] = consortiumData

	return consortiumData, nil
}

type stringPair struct {
	url, domain string
}

// AddGenesisFile adds a genesis file to the config.
func (cs *ConfigService) AddGenesisFile(url, domain string, genesisFile []byte) error {
	genesisConsortium, err := models.ParseConsortium(genesisFile)
	if err != nil {
		return fmt.Errorf("failed to add genesis file for url: %s, error: %w", url, err)
	}

	// TODO: error if repeat (url, domain)?
	// TODO: error if a genesis file is added during operation, after startup is already finished?

	cs.consortia[stringPair{domain: domain, url: url}] = genesisConsortium

	return nil
}

// GetStakeholder returns the stakeholder config file fetched by the wrapped config service.
func (cs *ConfigService) GetStakeholder(url, domain string) (*models.StakeholderFileData, error) {
	return cs.config.GetStakeholder(url, domain)
}

// GetSidetreeConfig get sidetree config.
func (cs *ConfigService) GetSidetreeConfig(url string) (*models.SidetreeConfig, error) {
	return cs.config.GetSidetreeConfig(url)
}
