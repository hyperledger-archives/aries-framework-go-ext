/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package verifyingconfig implement verifyingconfig
//
package verifyingconfig

import (
	"bytes"
	"fmt"
	"math/rand"

	log "github.com/sirupsen/logrus"

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
	configService := &ConfigService{
		config: config,
	}

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

	n := consortium.Policy.NumQueries

	// if ds.numStakeholders is 0, then we use all stakeholders
	if n == 0 {
		n = len(consortium.Members)
	}

	perm := rand.Perm(len(consortium.Members))

	// number of stakeholders that have verified
	verifiedCount := 0

	verificationErrors := ""

	for i := 0; i < n; i++ {
		stakeholder := consortium.Members[perm[i]].Domain
		// get consortium file from stakeholder server
		file, err := cs.config.GetConsortium(stakeholder, domain)
		if err != nil {
			msg := "stakeholder peer failed to return consortium config: " + err.Error()
			log.Warn(msg)
			verificationErrors += msg + ", "

			continue // skip failed stakeholders
		}

		if !bytes.Equal(file.JWS.UnsafePayloadWithoutVerification(), consortiumData.JWS.UnsafePayloadWithoutVerification()) {
			verificationErrors += "stakeholder copy of consortium file does not match, "

			continue
		}

		verifiedCount++
	}

	if verifiedCount < n {
		return nil, fmt.Errorf(
			"insufficient stakeholder endorsement of consortium config file. errors are: [%s]",
			verificationErrors)
	}

	return consortiumData, nil
}

// GetStakeholder returns the stakeholder config file fetched by the wrapped config service.
func (cs *ConfigService) GetStakeholder(url, domain string) (*models.StakeholderFileData, error) {
	return cs.config.GetStakeholder(url, domain)
}

// GetSidetreeConfig returns the sidetree config.
func (cs *ConfigService) GetSidetreeConfig(url string) (*models.SidetreeConfig, error) {
	return cs.config.GetSidetreeConfig(url)
}
