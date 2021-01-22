/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package staticselection implement staticselection
//
package staticselection

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

type config interface {
	GetConsortium(url, domain string) (*models.ConsortiumFileData, error)
	GetStakeholder(url, domain string) (*models.StakeholderFileData, error)
}

// SelectionService implements a static selection service.
type SelectionService struct {
	config config
}

// NewService return static selection service.
func NewService(config config) *SelectionService {
	return &SelectionService{config: config}
}

// SelectEndpoints select a random endpoint for each of N random stakeholders in a consortium
// Where N is the numQueries parameter in the consortium's policy configuration.
func (ds *SelectionService) SelectEndpoints(consortiumDomain string, endpoints []*models.Endpoint) ([]*models.Endpoint, error) { // nolint: lll
	consortiumData, err := ds.config.GetConsortium(consortiumDomain, consortiumDomain)
	if err != nil {
		return nil, fmt.Errorf("getting consortium: %w", err)
	}

	var out []*models.Endpoint

	// map from each domain to its endpoints
	domains := map[string][]*models.Endpoint{}

	for _, ep := range endpoints {
		domains[ep.Domain] = append(domains[ep.Domain], ep)
	}

	// list of domains
	d := make([]string, 0)

	for domain := range domains {
		d = append(d, domain)
	}

	consortium := consortiumData.Config

	n := 0
	if consortium != nil {
		n = consortium.Policy.NumQueries
	}

	// if ds.numStakeholders is 0, then we use all stakeholders
	if n == 0 {
		n = len(d)
	}

	perm := mathrand.Perm(len(d))

	for i := 0; i < n && i < len(d); i++ {
		list := domains[d[perm[i]]]

		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
		if err != nil {
			return nil, err
		}

		out = append(out, list[n.Uint64()])
	}

	return out, nil
}
