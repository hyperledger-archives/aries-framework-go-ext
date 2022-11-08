/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package lb implement load balancer
package lb

import (
	"github.com/hyperledger/aries-framework-go/pkg/common/log"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/util/concurrent/rollingcounter"
)

var logger = log.New("aries-framework-ext/vdr/orb") //nolint: gochecknoglobals

// RoundRobin implements a round-robin load-balance policy.
type RoundRobin struct {
	counter *rollingcounter.Counter
}

// NewRoundRobin returns a new RoundRobin load-balance policy.
func NewRoundRobin() *RoundRobin {
	return &RoundRobin{
		counter: rollingcounter.New(),
	}
}

// Choose chooses from the list of domains in round-robin fashion.
func (rb *RoundRobin) Choose(domains []string) (string, error) {
	if len(domains) == 0 {
		logger.Warnf("No domains to choose from!")

		return "", nil
	}

	return domains[rb.counter.Next(len(domains))], nil
}
