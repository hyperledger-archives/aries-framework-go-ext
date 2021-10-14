/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package lb_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/lb"
)

func TestRoundRobin(t *testing.T) {
	lbp := lb.NewRoundRobin()

	// Test with an empty set of domains
	domain, err := lbp.Choose([]string{})
	require.NoError(t, err)
	require.Empty(t, domain)

	domains := newMockDomins(10)

	lastIndexChosen := -1

	// Invoke a number of times and make sure it chooses each one consecutively
	for i := 0; i < len(domains); i++ {
		domain, err := lbp.Choose(domains)
		require.NoError(t, err)

		chosenIndex := findIndex(domains, domain)

		if lastIndexChosen >= 0 { //nolint: nestif
			if lastIndexChosen == (len(domains) - 1) {
				if chosenIndex != 0 {
					t.Fatalf("expecting chosen index to be 0 but got index %d", chosenIndex)
				}
			} else {
				if chosenIndex != lastIndexChosen+1 {
					t.Fatalf("expecting chosen index to be %d but got index %d", lastIndexChosen+1, chosenIndex)
				}
			}
		}

		lastIndexChosen = chosenIndex
	}
}

func findIndex(domains []string, domain string) int {
	for i, d := range domains {
		if domain == d {
			return i
		}
	}

	panic("domain does not exist in list of domains")
}

func newMockDomins(numDomains int) []string {
	var domains []string
	for i := 0; i < numDomains; i++ {
		domains = append(domains, fmt.Sprintf("domain_%d", i))
	}

	return domains
}
