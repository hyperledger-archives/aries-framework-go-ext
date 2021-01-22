/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

// DIDConfiguration asserts DID ownership over web domains using domain linkage assertions.
// Implements https://identity.foundation/specs/did-configuration/
type DIDConfiguration struct {
	Entries []DomainLinkageAssertion `json:"entries"`
}

// DomainLinkageAssertion asserts a DID's ownership over a domain.
type DomainLinkageAssertion struct {
	DID string `json:"did,omitempty"`
	JWT string `json:"jwt,omitempty"`
}

// DomainLinkageAssertionClaims holds the JWT claims of a Domain Linkage Assertion.
type DomainLinkageAssertionClaims struct {
	ISS    string `json:"iss"`
	Domain string `json:"domain"`
	Exp    int64  `json:"exp,omitempty"`
}
