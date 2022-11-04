/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package api include interface
package api

import "github.com/trustbloc/sidetree-core-go/pkg/jws"

// Signer defines JWS Signer interface that will be used to sign required data in Sidetree request.
type Signer interface {
	// Sign signs data and returns signature value
	Sign(data []byte) ([]byte, error)

	// Headers provides required JWS protected headers. It provides information about signing key and algorithm.
	Headers() jws.Headers

	// PublicKeyJWK return public key in JWK format
	PublicKeyJWK() *jws.JWK
}
