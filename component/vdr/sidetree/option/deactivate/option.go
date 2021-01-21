/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package deactivate implements sidetree deactivate did option
//
package deactivate

import (
	"crypto"
)

// Opts deactivate did opts.
type Opts struct {
	GetEndpoints        func() ([]string, error)
	SigningKey          crypto.PrivateKey
	SigningKeyID        string
	OperationCommitment string
}

// Option is a deactivate DID option.
type Option func(opts *Opts)

// WithSidetreeEndpoint get sidetree endpoints.
func WithSidetreeEndpoint(getEndpoints func() ([]string, error)) Option {
	return func(opts *Opts) {
		opts.GetEndpoints = getEndpoints
	}
}

// WithSigningKey set signing key.
func WithSigningKey(signingKey crypto.PrivateKey) Option {
	return func(opts *Opts) {
		opts.SigningKey = signingKey
	}
}

// WithSigningKeyID set signing key id.
func WithSigningKeyID(id string) Option {
	return func(opts *Opts) {
		opts.SigningKeyID = id
	}
}

// WithOperationCommitment sets last operation commitment.
func WithOperationCommitment(operationCommitment string) Option {
	return func(opts *Opts) {
		opts.OperationCommitment = operationCommitment
	}
}
