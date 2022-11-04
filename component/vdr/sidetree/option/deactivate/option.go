/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package deactivate implements sidetree deactivate did option
package deactivate

import (
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/api"
)

// Opts deactivate did opts.
type Opts struct {
	GetEndpoints        func() ([]string, error)
	Signer              api.Signer
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

// WithSigner set signer.
func WithSigner(signer api.Signer) Option {
	return func(opts *Opts) {
		opts.Signer = signer
	}
}

// WithOperationCommitment sets last operation commitment.
func WithOperationCommitment(operationCommitment string) Option {
	return func(opts *Opts) {
		opts.OperationCommitment = operationCommitment
	}
}
