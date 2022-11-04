/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package recovery implements sidetree recovery did option
package recovery

import (
	"crypto"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/api"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
)

// Opts recover did opts.
type Opts struct {
	PublicKeys            []doc.PublicKey
	Services              []docdid.Service
	AlsoKnownAs           []string
	GetEndpoints          func() ([]string, error)
	NextRecoveryPublicKey crypto.PublicKey
	NextUpdatePublicKey   crypto.PublicKey
	Signer                api.Signer
	OperationCommitment   string
	MultiHashAlgorithm    uint
	AnchorOrigin          string
}

// Option is a recover DID option.
type Option func(opts *Opts)

// WithPublicKey add DID public key.
func WithPublicKey(publicKey *doc.PublicKey) Option {
	return func(opts *Opts) {
		opts.PublicKeys = append(opts.PublicKeys, *publicKey)
	}
}

// WithService add service.
func WithService(service *docdid.Service) Option {
	return func(opts *Opts) {
		opts.Services = append(opts.Services, *service)
	}
}

// WithAlsoKnownAs adds also known as URI.
func WithAlsoKnownAs(uri string) Option {
	return func(opts *Opts) {
		opts.AlsoKnownAs = append(opts.AlsoKnownAs, uri)
	}
}

// WithSidetreeEndpoint get sidetree endpoints.
func WithSidetreeEndpoint(getEndpoints func() ([]string, error)) Option {
	return func(opts *Opts) {
		opts.GetEndpoints = getEndpoints
	}
}

// WithNextRecoveryPublicKey set next recovery public key.
func WithNextRecoveryPublicKey(nextRecoveryPublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.NextRecoveryPublicKey = nextRecoveryPublicKey
	}
}

// WithNextUpdatePublicKey set next update public key.
func WithNextUpdatePublicKey(nextUpdatePublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.NextUpdatePublicKey = nextUpdatePublicKey
	}
}

// WithSigner set signer.
func WithSigner(signer api.Signer) Option {
	return func(opts *Opts) {
		opts.Signer = signer
	}
}

// WithMultiHashAlgorithm set multi hash algorithm for sidetree request.
func WithMultiHashAlgorithm(multiHashAlgorithm uint) Option {
	return func(opts *Opts) {
		opts.MultiHashAlgorithm = multiHashAlgorithm
	}
}

// WithOperationCommitment sets last operation commitment.
func WithOperationCommitment(operationCommitment string) Option {
	return func(opts *Opts) {
		opts.OperationCommitment = operationCommitment
	}
}

// WithAnchorOrigin set anchor origin for sidetree request.
func WithAnchorOrigin(anchorOrigin string) Option {
	return func(opts *Opts) {
		opts.AnchorOrigin = anchorOrigin
	}
}
