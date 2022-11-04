/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package update implements sidetree update did option
package update

import (
	"crypto"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/api"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
)

// Option is a update DID option.
type Option func(opts *Opts)

// Opts update did opts.
type Opts struct {
	AddPublicKeys       []doc.PublicKey
	AddServices         []docdid.Service
	AddAlsoKnownAs      []string
	RemovePublicKeys    []string
	RemoveServices      []string
	RemoveAlsoKnownAs   []string
	GetEndpoints        func() ([]string, error)
	NextUpdatePublicKey crypto.PublicKey
	Signer              api.Signer
	OperationCommitment string
	MultiHashAlgorithm  uint
}

// WithAddPublicKey add DID public key.
func WithAddPublicKey(publicKey *doc.PublicKey) Option {
	return func(opts *Opts) {
		opts.AddPublicKeys = append(opts.AddPublicKeys, *publicKey)
	}
}

// WithAddService set services to be added.
func WithAddService(service *docdid.Service) Option {
	return func(opts *Opts) {
		opts.AddServices = append(opts.AddServices, *service)
	}
}

// WithAddAlsoKnownAs adds also known as.
func WithAddAlsoKnownAs(uri string) Option {
	return func(opts *Opts) {
		opts.AddAlsoKnownAs = append(opts.AddAlsoKnownAs, uri)
	}
}

// WithRemoveAlsoKnownAs removes also known as.
func WithRemoveAlsoKnownAs(uri string) Option {
	return func(opts *Opts) {
		opts.RemoveAlsoKnownAs = append(opts.RemoveAlsoKnownAs, uri)
	}
}

// WithRemovePublicKey set remove public key id.
func WithRemovePublicKey(publicKeyID string) Option {
	return func(opts *Opts) {
		opts.RemovePublicKeys = append(opts.RemovePublicKeys, publicKeyID)
	}
}

// WithSigner set signer.
func WithSigner(signer api.Signer) Option {
	return func(opts *Opts) {
		opts.Signer = signer
	}
}

// WithRemoveService set remove service id.
func WithRemoveService(serviceID string) Option {
	return func(opts *Opts) {
		opts.RemoveServices = append(opts.RemoveServices, serviceID)
	}
}

// WithNextUpdatePublicKey set next update public key.
func WithNextUpdatePublicKey(nextUpdatePublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.NextUpdatePublicKey = nextUpdatePublicKey
	}
}

// WithSidetreeEndpoint get sidetree endpoints.
func WithSidetreeEndpoint(getEndpoints func() ([]string, error)) Option {
	return func(opts *Opts) {
		opts.GetEndpoints = getEndpoints
	}
}

// WithOperationCommitment sets last operation commitment.
func WithOperationCommitment(operationCommitment string) Option {
	return func(opts *Opts) {
		opts.OperationCommitment = operationCommitment
	}
}

// WithMultiHashAlgorithm set multi hash algorithm for sidetree request.
func WithMultiHashAlgorithm(multiHashAlgorithm uint) Option {
	return func(opts *Opts) {
		opts.MultiHashAlgorithm = multiHashAlgorithm
	}
}
