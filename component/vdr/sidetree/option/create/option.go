/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package create implements sidetree create did option
package create

import (
	"crypto"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
)

// Opts create did opts.
type Opts struct {
	PublicKeys         []doc.PublicKey
	Services           []docdid.Service
	AlsoKnownAs        []string
	GetEndpoints       func() ([]string, error)
	RecoveryPublicKey  crypto.PublicKey
	UpdatePublicKey    crypto.PublicKey
	SigningKey         crypto.PrivateKey
	SigningKeyID       string
	MultiHashAlgorithm uint
	AnchorOrigin       string
}

// Option is a create DID option.
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

// WithRecoveryPublicKey set recovery public key.
func WithRecoveryPublicKey(recoveryPublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.RecoveryPublicKey = recoveryPublicKey
	}
}

// WithUpdatePublicKey set update public key.
func WithUpdatePublicKey(updatePublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.UpdatePublicKey = updatePublicKey
	}
}

// WithMultiHashAlgorithm set multi hash algorithm for sidetree request.
func WithMultiHashAlgorithm(multiHashAlgorithm uint) Option {
	return func(opts *Opts) {
		opts.MultiHashAlgorithm = multiHashAlgorithm
	}
}

// WithAnchorOrigin set anchor origin for sidetree request.
func WithAnchorOrigin(anchorOrigin string) Option {
	return func(opts *Opts) {
		opts.AnchorOrigin = anchorOrigin
	}
}
