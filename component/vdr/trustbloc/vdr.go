/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package trustbloc implements trustbloc DID method support.
//
package trustbloc

import (
	"crypto/tls"
	"unsafe"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
)

// VDR describes trustbloc instance.
type VDR struct{ *trustbloc.VDRI }

// New creates new trustbloc vdr.
func New(opts ...Option) *VDR {
	return &VDR{VDRI: trustbloc.New(*(*[]trustbloc.Option)(unsafe.Pointer(&opts))...)} // nolint: gosec
}

// Option configures the bloc vdri.
type Option trustbloc.Option

// WithResolverURL option is setting resolver url.
func WithResolverURL(resolverURL string) Option {
	return Option(trustbloc.WithResolverURL(resolverURL))
}

// WithDomain option is setting domain.
func WithDomain(domain string) Option {
	return Option(trustbloc.WithDomain(domain))
}

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return Option(trustbloc.WithTLSConfig(tlsConfig))
}

// WithAuthToken add auth token.
func WithAuthToken(authToken string) Option {
	return Option(trustbloc.WithAuthToken(authToken))
}

// EnableSignatureVerification enables signature verification.
func EnableSignatureVerification(enable bool) Option {
	return Option(trustbloc.EnableSignatureVerification(enable))
}
