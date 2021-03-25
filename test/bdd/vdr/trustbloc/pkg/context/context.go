/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package context implements context
//
package context

import (
	"crypto/tls"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariescontext "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
)

const masterKeyURI = "local-lock://custom/master/key/"

// BDDContext is a global context shared between different test suites in bddtests.
type BDDContext struct {
	TLSConfig *tls.Config
	LocalKMS  kms.KeyManager
}

// NewBDDContext create new BDDContext.
func NewBDDContext(caCertPaths ...string) (*BDDContext, error) {
	rootCAs, err := tlsutils.GetCertPool(false, caCertPaths)
	if err != nil {
		return nil, err
	}

	km, err := createKMS(mem.NewProvider())
	if err != nil {
		return nil, err
	}

	return &BDDContext{TLSConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}, LocalKMS: km}, nil
}

func createKMS(s storage.Provider) (kms.KeyManager, error) {
	sl := &noop.NoLock{} // for bdd tests, using no lock

	kmsProvider, err := ariescontext.New(ariescontext.WithStorageProvider(s), ariescontext.WithSecretLock(sl))
	if err != nil {
		return nil, fmt.Errorf("failed to create new kms provider: %w", err)
	}

	km, err := localkms.New(masterKeyURI, kmsProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create new kms: %w", err)
	}

	return km, nil
}
