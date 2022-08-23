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
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
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
	rootCAs, err := tlsutils.GetCertPool(true, caCertPaths)
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

	kmsStore, err := kms.NewAriesProviderWrapper(s)
	if err != nil {
		return nil, fmt.Errorf("create Aries KMS store wrapper: %w", err)
	}

	kmsProv := &kmsProvider{
		storageProvider:   kmsStore,
		secretLockService: sl,
	}

	km, err := localkms.New(masterKeyURI, kmsProv)
	if err != nil {
		return nil, fmt.Errorf("failed to create new kms: %w", err)
	}

	return km, nil
}

type kmsProvider struct {
	storageProvider   kms.Store
	secretLockService secretlock.Service
}

func (k *kmsProvider) StorageProvider() kms.Store {
	return k.storageProvider
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}
