/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientregistry

import (
	"fmt"
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"

	vercommon "github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/common"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/versions/common"
)

type factory interface {
	Create(version string, config *common.ProtocolConfig) (protocol.Version, error)
}

// Registry implements a client version factory registry.
type Registry struct {
	factories map[string]factory
	mutex     sync.RWMutex
}

// New returns a new client version factory Registry.
func New() *Registry {
	registry := &Registry{factories: make(map[string]factory)}

	addVersions(registry)

	return registry
}

// CreateClientVersion creates a new client version using the given version and providers.
func (r *Registry) CreateClientVersion(version string, config *common.ProtocolConfig) (protocol.Version, error) {
	v, err := r.resolveFactory(version)
	if err != nil {
		return nil, err
	}

	return v.Create(version, config)
}

// Register registers a client factory for a given version.
func (r *Registry) Register(version string, factory factory) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, ok := r.factories[version]; ok {
		panic(fmt.Errorf("client version factory [%s] already registered", version))
	}

	r.factories[version] = factory
}

func (r *Registry) resolveFactory(version string) (factory, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for v, f := range r.factories {
		if vercommon.Version(v).Matches(version) {
			return f, nil
		}
	}

	return nil, fmt.Errorf("client version factory for version [%s] not found", version)
}
