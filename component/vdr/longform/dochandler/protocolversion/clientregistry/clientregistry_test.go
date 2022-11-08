/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientregistry_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/clientregistry"
	crmocks "github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/clientregistry/mocks"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/versions/common"
)

//go:generate counterfeiter -o ./mocks/clientfactory.gen.go --fake-name ClientFactory . factory

func TestRegistry(t *testing.T) {
	const version = "0.1"

	f := &crmocks.ClientFactory{}
	f.CreateReturns(&coremocks.ProtocolVersion{}, nil)

	r := clientregistry.New()

	require.NotPanics(t, func() { r.Register(version, f) })
	require.PanicsWithError(t, "client version factory [0.1] already registered", func() { r.Register(version, f) })

	pv, err := r.CreateClientVersion(version, &common.ProtocolConfig{})
	require.NoError(t, err)
	require.NotNil(t, pv)

	pv, err = r.CreateClientVersion("99", &common.ProtocolConfig{})
	require.EqualError(t, err, "client version factory for version [99] not found")
	require.Nil(t, pv)
}
