/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nsprovider_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocol/nsprovider"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocol/verprovider"
)

const ns = "did:ion"

//go:generate counterfeiter -o ./../mocks/clientversionprovider.gen.go --fake-name ClientVersionProvider . ClientVersionProvider

func TestNew(t *testing.T) {
	p := nsprovider.New()
	require.NotNil(t, p)
}

func TestClientProvider_ForNamespace(t *testing.T) {
	v1_0 := &coremocks.ProtocolVersion{}
	v1_0.ProtocolReturns(protocol.Protocol{
		GenesisTime:       0,
		MaxOperationCount: 10,
	})

	versions := []protocol.Version{v1_0}

	p := nsprovider.New()
	require.NotNil(t, p)

	verProvider, err := verprovider.New(versions)
	require.NoError(t, err)

	p.Add(ns, verProvider)

	t.Run("success", func(t *testing.T) {
		vp, err := p.ForNamespace(ns)
		require.NoError(t, err)
		require.NotNil(t, vp)

		cur, err := vp.Current()
		require.NoError(t, err)
		require.Equal(t, uint(10), cur.Protocol().MaxOperationCount)
	})

	t.Run("error - client versions not found for namespace", func(t *testing.T) {
		vp, err := p.ForNamespace("invalid")
		require.Error(t, err)
		require.Nil(t, vp)
		require.Contains(t, err.Error(), "client version(s) not defined for namespace: invalid")
	})
}
