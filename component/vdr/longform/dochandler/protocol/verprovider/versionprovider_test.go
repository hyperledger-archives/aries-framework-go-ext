/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verprovider_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/api/protocol"
	coremocks "github.com/trustbloc/sidetree-go/pkg/mocks"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocol/verprovider"
)

func TestVersionprovider_New(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		v1_0 := &coremocks.ProtocolVersion{}
		v1_0.ProtocolReturns(protocol.Protocol{
			GenesisTime:         1,
			MultihashAlgorithms: []uint{18},
			MaxOperationSize:    2000,
			MaxOperationCount:   10000,
		})

		vp, err := verprovider.New([]protocol.Version{v1_0})
		require.NotNil(t, vp)
		require.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		client, err := verprovider.New(nil)
		require.Nil(t, client)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must provide at least one client version")
	})
}

func TestClient_Current(t *testing.T) {
	v1_0 := &coremocks.ProtocolVersion{}
	v1_0.VersionReturns("1.0")
	v1_0.ProtocolReturns(protocol.Protocol{
		GenesisTime:         1,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    2000,
		MaxOperationCount:   10000,
	})

	v0_1 := &coremocks.ProtocolVersion{}
	v0_1.VersionReturns("0.1")
	v0_1.ProtocolReturns(protocol.Protocol{
		GenesisTime:         0,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    500,
		MaxOperationCount:   100,
	})

	t.Run("success - default", func(t *testing.T) {
		versions := []protocol.Version{v1_0, v0_1}

		vp, err := verprovider.New(versions)
		require.NotNil(t, vp)
		require.NoError(t, err)

		p, err := vp.Current()
		require.NoError(t, err)
		require.Equal(t, uint(10000), p.Protocol().MaxOperationCount)
	})

	t.Run("success - with current protocol version", func(t *testing.T) {
		versions := []protocol.Version{v0_1, v1_0}

		vp, err := verprovider.New(versions, verprovider.WithCurrentProtocolVersion("0.1"))
		require.NotNil(t, vp)
		require.NoError(t, err)

		p, err := vp.Current()
		require.NoError(t, err)
		require.Equal(t, uint(100), p.Protocol().MaxOperationCount)
	})
}

func TestClientVersionProvider_Get(t *testing.T) {
	v1_0 := &coremocks.ProtocolVersion{}
	v1_0.VersionReturns("1.0")
	v1_0.ProtocolReturns(protocol.Protocol{
		GenesisTime:         1,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    2000,
		MaxOperationCount:   10000,
	})

	v0_1 := &coremocks.ProtocolVersion{}
	v0_1.VersionReturns("0.1")
	v0_1.ProtocolReturns(protocol.Protocol{
		GenesisTime:         0,
		MultihashAlgorithms: []uint{18},
		MaxOperationSize:    500,
		MaxOperationCount:   100,
	})

	versions := []protocol.Version{v1_0, v0_1}

	vp, err := verprovider.New(versions)
	require.NoError(t, err)
	require.NotNil(t, vp)

	v, err := vp.Get(0)
	require.NoError(t, err)
	require.Equal(t, uint(100), v.Protocol().MaxOperationCount)
	require.Equal(t, "0.1", v.Version())

	v, err = vp.Get(1)
	require.NoError(t, err)
	require.Equal(t, uint(10000), v.Protocol().MaxOperationCount)
	require.Equal(t, "1.0", v.Version())

	v, err = vp.Get(5)
	require.Error(t, err)
	require.Nil(t, v)
	require.Equal(t, err.Error(), "client version is not defined for version genesis time: 5")
}
