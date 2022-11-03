/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/versions/common"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/versions/v1_0/client"
)

func TestFactory_Create(t *testing.T) {
	f := client.New()
	require.NotNil(t, f)

	t.Run("success", func(t *testing.T) {
		pv, err := f.Create("1.0", &common.ProtocolConfig{})
		require.NoError(t, err)
		require.NotNil(t, pv)
	})
}
