/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigService_GetSidetreeConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cs := NewService()

		conf, err := cs.GetSidetreeConfig()
		require.NoError(t, err)

		require.Equal(t, uint(18), conf.MultiHashAlgorithm)
	})
}
