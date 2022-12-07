/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwk_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/jwk"
)

func TestCreate(t *testing.T) {
	t.Run("test create", func(t *testing.T) {
		v := jwk.New()
		doc, err := v.Create(nil)
		require.Error(t, err)
		require.Nil(t, doc)
		require.Contains(t, err.Error(), "TODO")
	})
}
