/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ldcontext_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/internal/ldcontext"
)

func TestMustGetALL(t *testing.T) {
	res := ldcontext.MustGetAll()
	require.Len(t, res, 1)
	require.Equal(t, "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1", res[0].URL)
}
