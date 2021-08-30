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
	require.Len(t, res, 2)
	require.Equal(t, "https://w3id.org/activityanchors/v1", res[0].URL)
	require.Equal(t, "https://www.w3.org/ns/activitystreams", res[1].URL)
}
