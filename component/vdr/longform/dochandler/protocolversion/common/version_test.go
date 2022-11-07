/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/common"
)

func TestCcVersion_Matches(t *testing.T) {
	v1 := common.Version("v1")
	v1_0 := common.Version("v1.0")
	v1_1 := common.Version("v1.1")
	v1_2 := common.Version("v1.2")

	require.True(t, v1.Matches("v1.0.0"))
	require.True(t, v1.Matches("v1.0.1"))
	require.True(t, v1_0.Matches("v1.0.1"))
	require.False(t, v1.Matches("v1.2.1"))
	require.True(t, v1_2.Matches("v1.2.1"))
	require.False(t, v1_1.Matches("v1.2.0"))
}

func TestCcVersion_Validate(t *testing.T) {
	v := common.Version("")
	v1 := common.Version("v1")
	v1_0 := common.Version("v1.0")
	v1_0_0 := common.Version("v1.0.0")

	require.EqualError(t, v.Validate(), "no version specified")
	require.NoError(t, v1.Validate())
	require.NoError(t, v1_0.Validate())
	require.EqualError(t, v1_0_0.Validate(), "version must only have a major and optional minor part (e.g. v1 or v1.1)")
}
