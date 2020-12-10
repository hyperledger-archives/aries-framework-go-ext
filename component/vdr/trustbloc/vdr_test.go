/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package trustbloc_test

import (
	"crypto/tls"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc"
)

var _ vdr.VDR = (*VDR)(nil)

func TestNew(t *testing.T) {
	require.NotNil(t, New())

	require.NotNil(t, New(
		WithResolverURL("url"),
		WithDomain("domain"),
		WithTLSConfig(&tls.Config{ServerName: "test", MinVersion: tls.VersionTLS12}),
		WithAuthToken("token"),
		EnableSignatureVerification(true),
	))
}
