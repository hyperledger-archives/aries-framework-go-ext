/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mockmodels "github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/internal/mock/models"
	. "github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

// nolint: gochecknoglobals
var payload = `
{
	"domain": "foo.bar",
	"policy": {
		"cache": {"maxAge": 123456789}
	},
	"members": [
		{
			"domain": "bar.baz",
			"did": "did:trustbloc:foo.bar:zQ1234567890987654321"
		},
		{
			"domain": "baz.qux",
			"did": "did:trustbloc:foo.bar:zQ0987654321234567890"
		}
	],
	"previous": ""
}
`

func Test_ParseConsortium(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		jws := mockmodels.DummyJWSWrap(payload)

		cData, err := ParseConsortium([]byte(jws))
		require.NoError(t, err)

		require.Equal(t, "foo.bar", cData.Config.Domain)
		require.Equal(t, payload, string(cData.JWS.UnsafePayloadWithoutVerification()))
	})

	t.Run("failure: not valid JSON", func(t *testing.T) {
		jws := `{`

		_, err := ParseConsortium([]byte(jws))
		require.Error(t, err)
		require.Contains(t, err.Error(), "config data should be a JWS")
	})

	t.Run("failure: not a JWS", func(t *testing.T) {
		jws := `{"foo":"bar"}`

		_, err := ParseConsortium([]byte(jws))
		require.Error(t, err)
		require.Contains(t, err.Error(), "config data should be a JWS")
	})

	t.Run("failure: malformed payload", func(t *testing.T) {
		jws := mockmodels.DummyJWSWrap(`@@bad data@@`)

		_, err := ParseConsortium([]byte(jws))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})
}

func TestConsortiumFileData_CacheLifetime(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfd := ConsortiumFileData{
			Config: &Consortium{
				Policy: ConsortiumPolicy{Cache: CacheControl{MaxAge: 12345}},
			},
		}

		d, err := cfd.CacheLifetime()
		require.NoError(t, err)

		require.Equal(t, time.Duration(12345)*time.Second, d)
	})

	t.Run("failure", func(t *testing.T) {
		cfd := ConsortiumFileData{
			Config: nil,
		}

		_, err := cfd.CacheLifetime()
		require.Error(t, err)

		require.Contains(t, err.Error(), "missing config")
	})
}
