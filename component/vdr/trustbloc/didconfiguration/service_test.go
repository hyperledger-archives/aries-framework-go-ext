/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package didconfiguration

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

func TestService_VerifyStakeholder(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		var confFile []byte

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, string(confFile))
		}))
		defer serv.Close()

		conf, err := CreateDIDConfiguration(serv.URL, "did:example:123abc", 0, &sigKey)
		require.NoError(t, err)

		confFile, err = json.Marshal(conf)
		require.NoError(t, err)

		doc, err := did.ParseDocument([]byte(testDoc))
		require.NoError(t, err)

		s := NewService()

		err = s.VerifyStakeholder(serv.URL, doc)
		require.NoError(t, err)
	})

	t.Run("failure - server down", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer serv.Close()

		s := NewService()

		err := s.VerifyStakeholder(serv.URL, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "did-configuration request failed")
	})

	t.Run("failure - bad config file", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "%^$&^Bad data")
		}))
		defer serv.Close()

		s := NewService()

		err := s.VerifyStakeholder(serv.URL, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse did configuration")
	})

	t.Run("failure - configuration fails verification", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		var confFile []byte

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, string(confFile))
		}))
		defer serv.Close()

		conf, err := CreateDIDConfiguration("wrong.url", "did:example:123abc", 0, &sigKey)
		require.NoError(t, err)

		confFile, err = json.Marshal(conf)
		require.NoError(t, err)

		doc, err := did.ParseDocument([]byte(testDoc))
		require.NoError(t, err)

		s := NewService()

		err = s.VerifyStakeholder(serv.URL, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "did configuration invalid")
	})
}

func TestOpts(t *testing.T) {
	t.Run("test opts", func(t *testing.T) {
		// test WithTLSConfig
		var opts []Option
		opts = append(opts, WithTLSConfig(&tls.Config{ServerName: "test", MinVersion: tls.VersionTLS12}))

		s := &Service{}

		// Apply options
		for _, opt := range opts {
			opt(s)
		}

		require.Equal(t, "test", s.tlsConfig.ServerName)
	})
}
