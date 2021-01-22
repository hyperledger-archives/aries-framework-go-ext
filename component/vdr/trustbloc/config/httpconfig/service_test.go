/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package httpconfig

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	mockmodels "github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/internal/mock/models"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

func TestConfigService_GetConsortium(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		consortium := mockmodels.DummyConsortium("foo.bar", []*models.StakeholderListElement{
			{
				Domain: "bar.baz",
			},
			{
				Domain: "baz.qux",
			},
		})

		consortiumFile, err := mockmodels.WrapConsortium(consortium)
		require.NoError(t, err)

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer serv.Close()

		cs := NewService()

		conf, err := cs.GetConsortium(serv.URL, "foo.bar")
		require.NoError(t, err)

		require.Equal(t, "foo.bar", conf.Config.Domain)
	})

	t.Run("failure: can't reach server", func(t *testing.T) {
		cs := NewService()

		_, err := cs.GetConsortium("https://0.0.0.0:0", "foo.bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection refused")
	})

	t.Run("failure: bad response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		cs := NewService()

		_, err := cs.GetConsortium(serv.URL, "foo.bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "consortium config request failed")
	})

	t.Run("failure: empty response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer serv.Close()

		cs := NewService()

		_, err := cs.GetConsortium(serv.URL, "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "consortium config data should be a JWS")
	})
}

func TestConfigService_GetSidetreeConfig(t *testing.T) {
	t.Run("test get default values", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer serv.Close()

		cs := NewService(WithAuthToken("tk1"))

		c, err := cs.GetSidetreeConfig(serv.URL)
		require.NoError(t, err)
		require.Equal(t, uint(sha2_256), c.MultiHashAlgorithm)
	})

	t.Run("success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := json.Marshal(models.SidetreeConfig{MultiHashAlgorithm: 10})
			require.NoError(t, err)

			fmt.Fprint(w, string(bytes))
		}))
		defer serv.Close()

		cs := NewService(WithAuthToken("tk1"))

		c, err := cs.GetSidetreeConfig(serv.URL)
		require.NoError(t, err)
		require.Equal(t, uint(10), c.MultiHashAlgorithm)
	})

	t.Run("test failed to unmarshal response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "{{")
		}))
		defer serv.Close()

		cs := NewService(WithAuthToken("tk1"))

		c, err := cs.GetSidetreeConfig(serv.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, c)
	})
}

func TestConfigService_GetStakeholder(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		stakeholder := mockmodels.DummyStakeholder("foo.bar", []string{
			"endpoint.website/go/here/",
			"endpoint.website/here/too/",
		})

		stakeholderFile, err := mockmodels.WrapStakeholder(stakeholder)
		require.NoError(t, err)

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, stakeholderFile)
		}))
		defer serv.Close()

		cs := NewService()

		conf, err := cs.GetStakeholder(serv.URL, "foo.bar")
		require.NoError(t, err)

		require.Equal(t, "foo.bar", conf.Config.Domain)
	})

	t.Run("failure: can't reach server", func(t *testing.T) {
		cs := NewService()

		_, err := cs.GetStakeholder("https://0.0.0.0:0", "foo.bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection refused")
	})

	t.Run("failure: bad response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		cs := NewService()

		_, err := cs.GetStakeholder(serv.URL, "foo.bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "stakeholder config request failed")
	})

	t.Run("failure: empty response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer serv.Close()

		cs := NewService()

		_, err := cs.GetStakeholder(serv.URL, "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "stakeholder config data should be a JWS")
	})
}

func Test_configURL(t *testing.T) {
	tests := [][2]string{ // first element is the test value, second is the correct value
		{
			configURL("http://foo.example.com", "foo.example.com"),
			"http://foo.example.com/.well-known/did-trustbloc/foo.example.com.json",
		},
		{ // adds http:// to the front of a domain
			configURL("foo.example.com", "foo.example.com"),
			"https://foo.example.com/.well-known/did-trustbloc/foo.example.com.json",
		},
		{ // doesn't work with full URLs in the domain field
			configURL("foo.example.com", "http://foo.example.com"),
			"https://foo.example.com/.well-known/did-trustbloc/http://foo.example.com.json",
		},
		{
			configURL("http://foo.example.com", "bar.baz.qux"),
			"http://foo.example.com/.well-known/did-trustbloc/bar.baz.qux.json",
		},
		{
			configURL("a", "b"),
			"https://a/.well-known/did-trustbloc/b.json",
		},
		{ // doesn't recognize urls that aren't http:// or https://
			configURL("ws:abcdefg", "hijklmn"),
			"https://ws:abcdefg/.well-known/did-trustbloc/hijklmn.json",
		},
		{ // doesn't work well with malformed urls
			configURL("http:/abcdefg", "hijklmn"),
			"https://http:/abcdefg/.well-known/did-trustbloc/hijklmn.json",
		},
	}

	for _, test := range tests {
		require.Equal(t, test[1], test[0])
	}
}

func TestOpts(t *testing.T) {
	t.Run("test opts", func(t *testing.T) {
		// test WithTLSConfig
		var opts []Option
		opts = append(opts, WithTLSConfig(&tls.Config{ServerName: "test", MinVersion: tls.VersionTLS12}))

		cs := &ConfigService{}

		// Apply options
		for _, opt := range opts {
			opt(cs)
		}

		require.Equal(t, "test", cs.tlsConfig.ServerName)
	})
}
