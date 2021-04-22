/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package staticdiscovery

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/config/httpconfig"
	mockmodels "github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/internal/mock/models"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

func TestDiscoveryService_GetEndpoints(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		shFile1, err := mockmodels.DummyStakeholderJSON("bar.baz", []string{
			"https://bar.baz/webapi/123456",
			"https://bar.baz/webapi/654321",
		})
		require.NoError(t, err)

		stakeholderServ1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, shFile1)
		}))
		defer stakeholderServ1.Close()

		shFile2, err := mockmodels.DummyStakeholderJSON("baz.qux", []string{
			"https://baz.qux/iyoubhlkn/",
			"https://baz.foo/ukjhjtfyw/",
		})
		require.NoError(t, err)

		stakeholderServ2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, shFile2)
		}))
		defer stakeholderServ2.Close()

		consortiumData, err := mockmodels.DummyConsortiumJSON("foo.bar", []*models.StakeholderListElement{
			{
				Domain: stakeholderServ1.URL,
			},
			{
				Domain: stakeholderServ2.URL,
			},
		})
		require.NoError(t, err)

		consortiumServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumData)
		}))
		defer stakeholderServ2.Close()

		s := NewService(httpconfig.NewService(httpconfig.WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})))
		endpoints, err := s.GetEndpoints(consortiumServ.URL)
		require.NoError(t, err)
		require.Len(t, endpoints, 4)
	})

	t.Run("failure: stakeholder server failure", func(t *testing.T) {
		stakeholderServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer stakeholderServ.Close()

		consortiumFile, err := mockmodels.DummyConsortiumJSON("foo.bar", []*models.StakeholderListElement{
			{
				Domain: stakeholderServ.URL,
			},
		})
		require.NoError(t, err)

		consortiumServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer consortiumServer.Close()

		s := NewService(httpconfig.NewService(httpconfig.WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})))
		_, err = s.GetEndpoints(consortiumServer.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "stakeholder config request failed")
	})
}
