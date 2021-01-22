/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package verifyingconfig

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/config/httpconfig"
	mockconfig "github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/internal/mock/config"
	mockmodels "github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/internal/mock/models"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

func TestConfigService_GetConsortium(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		consortiumFile := ""

		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer cServ.Close()

		s1Serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer s1Serv.Close()

		s2Serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer s2Serv.Close()

		var err error

		consortiumFile, err = mockmodels.DummyConsortiumJSON("foo.bar", []*models.StakeholderListElement{
			{
				Domain: s1Serv.URL,
			},
			{
				Domain: s2Serv.URL,
			},
		})
		require.NoError(t, err)

		cs := NewService(httpconfig.NewService())

		conf, err := cs.GetConsortium(cServ.URL, "foo.bar")
		require.NoError(t, err)

		require.Equal(t, "foo.bar", conf.Config.Domain)
	})

	t.Run("failure - one stakeholder server disagrees", func(t *testing.T) {
		consortiumFile := ""

		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer cServ.Close()

		s1Serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer s1Serv.Close()

		wrongFile, err := mockmodels.DummyConsortiumJSON("wrong.file", nil)
		require.NoError(t, err)

		s2Serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, wrongFile)
		}))
		defer s2Serv.Close()

		consortiumFile, err = mockmodels.DummyConsortiumJSON("foo.bar", []*models.StakeholderListElement{
			{
				Domain: s1Serv.URL,
			},
			{
				Domain: s2Serv.URL,
			},
		})
		require.NoError(t, err)

		cs := NewService(httpconfig.NewService())

		_, err = cs.GetConsortium(cServ.URL, "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "endorsement")
	})

	t.Run("success - one stakeholder server disagrees, only one needs to agree", func(t *testing.T) {
		consortiumFile := ""

		cServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer cServ.Close()

		s1Serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer s1Serv.Close()

		s2Serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "foo bar")
		}))
		defer s2Serv.Close()

		var err error

		consortium := mockmodels.DummyConsortium("foo.bar", []*models.StakeholderListElement{
			{
				Domain: s1Serv.URL,
			},
			{
				Domain: s2Serv.URL,
			},
		})

		// only require one stakeholder to endorse
		consortium.Policy.NumQueries = 1

		consortiumFile, err = mockmodels.WrapConsortium(consortium)
		require.NoError(t, err)

		cs := NewService(httpconfig.NewService())

		_, err = cs.GetConsortium(cServ.URL, "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "endorsement")
	})

	t.Run("failure - errors fetching consortium", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return nil, fmt.Errorf("consortium error")
			},
		})

		_, err := cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "consortium error")

		cs = NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{}, nil
			},
		})

		_, err = cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "consortium is nil")
	})
}

func TestConfigService_GetStakeholder(t *testing.T) {
	t.Run("pass through", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetStakeholderFunc: func(s string, s2 string) (*models.StakeholderFileData, error) {
				return &models.StakeholderFileData{Config: &models.Stakeholder{Domain: "foo"}}, fmt.Errorf("foo error")
			},
		})

		conf, err := cs.GetStakeholder("foo.bar", "foo.bar")
		// verify error is passed through
		require.Error(t, err)
		require.EqualError(t, err, "foo error")

		// verify return value is passed through
		require.NotNil(t, conf)
		require.NotNil(t, conf.Config)
		require.Equal(t, conf.Config.Domain, "foo")
	})
}
