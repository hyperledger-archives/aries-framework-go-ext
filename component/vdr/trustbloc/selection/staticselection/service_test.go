/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package staticselection

import (
	"testing"

	"github.com/stretchr/testify/require"

	mockconfig "github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/internal/mock/config"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

func intersectionSize(list, candidates []*models.Endpoint) int {
	set := map[*models.Endpoint]struct{}{}

	for _, ep := range list {
		set[ep] = struct{}{}
	}

	count := 0

	for _, ep := range candidates {
		if _, present := set[ep]; present {
			count++
		}
	}

	return count
}

func TestSelectionService_SelectEndpoints(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(s string, s2 string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &models.Consortium{
						Policy: models.ConsortiumPolicy{NumQueries: 0},
					},
				}, nil
			},
		})

		endpoints, err := s.SelectEndpoints("domain", []*models.Endpoint{{URL: "url"}})
		require.NoError(t, err)
		require.Len(t, endpoints, 1)
		require.Equal(t, "url", endpoints[0].URL)
	})

	t.Run("test success - repeat domains", func(t *testing.T) {
		endpoints1 := []*models.Endpoint{
			{URL: "url.1", Domain: "1"},
			{URL: "url.2", Domain: "1"},
		}

		endpoints2 := []*models.Endpoint{
			{URL: "url.3", Domain: "2"},
			{URL: "url.4", Domain: "2"},
		}

		s := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(s string, s2 string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &models.Consortium{},
				}, nil
			},
		})

		selectedEndpoints, err := s.SelectEndpoints("domain", append(endpoints1, endpoints2...))
		require.NoError(t, err)
		require.Len(t, selectedEndpoints, 2)
		require.Equal(t, 1, intersectionSize(selectedEndpoints, endpoints1))
		require.Equal(t, 1, intersectionSize(selectedEndpoints, endpoints2))
	})

	t.Run("test success - M of N", func(t *testing.T) {
		s := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(s string, s2 string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &models.Consortium{
						Policy: models.ConsortiumPolicy{NumQueries: 2},
					},
				}, nil
			},
		})

		endpoints := []*models.Endpoint{
			{URL: "url.1", Domain: "1"},
			{URL: "url.2", Domain: "2"},
			{URL: "url.3", Domain: "3"},
			{URL: "url.4", Domain: "4"},
		}

		selectedEndpoints, err := s.SelectEndpoints("domain", endpoints)

		require.NoError(t, err)
		require.Len(t, selectedEndpoints, 2)
		require.Equal(t, 2, intersectionSize(selectedEndpoints, endpoints))
	})
}
