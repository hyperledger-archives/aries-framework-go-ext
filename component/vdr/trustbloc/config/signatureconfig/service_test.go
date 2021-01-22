/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package signatureconfig

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"

	mockconfig "github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/internal/mock/config"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

func signConsortium(consortium *models.Consortium, keys ...jose.SigningKey) (*jose.JSONWebSignature, error) {
	signer, err := jose.NewMultiSigner(keys, nil)
	if err != nil {
		return nil, err
	}

	consortiumBytes, err := json.Marshal(consortium)
	if err != nil {
		return nil, err
	}

	return signer.Sign(consortiumBytes)
}

func TestConfigService_GetConsortium(t *testing.T) {
	rawPrivKey := []byte(`{
  "kty": "OKP",
  "kid": "key1",
  "d": "CSLczqR1ly2lpyBcWne9gFKnsjaKJw0dKfoSQu7lNvg",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`)

	key := jose.JSONWebKey{}
	e := key.UnmarshalJSON(rawPrivKey)
	require.NoError(t, e)

	sigKey := jose.SigningKey{Key: key.Key, Algorithm: jose.EdDSA}

	t.Run("success", func(t *testing.T) {
		rawPubKey := []byte(`{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`)

		config := models.Consortium{
			Members: []*models.StakeholderListElement{
				{PublicKey: models.PublicKey{JWK: json.RawMessage(rawPubKey)}},
			},
		}

		sig, err := signConsortium(&config, sigKey)
		require.NoError(t, err)

		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &config,
					JWS:    sig,
				}, nil
			},
		})

		_, err = cs.GetConsortium("foo", "foo")
		require.NoError(t, err)
	})

	t.Run("failure: can't parse key", func(t *testing.T) {
		rawPubKey := []byte(`[]`)

		config := models.Consortium{
			Members: []*models.StakeholderListElement{
				{PublicKey: models.PublicKey{JWK: json.RawMessage(rawPubKey)}},
			},
		}

		sig, err := signConsortium(&config, sigKey)
		require.NoError(t, err)

		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &config,
					JWS:    sig,
				}, nil
			},
		})

		_, err = cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "insufficient stakeholder endorsement")
	})

	t.Run("failure: bad key data", func(t *testing.T) {
		rawPubKey := []byte(`{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "badDataInHereHdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`)

		config := models.Consortium{
			Members: []*models.StakeholderListElement{
				{PublicKey: models.PublicKey{JWK: json.RawMessage(rawPubKey)}},
			},
		}

		sig, err := signConsortium(&config, sigKey)
		require.NoError(t, err)

		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &config,
					JWS:    sig,
				}, nil
			},
		})

		_, err = cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "insufficient stakeholder endorsement")
	})

	t.Run("failure: bad key data", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return nil, fmt.Errorf("error error")
			},
		})

		_, err := cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrapped config service")
	})

	t.Run("failure: bad key data", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{}, nil
			},
		})

		_, err := cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "consortium is nil")
	})
}

func TestConfigService_GetConsortium_MultiSig(t *testing.T) {
	rawPrivKeys := [][]byte{
		[]byte(`{
  "kty": "OKP",
  "kid": "key1",
  "d": "CSLczqR1ly2lpyBcWne9gFKnsjaKJw0dKfoSQu7lNvg",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`),
		[]byte(`{
  "kty": "OKP",
  "kid": "key1",
  "d": "-YawjZSeB9Rkdol9SHeOcT9hIvo_VuH6zM-pgtk3b10",
  "crv": "Ed25519",
  "x": "8rfXFZNHZs9GYzGbQLYDasGUAm1brAgTLI0jrD4KheU"
}`),
	}

	sigKeys := make([]jose.SigningKey, 0)

	for _, rawPrivKey := range rawPrivKeys {
		key := jose.JSONWebKey{}
		err := key.UnmarshalJSON(rawPrivKey)
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key.Key, Algorithm: jose.EdDSA}
		sigKeys = append(sigKeys, sigKey)
	}

	t.Run("success - verify all signatures", func(t *testing.T) {
		rawPubKeys := [][]byte{
			[]byte(`{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`), []byte(`{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "8rfXFZNHZs9GYzGbQLYDasGUAm1brAgTLI0jrD4KheU"
}`),
		}

		stakeholders := []*models.StakeholderListElement{}
		for _, rawPubKey := range rawPubKeys {
			stakeholders = append(stakeholders, &models.StakeholderListElement{
				PublicKey: models.PublicKey{JWK: json.RawMessage(rawPubKey)},
			})
		}

		config := models.Consortium{
			Members: stakeholders,
			Policy:  models.ConsortiumPolicy{NumQueries: 2},
		}

		sig, err := signConsortium(&config, sigKeys...)
		require.NoError(t, err)

		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &config,
					JWS:    sig,
				}, nil
			},
		})

		_, err = cs.GetConsortium("foo", "foo")
		require.NoError(t, err)
	})

	t.Run("success - one key is bad, but only one endorsement is needed", func(t *testing.T) {
		rawPubKeys := [][]byte{[]byte(`{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "ThisIsABadKey1GbQLYDasGUAm1brAgTLI0jrD4KheU"
}`), []byte(`{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`)}

		stakeholders := []*models.StakeholderListElement{}
		for _, rawPubKey := range rawPubKeys {
			stakeholders = append(stakeholders, &models.StakeholderListElement{
				PublicKey: models.PublicKey{JWK: json.RawMessage(rawPubKey)},
			})
		}

		config := models.Consortium{
			Members: stakeholders,
			Policy:  models.ConsortiumPolicy{NumQueries: 1},
		}

		sig, err := signConsortium(&config, sigKeys...)
		require.NoError(t, err)

		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &config,
					JWS:    sig,
				}, nil
			},
		})

		_, err = cs.GetConsortium("foo", "foo")
		require.NoError(t, err)
	})

	t.Run("failure - one key is bad, and both need to verify", func(t *testing.T) {
		rawPubKeys := [][]byte{[]byte(`{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "ThisIsABadKey1GbQLYDasGUAm1brAgTLI0jrD4KheU"
}`), []byte(`{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`)}

		stakeholders := []*models.StakeholderListElement{}
		for _, rawPubKey := range rawPubKeys {
			stakeholders = append(stakeholders, &models.StakeholderListElement{
				PublicKey: models.PublicKey{JWK: json.RawMessage(rawPubKey)},
			})
		}

		config := models.Consortium{
			Members: stakeholders,
			Policy:  models.ConsortiumPolicy{NumQueries: 2},
		}

		sig, err := signConsortium(&config, sigKeys...)
		require.NoError(t, err)

		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &config,
					JWS:    sig,
				}, nil
			},
		})

		_, err = cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "insufficient stakeholder endorsement")
	})
}

func TestConfigService_GetStakeholder(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetStakeholderFunc: func(u string, d string) (*models.StakeholderFileData, error) {
				return &models.StakeholderFileData{Config: &models.Stakeholder{Domain: "foo.bar"}}, nil
			},
		})

		sh, err := cs.GetStakeholder("foo", "foo")
		require.NoError(t, err)
		require.Equal(t, "foo.bar", sh.Config.Domain)
	})

	t.Run("test error", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetStakeholderFunc: func(u string, d string) (*models.StakeholderFileData, error) {
				return nil, fmt.Errorf("error error")
			},
		})

		_, err := cs.GetStakeholder("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error error")
	})
}

func TestConfigService_GetSidetreeConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(u string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			},
		})

		c, err := cs.GetSidetreeConfig("foo")
		require.NoError(t, err)
		require.Equal(t, uint(18), c.MultiHashAlgorithm)
	})

	t.Run("test error", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(u string) (*models.SidetreeConfig, error) {
				return nil, fmt.Errorf("error error")
			},
		})

		_, err := cs.GetSidetreeConfig("foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error error")
	})
}
