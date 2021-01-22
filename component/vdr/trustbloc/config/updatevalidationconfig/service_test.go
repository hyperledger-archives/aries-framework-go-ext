/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package updatevalidationconfig

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

func TestConfigService_AddGenesisFile(t *testing.T) {
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
		cs := NewService(nil)

		genesis, err := signConsortium(&models.Consortium{Domain: "foo"}, sigKey)
		require.NoError(t, err)

		err = cs.AddGenesisFile("foo", "foo", []byte(genesis.FullSerialize()))
		require.NoError(t, err)
	})

	t.Run("failure - genesis file is corrupt", func(t *testing.T) {
		cs := NewService(nil)

		err := cs.AddGenesisFile("foo", "foo", []byte("whoops}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "genesis file for url")
	})
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

	t.Run("success - file retrieved is same as genesis", func(t *testing.T) {
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
			Domain: "foo",
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

		err = cs.AddGenesisFile("foo", "foo", []byte(sig.FullSerialize()))
		require.NoError(t, err)

		res, err := cs.GetConsortium("foo", "foo")
		require.NoError(t, err)
		require.Equal(t, "foo", res.Config.Domain)
	})

	t.Run("success - genesis file endorses derived file", func(t *testing.T) {
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

		genesis := &models.Consortium{
			Members: []*models.StakeholderListElement{
				{PublicKey: models.PublicKey{JWK: json.RawMessage(rawPubKey)}},
			},
			Domain: "beep",
		}

		sig2, err := signConsortium(genesis, sigKey)
		require.NoError(t, err)

		err = cs.AddGenesisFile("foo", "foo", []byte(sig2.FullSerialize()))
		require.NoError(t, err)

		_, err = cs.GetConsortium("foo", "foo")
		require.NoError(t, err)
	})

	t.Run("failure - no genesis saved", func(t *testing.T) {
		cs := NewService(nil)

		_, err := cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing from cache")
	})

	t.Run("failure - nil genesis saved", func(t *testing.T) {
		cs := NewService(nil)

		cs.consortia[stringPair{"foo", "foo"}] = nil

		_, err := cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing from cache")
	})

	t.Run("failure - genesis has nil consortium", func(t *testing.T) {
		cs := NewService(nil)

		cs.consortia[stringPair{"foo", "foo"}] = &models.ConsortiumFileData{}

		_, err := cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "consortium is nil")
	})

	t.Run("failure - failed to fetch config", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(url string, domain string) (*models.ConsortiumFileData, error) {
				return nil, fmt.Errorf("config error")
			},
		})

		cs.consortia[stringPair{"foo", "foo"}] = &models.ConsortiumFileData{
			Config: &models.Consortium{},
		}

		_, err := cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "config error")
	})

	t.Run("failure - signature failed to verify", func(t *testing.T) {
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

		genesis := &models.Consortium{
			Members: []*models.StakeholderListElement{
				{PublicKey: models.PublicKey{JWK: json.RawMessage(rawPubKey)}},
			},
			Domain: "beep",
		}

		sig2, err := signConsortium(genesis, sigKey)
		require.NoError(t, err)

		err = cs.AddGenesisFile("foo", "foo", []byte(sig2.FullSerialize()))
		require.NoError(t, err)

		_, err = cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), " signature does not verify")
	})

	t.Run("failure - derived file isn't signed by a key in genesis file", func(t *testing.T) {
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

		priv2 := []byte(`{
  "kty": "OKP",
  "kid": "key1",
  "d": "-YawjZSeB9Rkdol9SHeOcT9hIvo_VuH6zM-pgtk3b10",
  "crv": "Ed25519",
  "x": "8rfXFZNHZs9GYzGbQLYDasGUAm1brAgTLI0jrD4KheU"
}`)

		key2 := jose.JSONWebKey{}
		err := key2.UnmarshalJSON(priv2)
		require.NoError(t, err)

		sigKey2 := jose.SigningKey{Key: key2.Key, Algorithm: jose.EdDSA}

		sig, err := signConsortium(&config, sigKey2)
		require.NoError(t, err)

		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{
					Config: &config,
					JWS:    sig,
				}, nil
			},
		})

		genesis := &models.Consortium{
			Members: []*models.StakeholderListElement{
				{PublicKey: models.PublicKey{JWK: json.RawMessage(rawPubKey)}},
			},
			Domain: "beep",
		}

		sig2, err := signConsortium(genesis, sigKey)
		require.NoError(t, err)

		err = cs.AddGenesisFile("foo", "foo", []byte(sig2.FullSerialize()))
		require.NoError(t, err)

		_, err = cs.GetConsortium("foo", "foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), " signature does not verify")
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

	t.Run("success", func(t *testing.T) {
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

		sc, err := cs.GetSidetreeConfig("foo")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error error")
		require.Nil(t, sc)
	})
}
