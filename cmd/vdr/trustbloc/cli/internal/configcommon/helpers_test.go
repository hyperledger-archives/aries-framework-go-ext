/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package configcommon

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

const (
	configData = `{
  "consortiumData": {
    "domain": "consortium.net",
    "genesisBlock": "6e2f978e16b59df1d6a1dfbacb92e7d3eddeb8b3fd825e573138b3fd77d77264",
    "policy": {
      "cache": {
        "maxAge": 2419200
      },
      "numQueries": 2,
      "historyHash": "SHA256"
    }
  },
  "membersData": [
    {
      "domain": "stakeholder.one",
      "policy": {"cache": {"maxAge": 604800}},
      "endpoints": [
        "http://endpoints.stakeholder.one/peer1/",
        "http://endpoints.stakeholder.one/peer2/"
      ],
      "privateKeyJwkPath": "%s"
    }
  ]
}`

	jwkData = `{
	"kty": "OKP",
	"kid": "key1",
	"d": "CSLczqR1ly2lpyBcWne9gFKnsjaKJw0dKfoSQu7lNvg",
	"crv": "Ed25519",
	"x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`
)

func TestWriteConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		filesData := map[string][]byte{
			"abc": []byte("data data"),
			"def": []byte("data2 data2"),
		}

		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.RemoveAll(dir)) }()

		require.NoError(t, WriteConfig(dir, filesData))

		_, err = os.Stat(dir + "/did-trustbloc/abc.json")
		require.False(t, os.IsNotExist(err))

		_, err = os.Stat(dir + "/did-trustbloc/def.json")
		require.False(t, os.IsNotExist(err))
	})

	t.Run("fail", func(t *testing.T) {
		filesData := map[string][]byte{
			"abc": []byte("data data"),
			"def": []byte("data2 data2"),
		}

		err := WriteConfig("\000?", filesData)
		require.Error(t, err)
		require.Contains(t, err.Error(), "mkdir")
	})
}

func TestGetConfig(t *testing.T) {
	t.Run("fail: missing arg", func(t *testing.T) {
		_, err := GetConfig(&cobra.Command{})
		require.Error(t, err)
	})

	t.Run("fail: can't read config file", func(t *testing.T) {
		os.Clearenv()
		require.NoError(t, os.Setenv(ConfigFileEnvKey, "bad.file"))

		conf, err := GetConfig(&cobra.Command{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read")
		require.Nil(t, conf)
	})

	t.Run("fail: config file not json", func(t *testing.T) {
		os.Clearenv()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString("aooga")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		require.NoError(t, os.Setenv(ConfigFileEnvKey, file.Name()))

		conf, err := GetConfig(&cobra.Command{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed unmarshal")
		require.Nil(t, conf)
	})

	t.Run("fail: can't read member key file", func(t *testing.T) {
		os.Clearenv()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(configData, "bad.file"))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		require.NoError(t, os.Setenv(ConfigFileEnvKey, file.Name()))

		conf, err := GetConfig(&cobra.Command{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read jwk file")
		require.Nil(t, conf)
	})

	t.Run("fail: corrupted member key file", func(t *testing.T) {
		os.Clearenv()

		jwkFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(jwkFile.Name())) }()

		_, err = jwkFile.WriteString("bad data bad data")
		require.NoError(t, err)

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(configData, jwkFile.Name()))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		require.NoError(t, os.Setenv(ConfigFileEnvKey, file.Name()))

		conf, err := GetConfig(&cobra.Command{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal to jwk")
		require.Nil(t, conf)
	})

	t.Run("test get config from temp file", func(t *testing.T) {
		os.Clearenv()

		jwkFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(jwkFile.Name())) }()

		_, err = jwkFile.WriteString(jwkData)
		require.NoError(t, err)

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(configData, jwkFile.Name()))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		require.NoError(t, os.Setenv(ConfigFileEnvKey, file.Name()))

		c, err := GetConfig(&cobra.Command{})
		require.NoError(t, err)

		require.Equal(t, "consortium.net", c.ConsortiumData.Domain)
		require.Len(t, c.MembersData, 1)

		member := c.MembersData[0]
		require.NotNil(t, member)
		require.Equal(t, "stakeholder.one", member.Domain)
	})
}

func getKey(t *testing.T, data string) jose.JSONWebKey {
	key := jose.JSONWebKey{}

	err := key.UnmarshalJSON([]byte(data))
	require.NoError(t, err)

	return key
}

func TestSignConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		priv := getKey(t, jwkData)
		pub := priv.Public()

		data := []byte(configData)

		sigString, err := SignConfig(data, []jose.SigningKey{{Key: priv.Key, Algorithm: jose.EdDSA}})
		require.NoError(t, err)

		sig, err := jose.ParseSigned(sigString)
		require.NoError(t, err)

		require.Equal(t, data, sig.UnsafePayloadWithoutVerification())

		_, _, out, err := sig.VerifyMulti(pub)
		require.NoError(t, err)
		require.Equal(t, data, out)
	})

	t.Run("failure - bad key", func(t *testing.T) {
		sig, err := SignConfig([]byte("data data data"), []jose.SigningKey{{}})
		require.Error(t, err)
		require.Equal(t, "", sig)
	})
}
