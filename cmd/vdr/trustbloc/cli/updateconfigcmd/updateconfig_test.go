/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package updateconfigcmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/internal/configcommon"
)

const (
	flag = "--"

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
        "d": "-YawjZSeB9Rkdol9SHeOcT9hIvo_VuH6zM-pgtk3b10",
        "crv": "Ed25519",
        "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
      }`
)

func TestUpdateConfigCmdWithMissingArg(t *testing.T) {
	t.Run("test missing arg config file", func(t *testing.T) {
		cmd := GetUpdateConfigCmd()

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither config-file (command line flag) nor DID_METHOD_CLI_CONFIG_FILE (environment variable) have been set.",
			err.Error())
	})
}

func TestUpdateConfigCmd(t *testing.T) {
	t.Run("test wrong config file", func(t *testing.T) {
		cmd := GetUpdateConfigCmd()

		var args []string
		args = append(args, configFileArg("wrongValue")...)

		cmd.SetArgs(args)

		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read config file")
	})

	t.Run("test wrong old config file path", func(t *testing.T) {
		cmd := GetUpdateConfigCmd()

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

		require.NoError(t, os.Setenv(configcommon.ConfigFileEnvKey, file.Name()))

		require.NoError(t, os.Setenv(oldConsortiumEnvKey, "./badfile"))

		err = cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file")
	})

	t.Run("test bad key file data", func(t *testing.T) {
		cmd := GetUpdateConfigCmd()

		os.Clearenv()

		jwkFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(jwkFile.Name())) }()

		_, err = jwkFile.WriteString(`jwkData`)
		require.NoError(t, err)

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(configData, jwkFile.Name()))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		require.NoError(t, os.Setenv(configcommon.ConfigFileEnvKey, file.Name()))

		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.RemoveAll(dir)) }()

		require.NoError(t, ioutil.WriteFile(filepath.Clean(dir+"/tmpfile"), []byte("abc"), 0600))

		require.NoError(t, os.Setenv(oldConsortiumEnvKey, filepath.Clean(dir+"/tmpfile")))
		require.NoError(t, os.Setenv(outputDirectoryEnvKey, filepath.Clean(dir)))

		err = cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal")
	})

	t.Run("test command execute success", func(t *testing.T) {
		cmd := GetUpdateConfigCmd()

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

		require.NoError(t, os.Setenv(configcommon.ConfigFileEnvKey, file.Name()))

		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.RemoveAll(dir)) }()

		require.NoError(t, ioutil.WriteFile(filepath.Clean(dir+"/tmpfile"), []byte("abc"), 0600))

		require.NoError(t, os.Setenv(oldConsortiumEnvKey, filepath.Clean(dir+"/tmpfile")))
		require.NoError(t, os.Setenv(outputDirectoryEnvKey, filepath.Clean(dir)))

		err = cmd.Execute()
		require.NoError(t, err)
	})

	t.Run("test update consortium from config then move config to history dir", func(t *testing.T) {
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

		require.NoError(t, os.Setenv(configcommon.ConfigFileEnvKey, file.Name()))

		c, err := configcommon.GetConfig(&cobra.Command{})
		require.NoError(t, err)

		filesData, err := updateConsortium(&parameters{config: c}, "foobar")
		require.NoError(t, err)

		require.Equal(t, 1, len(filesData))

		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.RemoveAll(dir)) }()

		require.NoError(t, configcommon.WriteConfig(dir, filesData))

		_, err = os.Stat(dir + "/did-trustbloc/consortium.net.json")
		require.False(t, os.IsNotExist(err))

		originalFile, err := ioutil.ReadFile(filepath.Clean(dir + "/did-trustbloc/consortium.net.json"))
		require.NoError(t, err)

		hash, err := moveToHistory(dir+"/did-trustbloc/consortium.net.json", dir+"/history/")
		require.NoError(t, err)
		_, err = os.Stat(dir + "/history/" + hash + ".json")
		require.False(t, os.IsNotExist(err))

		historyFile, err := ioutil.ReadFile(filepath.Clean(dir + "/history/" + hash + ".json"))
		require.NoError(t, err)

		require.Equal(t, originalFile, historyFile)
	})
}

func configFileArg(config string) []string {
	return []string{flag + configcommon.ConfigFileFlagName, config}
}
