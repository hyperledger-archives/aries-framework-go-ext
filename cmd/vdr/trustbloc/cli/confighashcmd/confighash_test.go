/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package confighashcmd

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const flag = "--"

// nolint: gochecknoglobals
var configData = `{
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

func TestConfigHashCmdWithMissingArg(t *testing.T) {
	t.Run("test missing arg config file", func(t *testing.T) {
		cmd := GetConfigHashCmd()

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither config-file (command line flag) nor DID_METHOD_CLI_CONFIG_FILE (environment variable) have been set.",
			err.Error())
	})
}

func TestConfigHashCmd(t *testing.T) {
	t.Run("test wrong config file", func(t *testing.T) {
		cmd := GetConfigHashCmd()

		var args []string
		args = append(args, configFileArg("wrongValue")...)

		cmd.SetArgs(args)

		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read config file")
	})

	t.Run("test create config and write them to file", func(t *testing.T) {
		os.Clearenv()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(configData)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		cmd := GetConfigHashCmd()

		var args []string
		args = append(args, configFileArg(file.Name())...)

		cmd.SetArgs(args)

		err = cmd.Execute()
		require.NoError(t, err)
	})
}

func configFileArg(config string) []string {
	return []string{flag + configFileFlagName, config}
}
