/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createconfigcmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/internal/configcommon"
)

const (
	flag = "--"

	pkPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFoxLiiZZYCh8XOZE0MXUYIgCrwIq
ho+LGIVUXDNaduiNfpLmk5MXS5Q7WQAMgaJBRyRldIvbrNWqph4DH2gdKQ==
-----END PUBLIC KEY-----`

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

func TestRecoveryKey(t *testing.T) {
	jwkFile, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = jwkFile.WriteString(jwkData)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(jwkFile.Name())) }()

	file, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = file.WriteString(fmt.Sprintf(configData, jwkFile.Name()))
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(file.Name())) }()

	t.Run("test recovery key empty", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateConfigCmd()

		var args []string
		args = append(args, sidetreeURLArg()...)
		args = append(args, configFileArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--recoverykey) or key file (--recoverykey-file) is required")
	})

	t.Run("test both recovery key and recovery key file exist", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateConfigCmd()

		var args []string
		args = append(args, sidetreeURLArg()...)
		args = append(args, configFileArg(file.Name())...)
		args = append(args, recoveryKeyFlagNameArg("key")...)
		args = append(args, recoveryKeyFileFlagNameArg("./file")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "only one of key (--recoverykey) or key file (--recoverykey-file) may be specified")
	})

	t.Run("test recovery key wrong pem", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateConfigCmd()

		var args []string
		args = append(args, sidetreeURLArg()...)
		args = append(args, configFileArg(file.Name())...)
		args = append(args, recoveryKeyFlagNameArg("w")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key not found in PEM")
	})

	t.Run("test recovery key success", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateConfigCmd()

		pkFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = pkFile.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(pkFile.Name())) }()

		var args []string
		args = append(args, sidetreeURLArg()...)
		args = append(args, configFileArg(file.Name())...)
		args = append(args, recoveryKeyFileFlagNameArg(pkFile.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--updatekey) or key file (--updatekey-file) is required")
	})
}

func TestCreateConfigCmdWithMissingArg(t *testing.T) {
	t.Run("test missing arg sidetree url", func(t *testing.T) {
		cmd := GetCreateConfigCmd()

		err := cmd.Execute()
		require.Error(t, err)
		require.Equal(t,
			"Neither sidetree-url (command line flag) nor DID_METHOD_CLI_SIDETREE_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing arg config file", func(t *testing.T) {
		cmd := GetCreateConfigCmd()

		cmd.SetArgs(sidetreeURLArg())
		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither config-file (command line flag) nor DID_METHOD_CLI_CONFIG_FILE (environment variable) have been set.",
			err.Error())
	})
}

func TestCreateConfigCmd(t *testing.T) {
	t.Run("test wrong config file", func(t *testing.T) {
		cmd := GetCreateConfigCmd()

		var args []string
		args = append(args, sidetreeURLArg()...)
		args = append(args, configFileArg("wrongValue")...)

		cmd.SetArgs(args)

		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read config file")
	})

	t.Run("test wrong path for private key jwk", func(t *testing.T) {
		cmd := GetCreateConfigCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(configData, "notexist.json"))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, sidetreeURLArg()...)
		args = append(args, configFileArg(file.Name())...)

		cmd.SetArgs(args)

		err = cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read jwk file")
	})

	t.Run("test wrong private key jwk", func(t *testing.T) {
		cmd := GetCreateConfigCmd()

		jwkFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(jwkFile.Name())) }()

		_, err = jwkFile.WriteString("wrongjwk")
		require.NoError(t, err)

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(configData, jwkFile.Name()))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, sidetreeURLArg()...)
		args = append(args, configFileArg(file.Name())...)

		cmd.SetArgs(args)

		err = cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal to jwk")
	})

	t.Run("test error from create did", func(t *testing.T) {
		cmd := GetCreateConfigCmd()

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

		keyFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = keyFile.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(keyFile.Name())) }()

		var args []string
		args = append(args, sidetreeURLArg()...)
		args = append(args, configFileArg(file.Name())...)
		args = append(args, recoveryKeyFileFlagNameArg(keyFile.Name())...)
		args = append(args, updateKeyFileFlagNameArg(keyFile.Name())...)

		cmd.SetArgs(args)

		err = cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting sidetreeconfig from cache")
	})

	t.Run("test create config and write them to file", func(t *testing.T) {
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

		filesData, didConfData, err := createConfig(&parameters{config: c,
			vdr: &mockvdr.MockVDR{
				CreateFunc: func(did *docdid.Doc,
					opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
					return &docdid.DocResolution{DIDDocument: &docdid.Doc{ID: "did1"}}, nil
				}}})
		require.NoError(t, err)

		require.Equal(t, 2, len(filesData))

		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.RemoveAll(dir)) }()

		require.NoError(t, writeFiles(dir, filesData, didConfData))

		_, err = os.Stat(dir + "/did-trustbloc/consortium.net.json")
		require.False(t, os.IsNotExist(err))

		_, err = os.Stat(dir + "/did-trustbloc/stakeholder.one.json")
		require.False(t, os.IsNotExist(err))

		_, err = os.Stat(dir + "/stakeholder.one/did-configuration.json")
		require.False(t, os.IsNotExist(err))
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	os.Clearenv()

	startCmd := GetCreateConfigCmd()

	require.NoError(t, os.Setenv(sidetreeURLEnvKey, "localhost:8080"))
	require.NoError(t, os.Setenv(configcommon.ConfigFileEnvKey, "domain"))
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func sidetreeURLArg() []string {
	return []string{flag + sidetreeURLFlagName, "localhost:8080"}
}

func configFileArg(config string) []string {
	return []string{flag + configcommon.ConfigFileFlagName, config}
}

func recoveryKeyFileFlagNameArg(value string) []string {
	return []string{flag + recoveryKeyFileFlagName, value}
}

func recoveryKeyFlagNameArg(value string) []string {
	return []string{flag + recoveryKeyFlagName, value}
}

func updateKeyFileFlagNameArg(value string) []string {
	return []string{flag + updateKeyFileFlagName, value}
}
