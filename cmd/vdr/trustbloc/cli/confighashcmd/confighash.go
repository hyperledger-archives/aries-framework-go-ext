/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package confighashcmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/btcsuite/btcutil/base58"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

const (
	configFileFlagName  = "config-file"
	configFileEnvKey    = "DID_METHOD_CLI_CONFIG_FILE"
	configFileFlagUsage = "Config file include data required for creating well known config files " +
		" Alternatively, this can be set with the following environment variable: " + configFileEnvKey
)

// GetConfigHashCmd returns the Cobra config hash command.
func GetConfigHashCmd() *cobra.Command {
	configHashCmd := createConfigHashCmd()

	createFlags(configHashCmd)

	return configHashCmd
}

func createConfigHashCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config-hash",
		Short: "Generate config hash",
		Long:  "Generate config hash",
		RunE: func(cmd *cobra.Command, args []string) error {
			configFile, err := cmdutils.GetUserSetVarFromString(cmd, configFileFlagName,
				configFileEnvKey, false)
			if err != nil {
				return err
			}

			configData, err := ioutil.ReadFile(configFile) //nolint: gosec
			if err != nil {
				return fmt.Errorf("failed to read config file '%s' : %w", configFile, err)
			}

			var m map[string]interface{}
			if errUnmarshal := json.Unmarshal(configData, &m); errUnmarshal != nil {
				return errUnmarshal
			}

			data, err := docutil.MarshalCanonical(m)
			if err != nil {
				return fmt.Errorf("failed to canonicalize config file : %w", err)
			}

			hash := base58.Encode(data)

			fmt.Println(hash[0:5])

			return nil
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(configFileFlagName, "", "", configFileFlagUsage)
}
