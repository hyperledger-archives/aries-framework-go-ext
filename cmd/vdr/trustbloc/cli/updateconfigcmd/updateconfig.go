/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package updateconfigcmd

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
	"github.com/spf13/cobra"
	gojose "github.com/square/go-jose/v3"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/internal/configcommon"
)

const (
	outputDirectoryFlagName  = "output-directory"
	outputDirectoryEnvKey    = "DID_METHOD_CLI_OUTPUT_DIRECTORY"
	outputDirectoryFlagUsage = "Output directory " +
		" Alternatively, this can be set with the following environment variable: " + outputDirectoryEnvKey

	oldConsortiumFlagName  = "prev-consortium"
	oldConsortiumEnvKey    = "DID_METHOD_CLI_PREV_CONSORTIUM"
	oldConsortiumFlagUsage = "The path of the previous consortium config file to be updated" +
		" Alternatively, this can be set with the following environment variable: " + oldConsortiumEnvKey
)

type parameters struct {
	config          *configcommon.Config
	outputDirectory string
	prevConfig      string
}

// GetUpdateConfigCmd returns the Cobra update config command.
func GetUpdateConfigCmd() *cobra.Command {
	updateConfigCmd := createUpdateConfigCmd()

	createFlags(updateConfigCmd)

	return updateConfigCmd
}

func createUpdateConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update-config",
		Short: "Update did method config file",
		Long:  "Update did method config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getParameters(cmd)
			if err != nil {
				return err
			}

			hash, err := moveToHistory(parameters.prevConfig, path.Join(parameters.outputDirectory, "did-trustbloc", "history"))
			if err != nil {
				return err
			}

			fileData, err := updateConsortium(parameters, hash)
			if err != nil {
				return err
			}

			return configcommon.WriteConfig(parameters.outputDirectory, fileData)
		},
	}
}

func getParameters(cmd *cobra.Command) (*parameters, error) {
	outputDirectory := cmdutils.GetUserSetOptionalVarFromString(cmd, outputDirectoryFlagName,
		outputDirectoryEnvKey)

	prevConfig := cmdutils.GetUserSetOptionalVarFromString(cmd, oldConsortiumFlagName, oldConsortiumEnvKey)

	config, err := configcommon.GetConfig(cmd)
	if err != nil {
		return nil, err
	}

	parameters := &parameters{
		config:          config,
		outputDirectory: outputDirectory,
		prevConfig:      prevConfig,
	}

	return parameters, nil
}

func moveToHistory(filePath, historyDirectory string) (string, error) {
	if historyDirectory != "" {
		if err := os.MkdirAll(historyDirectory, 0755); err != nil { //nolint: gosec
			return "", err
		}
	}

	fileBytes, err := ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return "", err
	}

	sha := crypto.SHA256.New()

	_, err = sha.Write(fileBytes)
	if err != nil {
		return "", err
	}

	sum := sha.Sum(nil)
	hash := base64.RawURLEncoding.EncodeToString(sum)

	err = ioutil.WriteFile(filepath.Join(historyDirectory, hash+".json"), fileBytes, 0600)

	if err != nil {
		return "", err
	}

	err = os.Remove(filepath.Clean(filePath))
	if err != nil {
		return "", err
	}

	return hash, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(configcommon.ConfigFileFlagName, "", "", configcommon.ConfigFileFlagUsage)
	startCmd.Flags().StringP(outputDirectoryFlagName, "", "", outputDirectoryFlagUsage)
	startCmd.Flags().StringP(oldConsortiumFlagName, "", "", oldConsortiumFlagUsage)
}

func updateConsortium(parameters *parameters, oldConsortiumHash string) (map[string][]byte, error) {
	sigKeys := make([]gojose.SigningKey, 0)

	consortium := models.Consortium{Domain: parameters.config.ConsortiumData.Domain,
		Policy: parameters.config.ConsortiumData.Policy, Previous: oldConsortiumHash}

	for _, member := range parameters.config.MembersData {
		pubKey, err := member.JSONWebKey.Public().MarshalJSON()
		if err != nil {
			return nil, err
		}

		consortium.Members = append(consortium.Members, &models.StakeholderListElement{Domain: member.Domain,
			DID: member.DID, PublicKey: models.PublicKey{ID: member.DID + "#" + member.JSONWebKey.KeyID,
				JWK: pubKey}})

		sigKeys = append(sigKeys, member.SigKey)
	}

	consortiumBytes, err := json.Marshal(consortium)
	if err != nil {
		return nil, err
	}

	jws, err := configcommon.SignConfig(consortiumBytes, sigKeys)
	if err != nil {
		return nil, err
	}

	filesData := make(map[string][]byte)
	filesData[consortium.Domain] = []byte(jws)

	return filesData, nil
}
