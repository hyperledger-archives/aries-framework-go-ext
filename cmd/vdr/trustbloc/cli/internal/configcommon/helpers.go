/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package configcommon

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
	"github.com/spf13/cobra"
	gojose "github.com/square/go-jose/v3"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
)

// Config file parameter for CLI consortium config commands
const (
	ConfigFileFlagName  = "config-file"
	ConfigFileEnvKey    = "DID_METHOD_CLI_CONFIG_FILE"
	ConfigFileFlagUsage = "Config file include data required for creating well known config files " +
		" Alternatively, this can be set with the following environment variable: " + ConfigFileEnvKey
)

// Config configuration for a did method consortium and its members
type Config struct {
	ConsortiumData ConsortiumData `json:"consortiumData,omitempty"`
	MembersData    []*MemberData  `json:"membersData,omitempty"`
}

// ConsortiumData configuration data for a consortium
type ConsortiumData struct {
	// Domain is the domain name of the consortium
	Domain string `json:"domain,omitempty"`
	// Policy contains the consortium policy configuration
	Policy models.ConsortiumPolicy `json:"policy"`
}

// MemberData configuration data for a consortium member
type MemberData struct {
	// Domain is the domain name of the member
	Domain string `json:"domain,omitempty"`
	// Policy contains stakeholder-specific configuration settings
	Policy models.StakeholderSettings `json:"policy"`
	// Endpoints is a list of sidetree endpoints owned by this stakeholder organization
	Endpoints []string `json:"endpoints"`
	// PrivateKeyJwk is privatekey jwk file
	PrivateKeyJwkPath string `json:"privateKeyJwkPath,omitempty"`
	// DID is the DID of the member, needed for consortium config updates
	DID string `json:"did,omitempty"`

	JSONWebKey gojose.JSONWebKey
	SigKey     gojose.SigningKey
}

// WriteConfig writes a number of json config files to the given directory, given a map of file names to their data
func WriteConfig(outputDirectory string, filesData map[string][]byte) error {
	if outputDirectory != "" {
		if err := os.MkdirAll(outputDirectory, 0755); err != nil { //nolint: gosec
			return err
		}
	}

	if err := os.MkdirAll(path.Join(outputDirectory, "did-trustbloc"), 0755); err != nil { //nolint: gosec
		return err
	}

	for k, v := range filesData {
		err := ioutil.WriteFile(path.Join(outputDirectory, "did-trustbloc", k+".json"), v, 0644) //nolint: gosec
		if err != nil {
			return fmt.Errorf("failed to write file %w", err)
		}
	}

	return nil
}

// GetConfig gets a config file for generating/updating a consortium's configs
func GetConfig(cmd *cobra.Command) (*Config, error) {
	configFile, err := cmdutils.GetUserSetVarFromString(cmd, ConfigFileFlagName,
		ConfigFileEnvKey, false)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadFile(filepath.Clean(configFile))
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s' : %w", configFile, err)
	}

	var conf Config

	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed unmarshal to config %w", err)
	}

	for _, member := range conf.MembersData {
		jwkData, err := ioutil.ReadFile(filepath.Clean(member.PrivateKeyJwkPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read jwk file '%s' : %w", member.PrivateKeyJwkPath, err)
		}

		if err := member.JSONWebKey.UnmarshalJSON(jwkData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal to jwk: %w", err)
		}
		// TODO add support for ECDSA using P-256 and SHA-256
		member.SigKey = gojose.SigningKey{Key: member.JSONWebKey.Key, Algorithm: gojose.EdDSA}
	}

	return &conf, nil
}

// SignConfig sign a config file
func SignConfig(configBytes []byte, keys []gojose.SigningKey) (string, error) {
	signer, err := gojose.NewMultiSigner(keys, nil)
	if err != nil {
		return "", err
	}

	jws, err := signer.Sign(configBytes)
	if err != nil {
		return "", err
	}

	return jws.FullSerialize(), nil
}
