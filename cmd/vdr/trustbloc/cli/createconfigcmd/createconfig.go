/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createconfigcmd

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/didconfiguration"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesjose "github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/spf13/cobra"
	gojose "github.com/square/go-jose/v3"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/internal/configcommon"
)

const (
	sidetreeURLFlagName  = "sidetree-url"
	sidetreeURLFlagUsage = "Sidetree url." +
		" Alternatively, this can be set with the following environment variable: " + sidetreeURLEnvKey
	sidetreeURLEnvKey = "DID_METHOD_CLI_SIDETREE_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "DID_METHOD_CLI_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "DID_METHOD_CLI_TLS_CACERTS"

	sidetreeWriteTokenFlagName  = "sidetree-write-token"
	sidetreeWriteTokenEnvKey    = "DID_METHOD_CLI_SIDETREE_WRITE_TOKEN" //nolint: gosec
	sidetreeWriteTokenFlagUsage = "The sidetree write token " +
		" Alternatively, this can be set with the following environment variable: " + sidetreeWriteTokenEnvKey

	outputDirectoryFlagName  = "output-directory"
	outputDirectoryEnvKey    = "DID_METHOD_CLI_OUTPUT_DIRECTORY"
	outputDirectoryFlagUsage = "Output directory " +
		" Alternatively, this can be set with the following environment variable: " + outputDirectoryEnvKey

	recoveryKeyFlagName  = "recoverykey"
	recoveryKeyEnvKey    = "DID_METHOD_CLI_RECOVERYKEY"
	recoveryKeyFlagUsage = "The public key PEM used for recovery of the document. " +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyEnvKey

	recoveryKeyFileFlagName  = "recoverykey-file"
	recoveryKeyFileEnvKey    = "DID_METHOD_CLI_RECOVERYKEY_FILE"
	recoveryKeyFileFlagUsage = "The file that contains the public key PEM used for recovery of the document. " +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyFileEnvKey

	updateKeyFlagName  = "updatekey"
	updateKeyEnvKey    = "DID_METHOD_CLI_UPDATEKEY"
	updateKeyFlagUsage = "The public key PEM used for validating the signature of the next update of the document. " +
		" Alternatively, this can be set with the following environment variable: " + updateKeyEnvKey

	updateKeyFileFlagName  = "updatekey-file"
	updateKeyFileEnvKey    = "DID_METHOD_CLI_UPDATEKEY_FILE"
	updateKeyFileFlagUsage = "The file that contains the public key PEM used for" +
		" validating the signature of the next update of the document " +
		" Alternatively, this can be set with the following environment variable: " + updateKeyFileEnvKey
)

type vdr interface {
	Create(didDoc *docdid.Doc, opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error)
}

type parameters struct {
	sidetreeURL     string
	vdr             vdr
	config          *configcommon.Config
	recoveryKey     crypto.PublicKey
	updateKey       crypto.PublicKey
	outputDirectory string
}

// GetCreateConfigCmd returns the Cobra create conifg command.
func GetCreateConfigCmd() *cobra.Command {
	createConfigCmd := createCreateConfigCmd()

	createFlags(createConfigCmd)

	return createConfigCmd
}

func createCreateConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create-config",
		Short: "Create did method config file",
		Long:  "Create did method config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getParameters(cmd)
			if err != nil {
				return err
			}

			filesData, didConfData, err := createConfig(parameters)
			if err != nil {
				return err
			}

			return writeFiles(parameters.outputDirectory, filesData, didConfData)
		},
	}
}

func getParameters(cmd *cobra.Command) (*parameters, error) {
	sidetreeURL, err := cmdutils.GetUserSetVarFromString(cmd, sidetreeURLFlagName, sidetreeURLEnvKey,
		false)
	if err != nil {
		return nil, err
	}

	rootCAs, err := getRootCAs(cmd)
	if err != nil {
		return nil, err
	}

	sidetreeWriteToken := cmdutils.GetUserSetOptionalVarFromString(cmd, sidetreeWriteTokenFlagName,
		sidetreeWriteTokenEnvKey)

	outputDirectory := cmdutils.GetUserSetOptionalVarFromString(cmd, outputDirectoryFlagName,
		outputDirectoryEnvKey)

	config, err := configcommon.GetConfig(cmd)
	if err != nil {
		return nil, err
	}

	recoveryKey, err := getKey(cmd, recoveryKeyFlagName, recoveryKeyEnvKey, recoveryKeyFileFlagName,
		recoveryKeyFileEnvKey)
	if err != nil {
		return nil, err
	}

	updateKey, err := getKey(cmd, updateKeyFlagName, updateKeyEnvKey, updateKeyFileFlagName,
		updateKeyFileEnvKey)
	if err != nil {
		return nil, err
	}

	vdr, err := trustbloc.New(nil, trustbloc.WithAuthToken(sidetreeWriteToken),
		trustbloc.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}))
	if err != nil {
		return nil, err
	}

	parameters := &parameters{
		sidetreeURL:     strings.TrimSpace(sidetreeURL),
		vdr:             vdr,
		config:          config,
		recoveryKey:     recoveryKey,
		updateKey:       updateKey,
		outputDirectory: outputDirectory,
	}

	return parameters, nil
}

func writeFiles(outputDirectory string, filesData, didConfData map[string][]byte) error {
	err := configcommon.WriteConfig(outputDirectory, filesData)
	if err != nil {
		return err
	}

	return writeDIDConfiguration(outputDirectory, didConfData)
}

func getKey(cmd *cobra.Command, keyFlagName, keyEnvKey, keyFileFlagName,
	keyFileEnvKey string) (crypto.PublicKey, error) {
	keyString := cmdutils.GetUserSetOptionalVarFromString(cmd, keyFlagName,
		keyEnvKey)

	keyFile := cmdutils.GetUserSetOptionalVarFromString(cmd, keyFileFlagName,
		keyFileEnvKey)

	if keyString == "" && keyFile == "" {
		return nil, fmt.Errorf("either key (--%s) or key file (--%s) is required", keyFlagName, keyFileFlagName)
	}

	if keyString != "" && keyFile != "" {
		return nil, fmt.Errorf("only one of key (--%s) or key file (--%s) may be specified", keyFlagName, keyFileFlagName)
	}

	if keyFile != "" {
		return publicKeyFromFile(keyFile)
	}

	return publicKeyFromPEM([]byte(keyString))
}

func publicKeyFromFile(file string) (crypto.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}

	return publicKeyFromPEM(keyBytes)
}

func publicKeyFromPEM(pubKeyPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("public key not found in PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := key.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key")
	}

	return publicKey, nil
}

func createDIDConfiguration(domain, didID string, expiryTime int64,
	signiningKeys ...*gojose.SigningKey) ([]byte, error) {
	conf, err := didconfiguration.CreateDIDConfiguration(domain, didID, expiryTime, signiningKeys...)
	if err != nil {
		return nil, err
	}

	return json.Marshal(conf)
}

func writeDIDConfiguration(outputDirectory string, filesData map[string][]byte) error {
	if outputDirectory != "" {
		if err := os.MkdirAll(outputDirectory, 0755); err != nil { //nolint: gosec
			return err
		}
	}

	for domain, data := range filesData {
		if err := os.MkdirAll(path.Join(outputDirectory, domain), 0755); err != nil { //nolint: gosec
			return err
		}

		err := ioutil.WriteFile(path.Join(outputDirectory, domain, "did-configuration.json"), data, 0644) //nolint: gosec
		if err != nil {
			return fmt.Errorf("failed to write file %w", err)
		}
	}

	return nil
}

func getRootCAs(cmd *cobra.Command) (*x509.CertPool, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error

		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey)

	return tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(sidetreeURLFlagName, "", "", sidetreeURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(configcommon.ConfigFileFlagName, "", "", configcommon.ConfigFileFlagUsage)
	startCmd.Flags().StringP(outputDirectoryFlagName, "", "", outputDirectoryFlagUsage)
	startCmd.Flags().StringP(recoveryKeyFlagName, "", "", recoveryKeyFlagUsage)
	startCmd.Flags().StringP(recoveryKeyFileFlagName, "", "", recoveryKeyFileFlagUsage)
	startCmd.Flags().StringP(updateKeyFlagName, "", "", updateKeyFlagUsage)
	startCmd.Flags().StringP(updateKeyFileFlagName, "", "", updateKeyFileFlagUsage)
}

func createConfig(parameters *parameters) (map[string][]byte, map[string][]byte, error) { //nolint: funlen
	filesData := make(map[string][]byte)
	sigKeys := make([]gojose.SigningKey, 0)

	didConfData := make(map[string][]byte)

	consortium := models.Consortium{Domain: parameters.config.ConsortiumData.Domain,
		Policy: parameters.config.ConsortiumData.Policy}

	for _, member := range parameters.config.MembersData {
		didDoc, err := createDID(parameters.vdr, parameters.sidetreeURL, &member.JSONWebKey, parameters.updateKey,
			parameters.recoveryKey)
		if err != nil {
			return nil, nil, err
		}

		pubKey, err := member.JSONWebKey.Public().MarshalJSON()
		if err != nil {
			return nil, nil, err
		}

		consortium.Members = append(consortium.Members, &models.StakeholderListElement{Domain: member.Domain,
			DID: didDoc.ID, PublicKey: models.PublicKey{ID: didDoc.ID + "#" + member.JSONWebKey.KeyID,
				JWK: pubKey}})

		stakeholder := models.Stakeholder{Domain: member.Domain, DID: didDoc.ID,
			Policy: member.Policy, Endpoints: member.Endpoints}

		stakeholderBytes, err := json.Marshal(stakeholder)
		if err != nil {
			return nil, nil, err
		}

		jws, err :=
			configcommon.SignConfig(stakeholderBytes, []gojose.SigningKey{member.SigKey})
		if err != nil {
			return nil, nil, err
		}

		sigKeys = append(sigKeys, member.SigKey)

		filesData[member.Domain] = []byte(jws)

		didConf, err := createDIDConfiguration(member.Domain, didDoc.ID, 0, &member.SigKey)
		if err != nil {
			return nil, nil, fmt.Errorf("did configuration failed %w: ", err)
		}

		didConfData[member.Domain] = didConf
	}

	consortiumBytes, err := json.Marshal(consortium)
	if err != nil {
		return nil, nil, err
	}

	jws, err := configcommon.SignConfig(consortiumBytes, sigKeys)
	if err != nil {
		return nil, nil, err
	}

	filesData[consortium.Domain] = []byte(jws)

	return filesData, didConfData, nil
}

func createDID(vdr vdr, sidetreeURL string, jsonWebKey *gojose.JSONWebKey,
	updateKey, recoveryKey crypto.PublicKey) (*docdid.Doc, error) {
	var didMethodOpt []vdrapi.DIDMethodOption

	didMethodOpt = append(didMethodOpt, vdrapi.WithOption(trustbloc.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(trustbloc.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(trustbloc.EndpointsOpt, []string{sidetreeURL}))

	jwk, err := ariesjose.JWKFromPublicKey(jsonWebKey.Public().Key)
	if err != nil {
		return nil, err
	}

	vm, err := docdid.NewVerificationMethodFromJWK(jsonWebKey.KeyID, doc.JWSVerificationKey2020, "", jwk)
	if err != nil {
		return nil, err
	}

	docResolution, err := vdr.Create(&docdid.Doc{
		Authentication: []docdid.Verification{*docdid.NewReferencedVerification(vm, docdid.Authentication)}},
		didMethodOpt...)
	if err != nil {
		return nil, err
	}

	return docResolution.DIDDocument, nil
}
