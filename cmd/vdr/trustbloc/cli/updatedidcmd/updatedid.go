/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package updatedidcmd

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strconv"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/common"
)

const (
	didURIFlagName  = "did-uri"
	didURIEnvKey    = "DID_METHOD_CLI_DID_URI"
	didURIFlagUsage = "DID URI. " +
		" Alternatively, this can be set with the following environment variable: " + didURIEnvKey

	domainFlagName      = "domain"
	domainFileEnvKey    = "DID_METHOD_CLI_DOMAIN"
	domainFileFlagUsage = "URL to the did:trustbloc consortium's domain. " +
		" Alternatively, this can be set with the following environment variable: " + domainFileEnvKey

	sidetreeURLFlagName  = "sidetree-url"
	sidetreeURLFlagUsage = "Comma-Separated list of sidetree url." +
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

	addPublicKeyFileFlagName  = "add-publickey-file"
	addPublicKeyFileEnvKey    = "DID_METHOD_CLI_ADD_PUBLICKEY_FILE"
	addPublicKeyFileFlagUsage = "publickey file include public keys to be added for TrustBloc DID " +
		" Alternatively, this can be set with the following environment variable: " + addPublicKeyFileEnvKey

	addServiceFileFlagName = "add-service-file"
	addServiceFileEnvKey   = "DID_METHOD_CLI_ADD_SERVICE_FILE"
	addServiceFlagUsage    = "publickey file include services to be added for TrustBloc DID " +
		" Alternatively, this can be set with the following environment variable: " + addServiceFileEnvKey

	signingKeyFlagName  = "signingkey"
	signingKeyEnvKey    = "DID_METHOD_CLI_SIGNINGKEY"
	signingKeyFlagUsage = "The private key PEM used for signing the update of the document." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyEnvKey

	signingKeyFileFlagName  = "signingkey-file"
	signingKeyFileEnvKey    = "DID_METHOD_CLI_SIGNINGKEY_FILE"
	signingKeyFileFlagUsage = "The file that contains the private key" +
		" PEM used for signing the update of the document." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyFileEnvKey

	signingKeyPasswordFlagName  = "signingkey-password"
	signingKeyPasswordEnvKey    = "DID_METHOD_CLI_SIGNINGKEY_PASSWORD" //nolint: gosec
	signingKeyPasswordFlagUsage = "signing key pem password. " +
		" Alternatively, this can be set with the following environment variable: " + signingKeyPasswordEnvKey

	nextUpdateKeyFlagName  = "nextupdatekey"
	nextUpdateKeyEnvKey    = "DID_METHOD_CLI_NEXTUPDATEKEY"
	nextUpdateKeyFlagUsage = "The public key PEM used for validating the signature of the next update of the document." +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyEnvKey

	nextUpdateKeyFileFlagName  = "nextupdatekey-file"
	nextUpdateKeyFileEnvKey    = "DID_METHOD_CLI_NEXTUPDATEKEY_FILE"
	nextUpdateKeyFileFlagUsage = "The file that contains the public key" +
		" PEM used for validating the signature of the next update of the document. " +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyFileEnvKey
)

// GetUpdateDIDCmd returns the Cobra update did command.
func GetUpdateDIDCmd() *cobra.Command {
	updateDIDCmd := updateDIDCmd()

	createFlags(updateDIDCmd)

	return updateDIDCmd
}

func updateDIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update-did",
		Short: "Update TrustBloc DID",
		Long:  "Update TrustBloc DID",
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCAs, err := getRootCAs(cmd)
			if err != nil {
				return err
			}

			didURI, err := cmdutils.GetUserSetVarFromString(cmd, didURIFlagName,
				didURIEnvKey, false)
			if err != nil {
				return err
			}

			sidetreeWriteToken := cmdutils.GetUserSetOptionalVarFromString(cmd, sidetreeWriteTokenFlagName,
				sidetreeWriteTokenEnvKey)

			domain := cmdutils.GetUserSetOptionalVarFromString(cmd, domainFlagName,
				domainFileEnvKey)

			didDoc, opts, err := updateDIDOption(didURI, cmd)
			if err != nil {
				return err
			}

			signingKey, err := common.GetKey(cmd, signingKeyFlagName, signingKeyEnvKey, signingKeyFileFlagName,
				signingKeyFileEnvKey, []byte(cmdutils.GetUserSetOptionalVarFromString(cmd, signingKeyPasswordFlagName,
					signingKeyPasswordEnvKey)), true)
			if err != nil {
				return err
			}

			nextUpdateKey, err := common.GetKey(cmd, nextUpdateKeyFlagName, nextUpdateKeyEnvKey, nextUpdateKeyFileFlagName,
				nextUpdateKeyFileEnvKey, nil, false)
			if err != nil {
				return err
			}

			vdr, err := trustbloc.New(&keyRetriever{nextUpdateKey: nextUpdateKey, signingKey: signingKey},
				trustbloc.WithAuthToken(sidetreeWriteToken), trustbloc.WithDomain(domain),
				trustbloc.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}))
			if err != nil {
				return err
			}

			err = vdr.Update(didDoc, opts...)
			if err != nil {
				return fmt.Errorf("failed to update did: %w", err)
			}

			fmt.Printf("successfully updated DID %s", didURI)

			return nil
		},
	}
}

func getSidetreeURL(cmd *cobra.Command) []vdrapi.DIDMethodOption {
	var opts []vdrapi.DIDMethodOption

	sidetreeURL := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLFlagName,
		sidetreeURLEnvKey)

	if len(sidetreeURL) > 0 {
		opts = append(opts, vdrapi.WithOption(trustbloc.EndpointsOpt, sidetreeURL))
	}

	return opts
}

func updateDIDOption(didID string, cmd *cobra.Command) (*ariesdid.Doc, []vdrapi.DIDMethodOption, error) {
	opts := getSidetreeURL(cmd)

	didDoc, err := getPublicKeys(cmd)
	if err != nil {
		return nil, nil, err
	}

	services, err := getServices(cmd)
	if err != nil {
		return nil, nil, err
	}

	didDoc.ID = didID
	didDoc.Service = services

	return didDoc, opts, nil
}

func getServices(cmd *cobra.Command) ([]ariesdid.Service, error) {
	serviceFile := cmdutils.GetUserSetOptionalVarFromString(cmd, addServiceFileFlagName,
		addServiceFileEnvKey)

	var svc []ariesdid.Service

	if serviceFile != "" {
		services, err := common.GetServices(serviceFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get services from file %w", err)
		}

		for i := range services {
			svc = append(svc, services[i])
		}
	}

	return svc, nil
}

func getPublicKeys(cmd *cobra.Command) (*ariesdid.Doc, error) {
	publicKeyFile := cmdutils.GetUserSetOptionalVarFromString(cmd, addPublicKeyFileFlagName,
		addPublicKeyFileEnvKey)

	if publicKeyFile != "" {
		return common.GetVDRPublicKeysFromFile(publicKeyFile)
	}

	return &ariesdid.Doc{}, nil
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
	startCmd.Flags().StringP(didURIFlagName, "", "", didURIFlagUsage)
	startCmd.Flags().StringP(domainFlagName, "", "", domainFileFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(addPublicKeyFileFlagName, "", "", addPublicKeyFileFlagUsage)
	startCmd.Flags().StringP(addServiceFileFlagName, "", "", addServiceFlagUsage)
	startCmd.Flags().StringP(signingKeyFlagName, "", "", signingKeyFlagUsage)
	startCmd.Flags().StringP(signingKeyFileFlagName, "", "", signingKeyFileFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFlagName, "", "", nextUpdateKeyFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFileFlagName, "", "", nextUpdateKeyFileFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLFlagName, "", []string{}, sidetreeURLFlagUsage)
	startCmd.Flags().StringP(signingKeyPasswordFlagName, "", "", signingKeyPasswordFlagUsage)
}

type keyRetriever struct {
	nextUpdateKey crypto.PublicKey
	signingKey    crypto.PublicKey
}

func (k *keyRetriever) GetNextRecoveryPublicKey(didID string) (crypto.PublicKey, error) {
	return nil, nil
}

func (k *keyRetriever) GetNextUpdatePublicKey(didID string) (crypto.PublicKey, error) {
	return k.nextUpdateKey, nil
}

func (k *keyRetriever) GetSigningKey(didID string, ot trustbloc.OperationType) (crypto.PrivateKey, error) {
	return k.signingKey, nil
}
