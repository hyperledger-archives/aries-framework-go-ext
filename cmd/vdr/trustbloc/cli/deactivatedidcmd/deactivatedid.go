/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package deactivatedidcmd

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strconv"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc"
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

	signingKeyFlagName  = "signingkey"
	signingKeyEnvKey    = "DID_METHOD_CLI_SIGNINGKEY"
	signingKeyFlagUsage = "The private key PEM used for signing the deactivate request." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyEnvKey

	signingKeyFileFlagName  = "signingkey-file"
	signingKeyFileEnvKey    = "DID_METHOD_CLI_SIGNINGKEY_FILE"
	signingKeyFileFlagUsage = "The file that contains the private key" +
		" PEM used for signing the deactivate request" +
		" Alternatively, this can be set with the following environment variable: " + signingKeyFileEnvKey

	signingKeyPasswordFlagName  = "signingkey-password"
	signingKeyPasswordEnvKey    = "DID_METHOD_CLI_SIGNINGKEY_PASSWORD" //nolint: gosec
	signingKeyPasswordFlagUsage = "signing key pem password. " +
		" Alternatively, this can be set with the following environment variable: " + signingKeyPasswordEnvKey
)

// GetDeactivateDIDCmd returns the Cobra deactivate did command.
func GetDeactivateDIDCmd() *cobra.Command {
	deactivateDIDCmd := deactivateDIDCmd()

	createFlags(deactivateDIDCmd)

	return deactivateDIDCmd
}

func deactivateDIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deactivate-did",
		Short: "Deactivate TrustBloc DID",
		Long:  "Deactivate TrustBloc DID",
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

			signingKey, err := common.GetKey(cmd, signingKeyFlagName, signingKeyEnvKey, signingKeyFileFlagName,
				signingKeyFileEnvKey, []byte(cmdutils.GetUserSetOptionalVarFromString(cmd, signingKeyPasswordFlagName,
					signingKeyPasswordEnvKey)), true)
			if err != nil {
				return err
			}

			vdr, err := trustbloc.New(&keyRetriever{signingKey: signingKey},
				trustbloc.WithAuthToken(sidetreeWriteToken), trustbloc.WithDomain(domain),
				trustbloc.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}))
			if err != nil {
				return err
			}

			err = vdr.Deactivate(didURI, deactivateDIDOption(cmd)...)
			if err != nil {
				return fmt.Errorf("failed to deactivate did: %w", err)
			}

			fmt.Printf("successfully deactivated DID %s", didURI)

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

func deactivateDIDOption(cmd *cobra.Command) []vdrapi.DIDMethodOption {
	return getSidetreeURL(cmd)
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
	startCmd.Flags().StringArrayP(sidetreeURLFlagName, "", []string{}, sidetreeURLFlagUsage)
	startCmd.Flags().StringP(signingKeyFlagName, "", "", signingKeyFlagUsage)
	startCmd.Flags().StringP(signingKeyFileFlagName, "", "", signingKeyFileFlagUsage)
	startCmd.Flags().StringP(signingKeyPasswordFlagName, "", "", signingKeyPasswordFlagUsage)
}

type keyRetriever struct {
	signingKey crypto.PublicKey
}

func (k *keyRetriever) GetNextRecoveryPublicKey(didID string) (crypto.PublicKey, error) {
	return nil, nil
}

func (k *keyRetriever) GetNextUpdatePublicKey(didID string) (crypto.PublicKey, error) {
	return nil, nil
}

func (k *keyRetriever) GetSigningKey(didID string, ot trustbloc.OperationType) (crypto.PrivateKey, error) {
	return k.signingKey, nil
}
