/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/confighashcmd"
	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/createconfigcmd"
	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/createdidcmd"
	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/deactivatedidcmd"
	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/recoverdidcmd"
	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/updateconfigcmd"
	"github.com/hyperledger/aries-framework-go-ext/cmd/vdr/trustbloc/cli/updatedidcmd"
)

func main() {
	rootCmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(createconfigcmd.GetCreateConfigCmd())
	rootCmd.AddCommand(updateconfigcmd.GetUpdateConfigCmd())
	rootCmd.AddCommand(confighashcmd.GetConfigHashCmd())
	rootCmd.AddCommand(createdidcmd.GetCreateDIDCmd())
	rootCmd.AddCommand(updatedidcmd.GetUpdateDIDCmd())
	rootCmd.AddCommand(recoverdidcmd.GetRecoverDIDCmd())
	rootCmd.AddCommand(deactivatedidcmd.GetDeactivateDIDCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to run did method cli: %s", err.Error())
	}
}
