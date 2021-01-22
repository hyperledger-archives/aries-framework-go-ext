/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package signatureconfig implement signatureconfig
//
package signatureconfig

import (
	"fmt"
	"math/rand"

	"github.com/sirupsen/logrus"
	"github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

// VerifyConsortiumSignatures verifies signatures on a consortium file, against stakeholder keys of a consortium config.
func VerifyConsortiumSignatures(signedData *models.ConsortiumFileData, signerConsortium *models.Consortium) error {
	n := signerConsortium.Policy.NumQueries
	if n == 0 || n > len(signerConsortium.Members) {
		n = len(signerConsortium.Members)
	}

	perm := rand.Perm(len(signerConsortium.Members))
	verifiedCount := 0
	verificationErrors := ""

	for i := 0; i < len(signerConsortium.Members); i++ {
		keyData := signerConsortium.Members[perm[i]].PublicKey.JWK
		key := jose.JSONWebKey{}

		err := key.UnmarshalJSON(keyData)
		if err != nil {
			msg := "bad key for stakeholder: " + signerConsortium.Members[perm[i]].Domain
			logrus.Warn(msg)
			verificationErrors += msg + ", "

			continue
		}

		_, _, _, err = signedData.JWS.VerifyMulti(key)
		if err != nil {
			msg := "key fails to verify for stakeholder: " + signerConsortium.Members[perm[i]].Domain
			logrus.Warn(msg)
			verificationErrors += msg + ", "

			continue
		}

		verifiedCount++

		if verifiedCount == n {
			break
		}
	}

	if verifiedCount < n {
		return fmt.Errorf(
			"insufficient stakeholder endorsement of consortium config file. errors are: [%s]",
			verificationErrors)
	}

	return nil
}
