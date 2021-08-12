/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didconfiguration

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	log "github.com/sirupsen/logrus"
	"github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

// CreateDIDConfiguration creates a DID Configuration asserting a given DID's ownership over a given domain
//   using the given signing keys (which are assumed to belong to the DID)
// Implements https://identity.foundation/specs/did-configuration/.
func CreateDIDConfiguration(domain, didValue string, expiryTime int64,
	signingKeys ...*jose.SigningKey) (*models.DIDConfiguration, error) {
	config := models.DIDConfiguration{Entries: []models.DomainLinkageAssertion{}}

	for _, key := range signingKeys {
		dla, err := createDomainLinkageAssertion(domain, didValue, expiryTime, key)
		if err != nil {
			return nil, fmt.Errorf("can't create DomainLinkageAssertion: %w", err)
		}

		config.Entries = append(config.Entries, *dla)
	}

	return &config, nil
}

// createDomainLinkageAssertion creates a Domain Linkage Assertion for a DID Configuration.
func createDomainLinkageAssertion(
	domain, didValue string, expiryTime int64, signingKey *jose.SigningKey) (*models.DomainLinkageAssertion, error) {
	claims := models.DomainLinkageAssertionClaims{
		ISS:    didValue,
		Domain: domain,
		Exp:    expiryTime,
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("can't marshal claims: %w", err)
	}

	signer, err := jose.NewSigner(*signingKey, nil)
	if err != nil {
		return nil, fmt.Errorf("can't construct signer: %w", err)
	}

	jws, err := signer.Sign(claimsBytes)
	if err != nil {
		return nil, fmt.Errorf("can't sign claims: %w", err)
	}

	jwsCompact, err := jws.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("can't serialize signature: %w", err)
	}

	return &models.DomainLinkageAssertion{
		DID: didValue,
		JWT: jwsCompact,
	}, nil
}

// VerifyDIDConfiguration verifies a DID configuration, using the given VDRI to resolve the DID.
//   returns a list of the DIDs that were successfully authenticated to this domain.
func VerifyDIDConfiguration(domain string, configuration *models.DIDConfiguration, doc *did.Doc) ([]string, error) {
	didSet := map[string]struct{}{}

	var errs []string

	for i, dla := range configuration.Entries {
		err := ValidateDomainLinkageAssertion(domain, dla, doc)
		if err != nil {
			log.Debugf("domain linkage assertion %v for %s invalid", i, domain)

			errs = append(errs, err.Error())
		} else {
			didSet[dla.DID] = struct{}{}
		}
	}

	dids := make([]string, 0, len(didSet))
	for id := range didSet {
		dids = append(dids, id)
	}

	if len(dids) == 0 {
		errMsg := ""
		for _, ems := range errs {
			errMsg += "`" + ems + "`, "
		}

		return nil, fmt.Errorf("all domain linkage assertions invalid for domain %s: %s", domain, errMsg)
	}

	return dids, nil
}

// ValidateDomainLinkageAssertion validates a domain linkage assertion, using the given VDRI to resolve the DID.
func ValidateDomainLinkageAssertion(domain string, assertion models.DomainLinkageAssertion, doc *did.Doc) error {
	jws, err := jose.ParseSigned(assertion.JWT)
	if err != nil {
		return fmt.Errorf("cannot parse assertion JWT: %w", err)
	}

	var claims models.DomainLinkageAssertionClaims

	rawClaims := jws.UnsafePayloadWithoutVerification()
	err = json.Unmarshal(rawClaims, &claims)

	if err != nil {
		return fmt.Errorf("cannot parse assertion JWT claims: %w", err)
	}

	if claims.ISS != assertion.DID {
		return fmt.Errorf("assertion DID does not match signature")
	}

	if claims.Domain != domain {
		return fmt.Errorf("assertion domain does not match host domain")
	}

	if claims.Exp != 0 && claims.Exp <= time.Now().Unix() {
		return fmt.Errorf("assertion has expired")
	}

	_, err = VerifyDIDSignature(jws, doc)

	return err
}

// VerifyDIDSignature verify a signature using a DID doc.
func VerifyDIDSignature(jws *jose.JSONWebSignature, doc *did.Doc) ([]byte, error) {
	if jws == nil {
		return nil, fmt.Errorf("jws is nil")
	}

	jwkList := getJWKs(doc)

	errs := ""

	var val []byte

	var err error

	verified := false

	for _, key := range jwkList {
		if key == nil || key.Key == nil {
			return nil, fmt.Errorf("key is nil")
		}

		_, _, val, err = jws.VerifyMulti(key.Key)
		if err == nil {
			verified = true

			break
		} else {
			errs += err.Error() + ", "
		}
	}

	if !verified {
		docMsg := ""

		docBytes, err := doc.JSONBytes()
		if err == nil {
			docMsg = " using doc:\n" + string(docBytes)
		}

		return nil, fmt.Errorf("failed to verify: %s%s", errs, docMsg)
	}

	return val, nil
}

func getJWKs(doc *did.Doc) []*jwk.JWK {
	jwkList := make([]*jwk.JWK, 0)

	for _, pk := range doc.VerificationMethod {
		jwkKey := pk.JSONWebKey()
		if jwkKey == nil || jwkKey.Key == nil {
			continue
		}

		jwkList = append(jwkList, jwkKey)
	}

	for _, method := range doc.Authentication {
		jwkKey := method.VerificationMethod.JSONWebKey()
		if jwkKey == nil || jwkKey.Key == nil {
			continue
		}

		jwkList = append(jwkList, jwkKey)
	}

	return jwkList
}
