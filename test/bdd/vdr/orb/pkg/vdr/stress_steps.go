/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package vdr implements vdr steps
//
package vdr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/sirupsen/logrus"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/orb/pkg/context"
)

var logger = logrus.New()

// StressSteps is steps for orb stress BDD tests.
type StressSteps struct {
	bddContext *context.BDDContext
}

// NewStressSteps returns new agent from client SDK.
func NewStressSteps(ctx *context.BDDContext) *StressSteps {
	return &StressSteps{
		bddContext: ctx,
	}
}

// RegisterSteps registers agent steps.
func (e *StressSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client sends request to "([^"]*)" to create and update "([^"]*)" DID documents with anchor origin "([^"]*)" using "([^"]*)" concurrent requests$`,
		e.createConcurrentReq)
}

func (e *StressSteps) createConcurrentReq(domainsEnv, didNumsEnv, anchorOriginEnv, concurrencyEnv string) error {
	domains := os.Getenv(domainsEnv)
	if domains == "" {
		return fmt.Errorf("domains is empty")
	}

	anchorOrigin := os.Getenv(anchorOriginEnv)
	if domains == "" {
		return fmt.Errorf("anchorOrigin is empty")
	}

	didNumsStr := os.Getenv(didNumsEnv)
	if didNumsStr == "" {
		return fmt.Errorf("did nums is empty")
	}

	didNums, err := strconv.Atoi(didNumsStr)
	if err != nil {
		return err
	}

	concurrencyReqStr := os.Getenv(concurrencyEnv)
	if concurrencyReqStr == "" {
		return fmt.Errorf("concurrency nums is empty")
	}

	concurrencyReq, err := strconv.Atoi(concurrencyReqStr)
	if err != nil {
		return err
	}

	urls := strings.Split(domains, ",")

	kr := &keyRetrieverMap{
		updateKey:             make(map[string]crypto.PrivateKey),
		nextUpdatePublicKey:   make(map[string]crypto.PublicKey),
		recoverKey:            make(map[string]crypto.PrivateKey),
		nextRecoveryPublicKey: make(map[string]crypto.PublicKey),
	}

	vdrs := make([]*orb.VDR, 0)

	for _, url := range urls {
		vdr, err := orb.New(kr, orb.WithTLSConfig(e.bddContext.TLSConfig),
			orb.WithDomain(url), orb.WithAuthToken("ADMIN_TOKEN"))
		if err != nil {
			return err
		}

		vdrs = append(vdrs, vdr)
	}

	p := NewWorkerPool(concurrencyReq)

	p.Start()

	for i := 0; i < didNums; i++ {
		randomVDR := vdrs[mrand.Intn(len(urls))]

		p.Submit(&createUpdateDIDRequest{
			vdr:          randomVDR,
			kr:           kr,
			anchorOrigin: anchorOrigin,
			steps:        e,
		})
	}

	p.Stop()

	logger.Infof("got %d responses for %d requests", len(p.responses), didNums)

	if len(p.responses) != didNums {
		return fmt.Errorf("expecting %d responses but got %d", didNums, len(p.responses))
	}

	for _, resp := range p.responses {
		if resp.Err != nil {
			return resp.Err
		}
	}

	return nil
}

func (e *StressSteps) createVerificationMethod(keyType string, pubKey []byte, kid,
	signatureSuite string) (*ariesdid.VerificationMethod, error) {
	var jwk *jose.JWK

	var err error

	switch keyType {
	case P256KeyType:
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey)

		jwk, err = jose.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()})
		if err != nil {
			return nil, err
		}
	case p384KeyType:
		x, y := elliptic.Unmarshal(elliptic.P384(), pubKey)

		jwk, err = jose.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P384()})
		if err != nil {
			return nil, err
		}
	case bls12381G2KeyType:
		pk, e := bbs12381g2pub.UnmarshalPublicKey(pubKey)
		if e != nil {
			return nil, e
		}

		jwk, err = jose.JWKFromKey(pk)
		if err != nil {
			return nil, err
		}
	default:
		jwk, err = jose.JWKFromKey(ed25519.PublicKey(pubKey))
		if err != nil {
			return nil, err
		}
	}

	return ariesdid.NewVerificationMethodFromJWK(kid, signatureSuite, "", jwk)
}

func (e *StressSteps) createDID(keyType, signatureSuite, origin, svcEndpoint string, vdr *orb.VDR) (crypto.PrivateKey,
	crypto.PrivateKey, string, error) {
	kid, pubKey, err := e.getPublicKey(keyType)
	if err != nil {
		return nil, nil, "", err
	}

	recoveryKey, recoveryKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	updateKey, updateKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	vm, err := e.createVerificationMethod(keyType, pubKey, kid, signatureSuite)
	if err != nil {
		return nil, nil, "", err
	}

	didDoc := &ariesdid.Doc{}

	didDoc.Authentication = append(didDoc.Authentication, *ariesdid.NewReferencedVerification(vm,
		ariesdid.Authentication))

	didDoc.Service = []ariesdid.Service{{ID: serviceID, Type: "type", ServiceEndpoint: svcEndpoint}}

	createdDocResolution, err := vdr.Create(didDoc,
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(orb.AnchorOriginOpt, origin))
	if err != nil {
		return nil, nil, "", err
	}

	return recoveryKeyPrivateKey, updateKeyPrivateKey, createdDocResolution.DIDDocument.ID, nil
}

func (e *StressSteps) updateDID(didID string, origin, svcEndpoint string, vdr *orb.VDR) error {
	didDoc := &ariesdid.Doc{ID: didID}

	didDoc.Service = []ariesdid.Service{{ID: serviceID, Type: "type", ServiceEndpoint: svcEndpoint}}

	return vdr.Update(didDoc,
		vdrapi.WithOption(orb.AnchorOriginOpt, origin))
}

func (e *StressSteps) getPublicKey(keyType string) (string, []byte, error) { //nolint:gocritic
	var kt kms.KeyType

	switch keyType {
	case Ed25519KeyType:
		kt = kms.ED25519Type
	case P256KeyType:
		kt = kms.ECDSAP256TypeIEEEP1363
	case p384KeyType:
		kt = kms.ECDSAP384TypeIEEEP1363
	case bls12381G2KeyType:
		kt = kms.BLS12381G2Type
	}

	return e.bddContext.LocalKMS.CreateAndExportPubKeyBytes(kt)
}

type keyRetrieverMap struct {
	nextRecoveryPublicKey map[string]crypto.PublicKey
	nextUpdatePublicKey   map[string]crypto.PublicKey
	updateKey             map[string]crypto.PrivateKey
	recoverKey            map[string]crypto.PrivateKey
}

func (k *keyRetrieverMap) GetNextRecoveryPublicKey(didID string) (crypto.PublicKey, error) {
	return k.nextRecoveryPublicKey[didID], nil
}

func (k *keyRetrieverMap) GetNextUpdatePublicKey(didID string) (crypto.PublicKey, error) {
	return k.nextUpdatePublicKey[didID], nil
}

func (k *keyRetrieverMap) GetSigningKey(didID string, ot orb.OperationType) (crypto.PrivateKey, error) {
	if ot == orb.Update {
		return k.updateKey[didID], nil
	}

	return k.recoverKey[didID], nil
}

type createUpdateDIDRequest struct {
	vdr          *orb.VDR
	kr           *keyRetrieverMap
	steps        *StressSteps
	anchorOrigin string
}

func (r *createUpdateDIDRequest) Invoke() (interface{}, error) {
	recoveryKeyPrivateKey, updateKeyPrivateKey, intermID, err := r.steps.createDID("Ed25519",
		"Ed25519VerificationKey2018", r.anchorOrigin, uuid.New().URN(), r.vdr)
	if err != nil {
		return nil, err
	}

	logger.Infof("created did successfully %s", intermID)
	logger.Infof("statred resolving created did %s", intermID)

	var docResolution *ariesdid.DocResolution

	for i := 1; i <= maxRetry; i++ {
		var err error
		docResolution, err = r.vdr.Read(intermID)

		if err == nil {
			break
		}

		if !strings.Contains(err.Error(), "DID does not exist") || i == maxRetry {
			return nil, err
		}

		time.Sleep(1 * time.Second)
	}

	canonicalID := docResolution.DocumentMetadata.CanonicalID

	logger.Infof("resolved created did successfully %s", canonicalID)

	r.kr.recoverKey[canonicalID] = recoveryKeyPrivateKey
	r.kr.updateKey[canonicalID] = updateKeyPrivateKey

	nextUpdatePublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	r.kr.nextUpdatePublicKey[canonicalID] = nextUpdatePublicKey

	svcEndpoint := uuid.New().URN()

	if err := r.steps.updateDID(canonicalID, r.anchorOrigin, svcEndpoint, r.vdr); err != nil {
		return nil, err
	}

	logger.Infof("update did successfully %s", canonicalID)
	logger.Infof("statred resolving updated did %s", canonicalID)

	for i := 1; i <= maxRetry; i++ {
		var err error
		docResolution, err = r.vdr.Read(canonicalID)

		if err == nil && docResolution.DIDDocument.Service[0].ServiceEndpoint == svcEndpoint {
			break
		}

		if i == maxRetry {
			return nil, fmt.Errorf("update did not working %s", canonicalID)
		}

		time.Sleep(1 * time.Second)
	}

	logger.Infof("resolved updated did successfully %s %s", intermID, canonicalID)

	return nil, nil
}
