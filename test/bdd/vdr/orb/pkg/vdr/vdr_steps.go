/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package vdr implements vdr steps
//
package vdr

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go-ext/test/bdd/vdr/orb/pkg/context"
)

const (
	maxRetry  = 10
	serviceID = "service"
	// P256KeyType EC P-256 key type.
	P256KeyType = "P256"
	p384KeyType = "P384"
	// Ed25519KeyType ed25519 key type.
	Ed25519KeyType = "Ed25519"
	origin         = "origin.com"
	jsonWebKey2020 = "JsonWebKey2020"
)

// Steps is steps for VC BDD tests.
type Steps struct {
	bddContext *context.BDDContext
	createdDID string
	kid        string
	httpClient *http.Client
	vdr        *orb.VDR
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *context.BDDContext) *Steps {
	vdr, err := orb.New(nil, orb.WithTLSConfig(ctx.TLSConfig))
	if err != nil {
		panic(err.Error())
	}

	return &Steps{bddContext: ctx, httpClient: &http.Client{}, vdr: vdr}
}

// RegisterSteps registers agent steps.
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Orb DID is created through "([^"]*)" with key type "([^"]*)" with signature suite "([^"]*)"$`,
		e.createDID)
	s.Step(`^Resolve created DID through "([^"]*)" and validate key type "([^"]*)", signature suite "([^"]*)"$`,
		e.resolveCreatedDID)
}

func (e *Steps) createDID(url, keyType, signatureSuite string) error {
	kid, pubKey, err := e.getPublicKey(keyType)
	if err != nil {
		return err
	}

	_, recoveryKey, err := e.getPublicKey("Ed25519")
	if err != nil {
		return err
	}

	_, updateKey, err := e.getPublicKey("Ed25519")
	if err != nil {
		return err
	}

	var k interface{}

	switch keyType {
	case P256KeyType:
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey)
		k = &ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()}
	case p384KeyType:
		x, y := elliptic.Unmarshal(elliptic.P384(), pubKey)
		k = &ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P384()}
	default:
		k = ed25519.PublicKey(pubKey)
	}

	jwk, err := jose.JWKFromPublicKey(k)
	if err != nil {
		return err
	}

	vm, err := ariesdid.NewVerificationMethodFromJWK(kid, signatureSuite, "", jwk)
	if err != nil {
		return err
	}

	didDoc := &ariesdid.Doc{}

	didDoc.Authentication = append(didDoc.Authentication, *ariesdid.NewReferencedVerification(vm,
		ariesdid.Authentication))

	didDoc.Service = []ariesdid.Service{{ID: serviceID, Type: "type", ServiceEndpoint: "http://www.example.com/"}}

	createdDocResolution, err := e.vdr.Create(didDoc, vdrapi.WithOption(orb.EndpointsOpt, []string{url}),
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, ed25519.PublicKey(recoveryKey)),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, ed25519.PublicKey(updateKey)),
		vdrapi.WithOption(orb.AnchorOriginOpt, origin))
	if err != nil {
		return err
	}

	e.createdDID = createdDocResolution.DIDDocument.ID
	e.kid = kid

	return nil
}

func (e *Steps) resolveCreatedDID(url, keyType, signatureSuite string) error {
	var docResolution *ariesdid.DocResolution

	for i := 1; i <= maxRetry; i++ {
		var err error
		docResolution, err = e.vdr.Read(e.createdDID, vdrapi.WithOption(orb.EndpointsOpt, []string{url}))

		if err != nil && (!strings.Contains(err.Error(), "DID does not exist") || i == maxRetry) {
			return err
		}

		time.Sleep(1 * time.Second)
	}

	if docResolution.DIDDocument.ID != e.createdDID {
		return fmt.Errorf("resolved did %s not equal to created did %s",
			docResolution.DIDDocument.ID, e.createdDID)
	}

	if docResolution.DIDDocument.Service[0].ID != docResolution.DIDDocument.ID+"#"+serviceID {
		return fmt.Errorf("resolved did service ID %s not equal to %s",
			docResolution.DIDDocument.Service[0].ID, docResolution.DIDDocument.ID+"#"+serviceID)
	}

	if err := e.validatePublicKey(docResolution.DIDDocument, keyType, signatureSuite); err != nil {
		return err
	}

	return nil
}

func (e *Steps) getPublicKey(keyType string) (string, []byte, error) { //nolint:gocritic
	var kt kms.KeyType

	switch keyType {
	case Ed25519KeyType:
		kt = kms.ED25519Type
	case P256KeyType:
		kt = kms.ECDSAP256TypeIEEEP1363
	case p384KeyType:
		kt = kms.ECDSAP384TypeIEEEP1363
	}

	return e.bddContext.LocalKMS.CreateAndExportPubKeyBytes(kt)
}

func (e *Steps) validatePublicKey(didDoc *ariesdid.Doc, keyType, signatureSuite string) error {
	if len(didDoc.VerificationMethod) != 1 {
		return fmt.Errorf("veification method size not equal one")
	}

	expectedJwkKeyType := ""

	switch keyType {
	case Ed25519KeyType:
		expectedJwkKeyType = "OKP"
	case P256KeyType:
		expectedJwkKeyType = "EC"
	case p384KeyType:
		expectedJwkKeyType = "EC"
	}

	if signatureSuite == jsonWebKey2020 &&
		expectedJwkKeyType != didDoc.VerificationMethod[0].JSONWebKey().Kty {
		return fmt.Errorf("jwk key type : expected=%s actual=%s", expectedJwkKeyType,
			didDoc.VerificationMethod[0].JSONWebKey().Kty)
	}

	if signatureSuite == doc.Ed25519VerificationKey2018 &&
		didDoc.VerificationMethod[0].JSONWebKey() != nil {
		return fmt.Errorf("jwk is not nil for %s", signatureSuite)
	}

	return e.verifyPublicKeyAndType(didDoc, signatureSuite)
}

func (e *Steps) verifyPublicKeyAndType(didDoc *ariesdid.Doc, signatureSuite string) error {
	if didDoc.VerificationMethod[0].ID != didDoc.ID+"#"+e.kid {
		return fmt.Errorf("resolved did public key ID %s not equal to %s",
			didDoc.VerificationMethod[0].ID, didDoc.ID+"#"+e.kid)
	}

	if didDoc.VerificationMethod[0].Type != signatureSuite {
		return fmt.Errorf("resolved did public key type %s not equal to %s",
			didDoc.VerificationMethod[0].Type, signatureSuite)
	}

	return nil
}
