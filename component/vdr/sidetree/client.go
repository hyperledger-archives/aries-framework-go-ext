/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package sidetree implements sidetree client
//
package sidetree

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/edsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/client"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/create"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/deactivate"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/recovery"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/update"
)

const (
	defaultHashAlgorithm = 18
)

var logger = log.New("aries-framework-ext/vdr/sidetree/client") //nolint: gochecknoglobals

// Client sidetree client.
type Client struct {
	client    *http.Client
	tlsConfig *tls.Config
	authToken string
}

// New return did bloc client.
func New(opts ...Option) *Client {
	c := &Client{client: &http.Client{}}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	c.client.Transport = &http.Transport{TLSClientConfig: c.tlsConfig}

	return c
}

// CreateDID create did doc.
func (c *Client) CreateDID(opts ...create.Option) (*docdid.DocResolution, error) { //
	createDIDOpts := &create.Opts{MultiHashAlgorithm: defaultHashAlgorithm}
	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	err := validateCreateReq(createDIDOpts)
	if err != nil {
		return nil, err
	}

	// TODO add logic for using different sidetree endpoint
	// for now will use the first one
	endpoints, err := createDIDOpts.GetEndpoints()
	if err != nil {
		return nil, err
	}

	sidetreeEndpoint := endpoints[0]

	req, err := buildCreateRequest(createDIDOpts.MultiHashAlgorithm, createDIDOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to build sidetree request: %w", err)
	}

	responseBytes, err := c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to send create sidetree request: %w", err)
	}

	documentResolution, err := docdid.ParseDocumentResolution(responseBytes)
	if err != nil {
		if !errors.Is(err, docdid.ErrDIDDocumentNotExist) {
			return nil, fmt.Errorf("failed to parse document resolution: %w", err)
		}

		logger.Warnf("failed to parse document resolution %w", err)
	} else {
		return documentResolution, nil
	}

	didDoc, err := docdid.ParseDocument(responseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse did document: %w", err)
	}

	return &docdid.DocResolution{DIDDocument: didDoc}, nil
}

// UpdateDID update did doc.
func (c *Client) UpdateDID(did string, opts ...update.Option) error {
	updateDIDOpts := &update.Opts{MultiHashAlgorithm: defaultHashAlgorithm}
	// Apply options
	for _, opt := range opts {
		opt(updateDIDOpts)
	}

	err := validateUpdateReq(updateDIDOpts)
	if err != nil {
		return err
	}

	// TODO add logic for using different sidetree endpoint
	// for now will use the first one
	endpoints, err := updateDIDOpts.GetEndpoints()
	if err != nil {
		return err
	}

	sidetreeEndpoint := endpoints[0]

	req, err := c.buildUpdateRequest(did, updateDIDOpts.MultiHashAlgorithm, updateDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build update request: %w", err)
	}

	_, err = c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return fmt.Errorf("failed to send update did request: %w", err)
	}

	return nil
}

// RecoverDID recover did doc.
func (c *Client) RecoverDID(did string, opts ...recovery.Option) error {
	recoverDIDOpts := &recovery.Opts{MultiHashAlgorithm: defaultHashAlgorithm}
	// Apply options
	for _, opt := range opts {
		opt(recoverDIDOpts)
	}

	err := validateRecoverReq(recoverDIDOpts)
	if err != nil {
		return err
	}

	// TODO add logic for using different sidetree endpoint
	// for now will use the first one
	endpoints, err := recoverDIDOpts.GetEndpoints()
	if err != nil {
		return err
	}

	sidetreeEndpoint := endpoints[0]

	req, err := buildRecoverRequest(did, recoverDIDOpts.MultiHashAlgorithm, recoverDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build sidetree request: %w", err)
	}

	_, err = c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return fmt.Errorf("failed to send recover sidetree request: %w", err)
	}

	return err
}

// DeactivateDID deactivate did doc.
func (c *Client) DeactivateDID(did string, opts ...deactivate.Option) error {
	deactivateDIDOpts := &deactivate.Opts{}
	// Apply options
	for _, opt := range opts {
		opt(deactivateDIDOpts)
	}

	err := validateDeactivateReq(deactivateDIDOpts)
	if err != nil {
		return err
	}

	// TODO add logic for using different sidetree endpoint
	// for now will use the first one
	endpoints, err := deactivateDIDOpts.GetEndpoints()
	if err != nil {
		return err
	}

	sidetreeEndpoint := endpoints[0]

	req, err := buildDeactivateRequest(did, deactivateDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build sidetree request: %w", err)
	}

	_, err = c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return fmt.Errorf("failed to send deactivate sidetree request: %w", err)
	}

	return err
}

func validateCreateReq(createDIDOpts *create.Opts) error {
	if createDIDOpts.RecoveryPublicKey == nil {
		return fmt.Errorf("recovery public key is required")
	}

	if createDIDOpts.UpdatePublicKey == nil {
		return fmt.Errorf("update public key is required")
	}

	if createDIDOpts.GetEndpoints == nil {
		return fmt.Errorf("sidetree get endpoints func is required")
	}

	return nil
}

func validateUpdateReq(updateDIDOpts *update.Opts) error {
	if updateDIDOpts.SigningKey == nil {
		return fmt.Errorf("signing public key is required")
	}

	if updateDIDOpts.NextUpdatePublicKey == nil {
		return fmt.Errorf("next update public key is required")
	}

	if updateDIDOpts.OperationCommitment == "" {
		return fmt.Errorf("operation commitment is required")
	}

	if updateDIDOpts.GetEndpoints == nil {
		return fmt.Errorf("sidetree get endpoints func is required")
	}

	return nil
}

func validateRecoverReq(recoverDIDOpts *recovery.Opts) error {
	if recoverDIDOpts.NextRecoveryPublicKey == nil {
		return fmt.Errorf("next recovery public key is required")
	}

	if recoverDIDOpts.NextUpdatePublicKey == nil {
		return fmt.Errorf("next update public key is required")
	}

	if recoverDIDOpts.SigningKey == nil {
		return fmt.Errorf("signing key is required")
	}

	if recoverDIDOpts.OperationCommitment == "" {
		return fmt.Errorf("operation commitment is required")
	}

	if recoverDIDOpts.GetEndpoints == nil {
		return fmt.Errorf("sidetree get endpoints func is required")
	}

	return nil
}

func validateDeactivateReq(deactivateDIDOpts *deactivate.Opts) error {
	if deactivateDIDOpts.SigningKey == nil {
		return fmt.Errorf("signing key is required")
	}

	if deactivateDIDOpts.OperationCommitment == "" {
		return fmt.Errorf("operation commitment is required")
	}

	if deactivateDIDOpts.GetEndpoints == nil {
		return fmt.Errorf("sidetree get endpoints func is required")
	}

	return nil
}

// buildCreateRequest request builder for sidetree public DID creation.
func buildCreateRequest(multiHashAlgorithm uint, createDIDOpts *create.Opts) ([]byte, error) {
	didDoc := &doc.Doc{
		PublicKey: createDIDOpts.PublicKeys,
		Service:   createDIDOpts.Services,
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %s", err)
	}

	recoveryKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.RecoveryPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get recovery key : %s", err)
	}

	updateKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.UpdatePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get update key : %s", err)
	}

	recoveryCommitment, err := commitment.GetCommitment(recoveryKey, multiHashAlgorithm)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.GetCommitment(updateKey, multiHashAlgorithm)
	if err != nil {
		return nil, err
	}

	createRequestInfo := &client.CreateRequestInfo{
		OpaqueDocument:     string(docBytes),
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      multiHashAlgorithm,
	}

	req, err := client.NewCreateRequest(createRequestInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create sidetree request: %w", err)
	}

	return req, nil
}

// buildUpdateRequest request builder for sidetree public DID update.
func (c *Client) buildUpdateRequest(did string, multiHashAlgorithm uint,
	updateDIDOpts *update.Opts) ([]byte, error) {
	nextUpdateKey, err := pubkey.GetPublicKeyJWK(updateDIDOpts.NextUpdatePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get next update key : %s", err)
	}

	nextUpdateCommitment, err := commitment.GetCommitment(nextUpdateKey, multiHashAlgorithm)
	if err != nil {
		return nil, err
	}

	signer, updateKey, err := getSigner(updateDIDOpts.SigningKey, updateDIDOpts.SigningKeyID)
	if err != nil {
		return nil, err
	}

	patches, err := createUpdatePatches(updateDIDOpts)
	if err != nil {
		return nil, err
	}

	didSuffix, err := getUniqueSuffix(did)
	if err != nil {
		return nil, err
	}

	multihashCode, err := hashing.GetMultihashCode(updateDIDOpts.OperationCommitment)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(updateKey, uint(multihashCode))
	if err != nil {
		return nil, err
	}

	return client.NewUpdateRequest(&client.UpdateRequestInfo{
		DidSuffix:        didSuffix,
		RevealValue:      rv,
		UpdateCommitment: nextUpdateCommitment,
		UpdateKey:        updateKey,
		Patches:          patches,
		MultihashCode:    multiHashAlgorithm,
		Signer:           signer,
	})
}

// buildRecoverRequest request builder for sidetree public DID recovery.
func buildRecoverRequest(did string, multiHashAlgorithm uint, recoverDIDOpts *recovery.Opts) ([]byte, error) {
	didDoc := &doc.Doc{
		PublicKey: recoverDIDOpts.PublicKeys,
		Service:   recoverDIDOpts.Services,
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %s", err)
	}

	nextRecoveryCommitment, nextUpdateCommitment, err := getCommitment(multiHashAlgorithm, recoverDIDOpts)
	if err != nil {
		return nil, err
	}

	signer, recoveryKey, err := getSigner(recoverDIDOpts.SigningKey, recoverDIDOpts.SigningKeyID)
	if err != nil {
		return nil, err
	}

	didSuffix, err := getUniqueSuffix(did)
	if err != nil {
		return nil, err
	}

	multihashCode, err := hashing.GetMultihashCode(recoverDIDOpts.OperationCommitment)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(recoveryKey, uint(multihashCode))
	if err != nil {
		return nil, err
	}

	req, err := client.NewRecoverRequest(&client.RecoverRequestInfo{
		DidSuffix: didSuffix, RevealValue: rv, OpaqueDocument: string(docBytes),
		RecoveryCommitment: nextRecoveryCommitment, UpdateCommitment: nextUpdateCommitment,
		MultihashCode: multiHashAlgorithm, Signer: signer, RecoveryKey: recoveryKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sidetree request: %w", err)
	}

	return req, nil
}

// buildDeactivateRequest request builder for sidetree public DID deactivate.
func buildDeactivateRequest(did string, deactivateDIDOpts *deactivate.Opts) ([]byte, error) {
	signer, publicKey, err := getSigner(deactivateDIDOpts.SigningKey, deactivateDIDOpts.SigningKeyID)
	if err != nil {
		return nil, err
	}

	didSuffix, err := getUniqueSuffix(did)
	if err != nil {
		return nil, err
	}

	multihashCode, err := hashing.GetMultihashCode(deactivateDIDOpts.OperationCommitment)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(publicKey, uint(multihashCode))
	if err != nil {
		return nil, err
	}

	return client.NewDeactivateRequest(&client.DeactivateRequestInfo{
		DidSuffix:   didSuffix,
		RevealValue: rv,
		RecoveryKey: publicKey,
		Signer:      signer,
	})
}

func (c *Client) sendRequest(req []byte, endpointURL string) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, endpointURL+"/operations", bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	if c.authToken != "" {
		httpReq.Header.Add("Authorization", c.authToken)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func createUpdatePatches(updateDIDOpts *update.Opts) ([]patch.Patch, error) {
	var patches []patch.Patch

	if len(updateDIDOpts.RemovePublicKeys) != 0 {
		p, err := createRemovePublicKeysPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	if len(updateDIDOpts.RemoveServices) != 0 {
		p, err := createRemoveServicesPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	if len(updateDIDOpts.AddServices) != 0 {
		p, err := createAddServicesPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	if len(updateDIDOpts.AddPublicKeys) != 0 {
		p, err := createAddPublicKeysPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	return patches, nil
}

func createRemovePublicKeysPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	removePubKeys, err := json.Marshal(updateDIDOpts.RemovePublicKeys)
	if err != nil {
		return nil, err
	}

	return patch.NewRemovePublicKeysPatch(string(removePubKeys))
}

func createRemoveServicesPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	removeServices, err := json.Marshal(updateDIDOpts.RemoveServices)
	if err != nil {
		return nil, err
	}

	return patch.NewRemoveServiceEndpointsPatch(string(removeServices))
}

func createAddServicesPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	addServices, err := json.Marshal(doc.PopulateRawServices(updateDIDOpts.AddServices))
	if err != nil {
		return nil, err
	}

	return patch.NewAddServiceEndpointsPatch(string(addServices))
}

func createAddPublicKeysPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	rawPublicKeys, err := doc.PopulateRawPublicKeys(updateDIDOpts.AddPublicKeys)
	if err != nil {
		return nil, err
	}

	addPublicKeys, err := json.Marshal(rawPublicKeys)
	if err != nil {
		return nil, err
	}

	return patch.NewAddPublicKeysPatch(string(addPublicKeys))
}

func getSigner(signingkey crypto.PrivateKey, keyID string) (client.Signer, *jws.JWK, error) {
	switch key := signingkey.(type) {
	case *ecdsa.PrivateKey:
		updateKey, err := pubkey.GetPublicKeyJWK(key.Public())
		if err != nil {
			return nil, nil, err
		}

		return ecsigner.New(key, "ES256", keyID), updateKey, nil
	case ed25519.PrivateKey:
		updateKey, err := pubkey.GetPublicKeyJWK(key.Public())
		if err != nil {
			return nil, nil, err
		}

		return edsigner.New(key, "EdDSA", keyID), updateKey, nil
	default:
		return nil, nil, fmt.Errorf("key not supported")
	}
}

func getUniqueSuffix(id string) (string, error) {
	p := strings.LastIndex(id, ":")
	if p == -1 {
		return "", fmt.Errorf("unique suffix not provided in id [%s]", id)
	}

	return id[p+1:], nil
}

func getCommitment(multiHashAlgorithm uint, recoverDIDOpts *recovery.Opts) (nextRecoveryCommitment string,
	nextUpdateCommitment string, err error) {
	nextRecoveryKey, err := pubkey.GetPublicKeyJWK(recoverDIDOpts.NextRecoveryPublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to get next recovery key : %s", err)
	}

	nextUpdateKey, err := pubkey.GetPublicKeyJWK(recoverDIDOpts.NextUpdatePublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to get next update key : %s", err)
	}

	nextRecoveryCommitment, err = commitment.GetCommitment(nextRecoveryKey, multiHashAlgorithm)
	if err != nil {
		return "", "", err
	}

	nextUpdateCommitment, err = commitment.GetCommitment(nextUpdateKey, multiHashAlgorithm)
	if err != nil {
		return "", "", err
	}

	return nextRecoveryCommitment, nextUpdateCommitment, nil
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Errorf("Failed to close response body: %v", e)
	}
}
