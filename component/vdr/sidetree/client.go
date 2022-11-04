/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package sidetree implements sidetree client
package sidetree

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/client"

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

type authTokenProvider interface {
	AuthToken() (string, error)
}

// Client sidetree client.
type Client struct {
	client            *http.Client
	authToken         string
	authTokenProvider authTokenProvider
	sendRequest       func(req []byte, getEndpoints func() ([]string, error)) ([]byte, error)
}

// New return sidetree client.
func New(opts ...Option) *Client {
	c := &Client{client: &http.Client{}}

	c.sendRequest = c.defaultSendRequest

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

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

	req, err := buildCreateRequest(createDIDOpts.MultiHashAlgorithm, createDIDOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to build sidetree request: %w", err)
	}

	responseBytes, err := c.sendRequest(req, createDIDOpts.GetEndpoints)
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

	req, err := c.buildUpdateRequest(did, updateDIDOpts.MultiHashAlgorithm, updateDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build update request: %w", err)
	}

	_, err = c.sendRequest(req, updateDIDOpts.GetEndpoints)
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

	req, err := buildRecoverRequest(did, recoverDIDOpts.MultiHashAlgorithm, recoverDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build sidetree request: %w", err)
	}

	_, err = c.sendRequest(req, recoverDIDOpts.GetEndpoints)
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

	req, err := buildDeactivateRequest(did, deactivateDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build sidetree request: %w", err)
	}

	_, err = c.sendRequest(req, deactivateDIDOpts.GetEndpoints)
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

	return nil
}

func validateUpdateReq(updateDIDOpts *update.Opts) error {
	if updateDIDOpts.Signer == nil {
		return fmt.Errorf("signer is required")
	}

	if updateDIDOpts.NextUpdatePublicKey == nil {
		return fmt.Errorf("next update public key is required")
	}

	if updateDIDOpts.OperationCommitment == "" {
		return fmt.Errorf("operation commitment is required")
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

	if recoverDIDOpts.Signer == nil {
		return fmt.Errorf("signer is required")
	}

	if recoverDIDOpts.OperationCommitment == "" {
		return fmt.Errorf("operation commitment is required")
	}

	return nil
}

func validateDeactivateReq(deactivateDIDOpts *deactivate.Opts) error {
	if deactivateDIDOpts.Signer == nil {
		return fmt.Errorf("signer is required")
	}

	if deactivateDIDOpts.OperationCommitment == "" {
		return fmt.Errorf("operation commitment is required")
	}

	return nil
}

// buildCreateRequest request builder for sidetree public DID creation.
func buildCreateRequest(multiHashAlgorithm uint, createDIDOpts *create.Opts) ([]byte, error) {
	didDoc := &doc.Doc{
		PublicKey:   createDIDOpts.PublicKeys,
		Service:     createDIDOpts.Services,
		AlsoKnownAs: createDIDOpts.AlsoKnownAs,
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %w", err)
	}

	recoveryKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.RecoveryPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get recovery key : %w", err)
	}

	updateKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.UpdatePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get update key : %w", err)
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

	if createDIDOpts.AnchorOrigin != "" {
		createRequestInfo.AnchorOrigin = createDIDOpts.AnchorOrigin
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
		return nil, fmt.Errorf("failed to get next update key : %w", err)
	}

	nextUpdateCommitment, err := commitment.GetCommitment(nextUpdateKey, multiHashAlgorithm)
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

	rv, err := commitment.GetRevealValue(updateDIDOpts.Signer.PublicKeyJWK(), uint(multihashCode))
	if err != nil {
		return nil, err
	}

	return client.NewUpdateRequest(&client.UpdateRequestInfo{
		DidSuffix:        didSuffix,
		RevealValue:      rv,
		UpdateCommitment: nextUpdateCommitment,
		UpdateKey:        updateDIDOpts.Signer.PublicKeyJWK(),
		Patches:          patches,
		MultihashCode:    multiHashAlgorithm,
		Signer:           updateDIDOpts.Signer,
	})
}

// buildRecoverRequest request builder for sidetree public DID recovery.
func buildRecoverRequest(did string, multiHashAlgorithm uint, recoverDIDOpts *recovery.Opts) ([]byte, error) {
	didDoc := &doc.Doc{
		PublicKey:   recoverDIDOpts.PublicKeys,
		Service:     recoverDIDOpts.Services,
		AlsoKnownAs: recoverDIDOpts.AlsoKnownAs,
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %w", err)
	}

	nextRecoveryCommitment, nextUpdateCommitment, err := getCommitment(multiHashAlgorithm, recoverDIDOpts)
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

	rv, err := commitment.GetRevealValue(recoverDIDOpts.Signer.PublicKeyJWK(), uint(multihashCode))
	if err != nil {
		return nil, err
	}

	recoverRequestInfo := &client.RecoverRequestInfo{
		DidSuffix: didSuffix, RevealValue: rv, OpaqueDocument: string(docBytes),
		RecoveryCommitment: nextRecoveryCommitment, UpdateCommitment: nextUpdateCommitment,
		MultihashCode: multiHashAlgorithm, Signer: recoverDIDOpts.Signer,
		RecoveryKey: recoverDIDOpts.Signer.PublicKeyJWK(),
	}

	if recoverDIDOpts.AnchorOrigin != "" {
		recoverRequestInfo.AnchorOrigin = recoverDIDOpts.AnchorOrigin
	}

	req, err := client.NewRecoverRequest(recoverRequestInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create sidetree request: %w", err)
	}

	return req, nil
}

// buildDeactivateRequest request builder for sidetree public DID deactivate.
func buildDeactivateRequest(did string, deactivateDIDOpts *deactivate.Opts) ([]byte, error) {
	didSuffix, err := getUniqueSuffix(did)
	if err != nil {
		return nil, err
	}

	multihashCode, err := hashing.GetMultihashCode(deactivateDIDOpts.OperationCommitment)
	if err != nil {
		return nil, err
	}

	rv, err := commitment.GetRevealValue(deactivateDIDOpts.Signer.PublicKeyJWK(), uint(multihashCode))
	if err != nil {
		return nil, err
	}

	return client.NewDeactivateRequest(&client.DeactivateRequestInfo{
		DidSuffix:   didSuffix,
		RevealValue: rv,
		RecoveryKey: deactivateDIDOpts.Signer.PublicKeyJWK(),
		Signer:      deactivateDIDOpts.Signer,
	})
}

func (c *Client) defaultSendRequest(req []byte, getEndpoints func() ([]string, error)) ([]byte, error) {
	if getEndpoints == nil {
		return nil, fmt.Errorf("sidetree get endpoints func is required")
	}

	endpoints, err := getEndpoints()
	if err != nil {
		return nil, fmt.Errorf("sidetree get endpoints: %w", err)
	}

	// TODO add logic for using different sidetree endpoint
	// for now will use the first one
	endpointURL := endpoints[0]

	httpReq, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, endpointURL, bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	authToken := c.authToken

	if c.authTokenProvider != nil {
		v, errToken := c.authTokenProvider.AuthToken()
		if errToken != nil {
			return nil, errToken
		}

		authToken = "Bearer " + v
	}

	if authToken != "" {
		httpReq.Header.Add("Authorization", authToken)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func createUpdatePatches(updateDIDOpts *update.Opts) ([]patch.Patch, error) {
	var patches []patch.Patch

	if len(updateDIDOpts.RemoveAlsoKnownAs) != 0 {
		p, err := createRemoveAlsoKnownAsPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

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

	if len(updateDIDOpts.AddAlsoKnownAs) != 0 {
		p, err := createAddAlsoKnownAsPatch(updateDIDOpts)
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

func createRemoveAlsoKnownAsPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	removeAlsoKnownAs, err := json.Marshal(updateDIDOpts.RemoveAlsoKnownAs)
	if err != nil {
		return nil, err
	}

	return patch.NewRemoveAlsoKnownAs(string(removeAlsoKnownAs))
}

func createAddAlsoKnownAsPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	rawAlsoKnownAs := doc.PopulateRawAlsoKnownAs(updateDIDOpts.AddAlsoKnownAs)

	addAlsoKnownAs, err := json.Marshal(rawAlsoKnownAs)
	if err != nil {
		return nil, err
	}

	return patch.NewAddAlsoKnownAs(string(addAlsoKnownAs))
}

func createAddServicesPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	rawServices, err := doc.PopulateRawServices(updateDIDOpts.AddServices)
	if err != nil {
		return nil, err
	}

	addServices, err := json.Marshal(rawServices)
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
		return "", "", fmt.Errorf("failed to get next recovery key : %w", err)
	}

	nextUpdateKey, err := pubkey.GetPublicKeyJWK(recoverDIDOpts.NextUpdatePublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to get next update key : %w", err)
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
