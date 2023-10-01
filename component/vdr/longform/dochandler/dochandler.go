/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package dochandler performs document operation processing and document resolution.
//
// the supplied create request is used directly to generate and return a resolved document.
// In this case the supplied create request is subject to the same validation as in a create operation.
package dochandler

import (
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-go/pkg/document"
	"github.com/trustbloc/sidetree-go/pkg/docutil"
	"github.com/trustbloc/sidetree-go/pkg/encoder"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocol/nsprovider"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocol/verprovider"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/clientregistry"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/versions/common"
)

const (
	badRequest = "bad request"
	v1         = "1.0"
)

// DocumentHandler implements document handler.
type DocumentHandler struct {
	protocolClient         protocol.Client
	protocolVersions       []string
	currentProtocolVersion string

	namespace string
}

// Option is an option for document handler.
type Option func(opts *DocumentHandler)

// WithProtocolVersions sets optional client protocol versions.
func WithProtocolVersions(versions []string) Option {
	return func(opts *DocumentHandler) {
		opts.protocolVersions = versions
	}
}

// WithCurrentProtocolVersion sets optional current protocol versions.
// Defaults to the latest in the protocol versions list.
func WithCurrentProtocolVersion(version string) Option {
	return func(opts *DocumentHandler) {
		opts.currentProtocolVersion = version
	}
}

// New creates a new document handler with the context.
func New(namespace string, opts ...Option) (*DocumentHandler, error) {
	dh := &DocumentHandler{
		namespace:              namespace,
		protocolVersions:       []string{v1},
		currentProtocolVersion: v1,
	}

	// apply options
	for _, opt := range opts {
		opt(dh)
	}

	pc, err := createProtocolClient(dh.namespace, dh.protocolVersions, dh.currentProtocolVersion)
	if err != nil {
		return nil, err
	}

	dh.protocolClient = pc

	return dh, nil
}

// Namespace returns the namespace of the document handler.
func (r *DocumentHandler) Namespace() string {
	return r.namespace
}

// ProcessOperation validates create operation and returns resolution result of that create operation.
// Only create operation is supported.
func (r *DocumentHandler) ProcessOperation(operationBuffer []byte) (*document.ResolutionResult, error) {
	pv, err := r.protocolClient.Current()
	if err != nil {
		return nil, err
	}

	op, err := pv.OperationParser().Parse(r.namespace, operationBuffer)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	if op.Type != operation.TypeCreate {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	jcsBytes, err := canonicalizer.MarshalCanonical(operationBuffer)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	requestJCS := encoder.EncodeToString(jcsBytes)

	ti := docutil.GetTransformationInfoForUnpublished(r.namespace, "", "", op.UniqueSuffix, requestJCS)

	return r.getCreateResponse(op, ti, pv)
}

func (r *DocumentHandler) getCreateResponse(op *operation.Operation,
	ti protocol.TransformationInfo, pv protocol.Version) (*document.ResolutionResult, error) {
	rm, err := docutil.GetCreateResult(op, pv)
	if err != nil {
		return nil, err
	}

	return pv.DocumentTransformer().TransformDocument(rm, ti)
}

// ResolveDocument resolves long form DID format.
//
// Long Form DID format:
// did:METHOD:<did-suffix>:Base64url(JCS({suffix-data-object, delta-object}))
//
// The <suffix-data-object> and <delta-object> are used to generate and return resolved DID Document.
// In this case the supplied delta and suffix objects are subject to the same validation
// as during processing create operation.
func (r *DocumentHandler) ResolveDocument(longFormDID string,
	_ ...document.ResolutionOption) (*document.ResolutionResult, error) {
	ns, err := r.getNamespace(longFormDID)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	pv, err := r.protocolClient.Current()
	if err != nil {
		return nil, err
	}

	// extract did and initial document value
	shortFormDID, createReq, err := pv.OperationParser().ParseDID(ns, longFormDID)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	if createReq == nil {
		return nil, fmt.Errorf("%s: %s", badRequest, "missing create request")
	}

	uniquePortion, err := getSuffix(shortFormDID)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	return r.resolveRequestWithInitialState(uniquePortion, longFormDID, createReq, pv)
}

func (r *DocumentHandler) getNamespace(shortOrLongFormDID string) (string, error) {
	if strings.HasPrefix(shortOrLongFormDID, r.namespace) {
		return r.namespace, nil
	}

	return "", fmt.Errorf("did must start with configured namespace[%s]", r.namespace)
}

func (r *DocumentHandler) resolveRequestWithInitialState(uniqueSuffix, longFormDID string, initialBytes []byte,
	pv protocol.Version) (*document.ResolutionResult, error) {
	op, err := pv.OperationParser().Parse(r.namespace, initialBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", badRequest, err.Error())
	}

	if uniqueSuffix != op.UniqueSuffix {
		return nil, fmt.Errorf("%s: provided did doesn't match did created from initial state", badRequest)
	}

	createRequestJCS := longFormDID[strings.LastIndex(longFormDID, docutil.NamespaceDelimiter)+1:]
	ti := docutil.GetTransformationInfoForUnpublished(r.namespace, "", "", uniqueSuffix, createRequestJCS)

	return r.getCreateResponse(op, ti, pv)
}

// getSuffix returns suffix from short form DID.
func getSuffix(shortFormDID string) (string, error) {
	parts := strings.Split(shortFormDID, docutil.NamespaceDelimiter)

	const minParts = 3
	if len(parts) < minParts {
		return "", fmt.Errorf("invalid number of parts[%d] for DID identifier", len(parts))
	}

	// suffix is always the last part
	suffix := parts[len(parts)-1]

	return suffix, nil
}

func createProtocolClient(namespace string, versions []string, currentVersion string) (protocol.Client, error) {
	registry := clientregistry.New()

	var clientVersions []protocol.Version

	config := &common.ProtocolConfig{EnableBase: true}

	for _, version := range versions {
		cv, err := registry.CreateClientVersion(version, config)
		if err != nil {
			return nil, fmt.Errorf("error creating client version [%s]: %w", version, err)
		}

		clientVersions = append(clientVersions, cv)
	}

	verProvider, err := verprovider.New(clientVersions, verprovider.WithCurrentProtocolVersion(currentVersion))
	if err != nil {
		return nil, fmt.Errorf("failed to create version provider: %w", err)
	}

	nsProvider := nsprovider.New()
	nsProvider.Add(namespace, verProvider)

	return nsProvider.ForNamespace(namespace)
}
