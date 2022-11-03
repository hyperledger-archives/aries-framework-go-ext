/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package longform implement long-form vdr
package longform

import (
	"crypto"
	"encoding/json"
	"fmt"

	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/create"
)

const (
	// UpdatePublicKeyOpt update public key opt.
	UpdatePublicKeyOpt = "updatePublicKey"
	// RecoveryPublicKeyOpt recovery public key opt.
	RecoveryPublicKeyOpt = "recoveryPublicKey"

	sha2_256         = 18
	defaultDIDMethod = "did:ion"
)

type sidetreeClient interface {
	CreateDID(opts ...create.Option) (*docdid.DocResolution, error)
}

// VDR bloc.
type VDR struct {
	method string

	sidetreeDocHandler sidetreeDocumentHandler
	sidetreeClient     sidetreeClient

	documentLoader jsonld.DocumentLoader
}

type sidetreeDocumentHandler interface {
	ResolveDocument(longFormDID string, opts ...document.ResolutionOption) (*document.ResolutionResult, error)
	ProcessOperation(operationBuffer []byte) (*document.ResolutionResult, error)
}

// New creates new long form VDR.
func New(opts ...Option) (*VDR, error) {
	v := &VDR{method: defaultDIDMethod}

	for _, opt := range opts {
		opt(v)
	}

	if v.documentLoader == nil {
		l, err := createJSONLDDocumentLoader()
		if err != nil {
			return nil, fmt.Errorf("failed to init default jsonld document loader: %w", err)
		}

		v.documentLoader = l
	}

	var err error

	v.sidetreeDocHandler, err = dochandler.New(v.method)
	if err != nil {
		return nil, err
	}

	v.sidetreeClient = sidetree.New(sidetree.WithSidetreeOperationRequestFnc(v.sendRequest))

	return v, nil
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

func createJSONLDDocumentLoader() (jsonld.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	documentLoader, err := ld.NewDocumentLoader(ldStore)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return documentLoader, nil
}

// Accept did method.
func (v *VDR) Accept(method string) bool {
	return method == v.method
}

// Close vdr.
func (v *VDR) Close() error {
	return nil
}

// Create did doc.
func (v *VDR) Create(did *docdid.Doc,
	opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	createOpt := make([]create.Option, 0)

	// get keys
	if didMethodOpts.Values[UpdatePublicKeyOpt] == nil {
		return nil, fmt.Errorf("updatePublicKey opt is empty")
	}

	updatePublicKey, ok := didMethodOpts.Values[UpdatePublicKeyOpt].(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("upatePublicKey is not  crypto.PublicKey")
	}

	if didMethodOpts.Values[RecoveryPublicKeyOpt] == nil {
		return nil, fmt.Errorf("recoveryPublicKey opt is empty")
	}

	recoveryPublicKey, ok := didMethodOpts.Values[RecoveryPublicKeyOpt].(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("recoveryPublicKey is not  crypto.PublicKey")
	}

	// get also known as
	for i := range did.AlsoKnownAs {
		createOpt = append(createOpt, create.WithAlsoKnownAs(did.AlsoKnownAs[i]))
	}

	// get services
	for i := range did.Service {
		createOpt = append(createOpt, create.WithService(&did.Service[i]))
	}

	// get verification method
	pks, err := getSidetreePublicKeys(did)
	if err != nil {
		return nil, err
	}

	for k := range pks {
		createOpt = append(createOpt, create.WithPublicKey(pks[k].publicKey))
	}

	createOpt = append(createOpt,
		create.WithMultiHashAlgorithm(sha2_256),
		create.WithUpdatePublicKey(updatePublicKey),
		create.WithRecoveryPublicKey(recoveryPublicKey))

	createdDID, err := v.sidetreeClient.CreateDID(createOpt...)
	if err != nil {
		return nil, err
	}

	return createdDID, nil
}

// Read long-form DID.
func (v *VDR) Read(longFormDID string, _ ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	resolutionResult, err := v.sidetreeDocHandler.ResolveDocument(longFormDID)
	if err != nil {
		return nil, err
	}

	resolutionResultBytes, err := json.Marshal(resolutionResult)
	if err != nil {
		return nil, err
	}

	documentResolution, err := docdid.ParseDocumentResolution(resolutionResultBytes)
	if err != nil {
		return nil, err
	}

	return &docdid.DocResolution{
		DIDDocument:      documentResolution.DIDDocument,
		DocumentMetadata: documentResolution.DocumentMetadata,
		Context:          documentResolution.Context,
	}, nil
}

// Update did doc.
func (v *VDR) Update(_ *docdid.Doc, _ ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not implemented")
}

// Deactivate did doc.
func (v *VDR) Deactivate(_ string, _ ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not implemented")
}

func (v *VDR) sendRequest(req []byte, _ func() ([]string, error)) ([]byte, error) {
	didResolution, err := v.sidetreeDocHandler.ProcessOperation(req)
	if err != nil {
		return nil, err
	}

	return json.Marshal(didResolution)
}

type pk struct {
	value     []byte
	publicKey *doc.PublicKey
}

func getSidetreePublicKeys(didDoc *docdid.Doc) (map[string]*pk, error) {
	pksMap := make(map[string]*pk)

	ver := make([]docdid.Verification, 0)

	ver = append(ver, didDoc.Authentication...)
	ver = append(ver, didDoc.AssertionMethod...)
	ver = append(ver, didDoc.CapabilityDelegation...)
	ver = append(ver, didDoc.CapabilityInvocation...)
	ver = append(ver, didDoc.KeyAgreement...)

	for _, v := range ver {
		var purpose string

		switch v.Relationship { //nolint: exhaustive
		case docdid.Authentication:
			purpose = doc.KeyPurposeAuthentication
		case docdid.AssertionMethod:
			purpose = doc.KeyPurposeAssertionMethod
		case docdid.CapabilityDelegation:
			purpose = doc.KeyPurposeCapabilityDelegation
		case docdid.CapabilityInvocation:
			purpose = doc.KeyPurposeCapabilityInvocation
		case docdid.KeyAgreement:
			purpose = doc.KeyPurposeKeyAgreement
		default:
			return nil, fmt.Errorf("vm relationship %d not supported", v.Relationship)
		}

		s := strings.Split(v.VerificationMethod.ID, "#")

		id := s[0]
		if len(s) > 1 {
			id = s[1]
		}

		value, ok := pksMap[id]
		if ok {
			value.publicKey.Purposes = append(value.publicKey.Purposes, purpose)

			continue
		}

		switch {
		case v.VerificationMethod.JSONWebKey() != nil:
			pksMap[id] = &pk{
				publicKey: &doc.PublicKey{
					ID:       id,
					Type:     v.VerificationMethod.Type,
					Purposes: []string{purpose},
					JWK:      *v.VerificationMethod.JSONWebKey(),
				},
				value: v.VerificationMethod.Value,
			}
		case v.VerificationMethod.Value != nil:
			pksMap[id] = &pk{
				publicKey: &doc.PublicKey{
					ID:       id,
					Type:     v.VerificationMethod.Type,
					Purposes: []string{purpose},
					B58Key:   base58.Encode(v.VerificationMethod.Value),
				},
				value: v.VerificationMethod.Value,
			}
		default:
			return nil, fmt.Errorf("verificationMethod needs either JSONWebKey or Base58 key")
		}
	}

	return pksMap, nil
}

// Option configures the long-form vdr.
type Option func(opts *VDR)

// WithDocumentLoader overrides the default JSONLD document loader used when processing JSONLD DID Documents.
func WithDocumentLoader(l jsonld.DocumentLoader) Option {
	return func(opts *VDR) {
		opts.documentLoader = l
	}
}

// WithDIDMethod overrides the default did method.
func WithDIDMethod(method string) Option {
	return func(opts *VDR) {
		opts.method = method
	}
}
