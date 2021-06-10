/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package orb implement orb vdr
//
package orb

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/config"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/models"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/create"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/deactivate"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/recovery"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/update"
)

const (
	// DIDMethod did method.
	DIDMethod = "orb"
	// OperationEndpointsOpt operation endpoints opt.
	OperationEndpointsOpt = "operationEndpoints"
	// ResolutionEndpointsOpt resolution endpoints opt.
	ResolutionEndpointsOpt = "resolutionEndpointsOpt"
	// UpdatePublicKeyOpt update public key opt.
	UpdatePublicKeyOpt = "updatePublicKey"
	// RecoveryPublicKeyOpt recovery public key opt.
	RecoveryPublicKeyOpt = "recoveryPublicKey"
	// RecoverOpt recover opt.
	RecoverOpt = "recover"
	// AnchorOriginOpt anchor origin opt.
	AnchorOriginOpt = "anchorOrigin"
)

var logger = log.New("aries-framework-ext/vdr/orb") //nolint: gochecknoglobals

// OperationType operation type.
type OperationType int

const (
	// Update operation.
	Update OperationType = iota
	// Recover operation.
	Recover
)

type sidetreeClient interface {
	CreateDID(opts ...create.Option) (*docdid.DocResolution, error)
	UpdateDID(didID string, opts ...update.Option) error
	RecoverDID(did string, opts ...recovery.Option) error
	DeactivateDID(did string, opts ...deactivate.Option) error
}

type vdr interface {
	Read(id string, opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error)
}

type configService interface {
	GetSidetreeConfig() (*models.SidetreeConfig, error)
	GetEndpoint(domain string) (*models.Endpoint, error)
	GetEndpointFromIPNS(did string) (*models.Endpoint, error)
}

// VDR bloc.
type VDR struct {
	getHTTPVDR     func(url string) (vdr, error) // needed for unit test
	tlsConfig      *tls.Config
	authToken      string
	domain         string
	sidetreeClient sidetreeClient
	keyRetriever   KeyRetriever
	configService  configService
	docLoader      ld.DocumentLoader
}

// KeyRetriever key retriever.
type KeyRetriever interface {
	GetNextRecoveryPublicKey(didID string) (crypto.PublicKey, error)
	GetNextUpdatePublicKey(didID string) (crypto.PublicKey, error)
	GetSigningKey(didID string, ot OperationType) (crypto.PrivateKey, error)
}

// New creates new orb VDR.
func New(keyRetriever KeyRetriever, opts ...Option) (*VDR, error) {
	v := &VDR{}

	for _, opt := range opts {
		opt(v)
	}

	if v.docLoader == nil {
		l, err := jld.NewDocumentLoader(mem.NewProvider())
		if err != nil {
			return nil, fmt.Errorf("failed to init default jsonld document loader: %w", err)
		}

		v.docLoader = l
	}

	v.sidetreeClient = sidetree.New(sidetree.WithAuthToken(v.authToken), sidetree.WithTLSConfig(v.tlsConfig))

	v.getHTTPVDR = func(url string) (vdr, error) {
		return httpbinding.New(url,
			httpbinding.WithTLSConfig(v.tlsConfig), httpbinding.WithResolveAuthToken(v.authToken))
	}

	v.keyRetriever = keyRetriever

	var err error

	v.configService, err = config.NewService(v.docLoader, config.WithHTTPClient(&http.Client{
		Transport: &http.Transport{TLSClientConfig: v.tlsConfig},
	}))
	if err != nil {
		return nil, err
	}

	return v, nil
}

// Accept did method.
func (v *VDR) Accept(method string) bool {
	return method == DIDMethod
}

// Close vdr.
func (v *VDR) Close() error {
	return nil
}

// Create did doc.
// nolint: funlen,gocyclo
func (v *VDR) Create(did *docdid.Doc,
	opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	createOpt := make([]create.Option, 0)

	getEndpoints := v.getSidetreeOperationEndpoints(didMethodOpts)

	sidetreeConfig, err := v.configService.GetSidetreeConfig()
	if err != nil {
		return nil, err
	}

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

	if didMethodOpts.Values[AnchorOriginOpt] == nil {
		return nil, fmt.Errorf("anchorOrigin opt is empty")
	}

	anchorOrigin, ok := didMethodOpts.Values[AnchorOriginOpt].(string)
	if !ok {
		return nil, fmt.Errorf("anchorOrigin is not string")
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
		createOpt = append(createOpt, create.WithPublicKey(pks[k]))
	}

	createOpt = append(createOpt, create.WithSidetreeEndpoint(getEndpoints), create.WithAnchorOrigin(anchorOrigin),
		create.WithMultiHashAlgorithm(sidetreeConfig.MultiHashAlgorithm), create.WithUpdatePublicKey(updatePublicKey),
		create.WithRecoveryPublicKey(recoveryPublicKey))

	return v.sidetreeClient.CreateDID(createOpt...)
}

func (v *VDR) Read(did string, opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) { //nolint: funlen,gocyclo
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	if didMethodOpts.Values[ResolutionEndpointsOpt] != nil {
		endpoints, ok := didMethodOpts.Values[ResolutionEndpointsOpt].([]string)
		if !ok {
			return nil, fmt.Errorf("resolutionEndpointsOpt not array of string")
		}

		return v.sidetreeResolve(endpoints[0], did, opts...)
	}

	var endpoint *models.Endpoint

	var err error

	switch {
	case v.domain != "":
		endpoint, err = v.configService.GetEndpoint(v.domain)
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}
	case strings.Contains(did, fmt.Sprintf("%s:ipfs", DIDMethod)):
		endpoint, err = v.configService.GetEndpointFromIPNS(did)
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}
	default:
		return nil, fmt.Errorf("failed to get endpoints domain is empty and did not ipfs")
	}

	var docResolution *docdid.DocResolution

	var docBytes []byte

	minResolver := 0

	// Resolve the DID at each of the n chosen links.
	// Ensure that the DID resolution result matches (other than resolver-specific metadata such as timestamps).
	// In case of a mismatch, additional links may need to be chosen until the client has n matches.

	for _, e := range endpoint.ResolutionEndpoints {
		resp, err := v.sidetreeResolve(e, did, opts...)
		if err != nil {
			return nil, err
		}

		respBytes, err := canonicalizeDoc(resp.DIDDocument, v.docLoader)
		if err != nil {
			return nil, fmt.Errorf("cannot canonicalize resolved doc: %w", err)
		}

		if docResolution != nil && !bytes.Equal(docBytes, respBytes) {
			logger.Warnf("mismatch in document contents for did %s. Doc 1: %s, Doc 2: %s",
				did, string(docBytes), string(respBytes))

			continue
		}

		minResolver++

		docResolution = resp

		docBytes = respBytes

		if minResolver == endpoint.MinResolvers {
			break
		}
	}

	if minResolver != endpoint.MinResolvers {
		return nil, fmt.Errorf("failed to fetch correct did from min resolvers")
	}

	return docResolution, nil
}

// Update did doc.
func (v *VDR) Update(didDoc *docdid.Doc, opts ...vdrapi.DIDMethodOption) error { //nolint:funlen,gocyclo
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	updateOpt := make([]update.Option, 0)

	sidetreeConfig, err := v.configService.GetSidetreeConfig()
	if err != nil {
		return err
	}

	docResolution, err := v.Read(didDoc.ID, opts...)
	if err != nil {
		return err
	}

	// check recover option
	if didMethodOpts.Values[RecoverOpt] != nil {
		if didMethodOpts.Values[AnchorOriginOpt] == nil {
			return fmt.Errorf("anchorOrigin opt is empty")
		}

		anchorOrigin, ok := didMethodOpts.Values[AnchorOriginOpt].(string)
		if !ok {
			return fmt.Errorf("anchorOrigin is not string")
		}

		return v.recover(didDoc, sidetreeConfig, v.getSidetreeOperationEndpoints(didMethodOpts),
			docResolution.DocumentMetadata.Method.RecoveryCommitment, anchorOrigin)
	}

	// get services
	for i := range didDoc.Service {
		updateOpt = append(updateOpt, update.WithAddService(&didDoc.Service[i]))
	}

	updateOpt = append(updateOpt, getRemovedSvcKeysID(docResolution.DIDDocument.Service, didDoc.Service)...)

	// get verification method
	pks, err := getSidetreePublicKeys(didDoc)
	if err != nil {
		return err
	}

	for k := range pks {
		updateOpt = append(updateOpt, update.WithAddPublicKey(pks[k]))
	}

	// get keys
	nextUpdatePublicKey, err := v.keyRetriever.GetNextUpdatePublicKey(didDoc.ID)
	if err != nil {
		return err
	}

	updateSigningKey, err := v.keyRetriever.GetSigningKey(didDoc.ID, Update)
	if err != nil {
		return err
	}

	updateOpt = append(updateOpt, getRemovedPKKeysID(docResolution.DIDDocument.VerificationMethod,
		didDoc.VerificationMethod)...)

	updateOpt = append(updateOpt, update.WithSidetreeEndpoint(v.getSidetreeOperationEndpoints(didMethodOpts)),
		update.WithNextUpdatePublicKey(nextUpdatePublicKey),
		update.WithMultiHashAlgorithm(sidetreeConfig.MultiHashAlgorithm),
		update.WithSigningKey(updateSigningKey),
		update.WithOperationCommitment(docResolution.DocumentMetadata.Method.UpdateCommitment))

	return v.sidetreeClient.UpdateDID(didDoc.ID, updateOpt...)
}

func (v *VDR) recover(didDoc *docdid.Doc, sidetreeConfig *models.SidetreeConfig,
	getEndpoints func() ([]string, error), recoveryCommitment, anchorOrigin string) error {
	recoveryOpt := make([]recovery.Option, 0)

	// get services
	for i := range didDoc.Service {
		recoveryOpt = append(recoveryOpt, recovery.WithService(&didDoc.Service[i]))
	}

	// get verification method
	pks, err := getSidetreePublicKeys(didDoc)
	if err != nil {
		return err
	}

	for k := range pks {
		recoveryOpt = append(recoveryOpt, recovery.WithPublicKey(pks[k]))
	}

	// get keys
	nextUpdatePublicKey, err := v.keyRetriever.GetNextUpdatePublicKey(didDoc.ID)
	if err != nil {
		return err
	}

	nextRecoveryPublicKey, err := v.keyRetriever.GetNextRecoveryPublicKey(didDoc.ID)
	if err != nil {
		return err
	}

	updateSigningKey, err := v.keyRetriever.GetSigningKey(didDoc.ID, Recover)
	if err != nil {
		return err
	}

	recoveryOpt = append(recoveryOpt, recovery.WithSidetreeEndpoint(getEndpoints),
		recovery.WithNextUpdatePublicKey(nextUpdatePublicKey),
		recovery.WithNextRecoveryPublicKey(nextRecoveryPublicKey),
		recovery.WithMultiHashAlgorithm(sidetreeConfig.MultiHashAlgorithm),
		recovery.WithSigningKey(updateSigningKey),
		recovery.WithOperationCommitment(recoveryCommitment),
		recovery.WithAnchorOrigin(anchorOrigin))

	return v.sidetreeClient.RecoverDID(didDoc.ID, recoveryOpt...)
}

// Deactivate did doc.
func (v *VDR) Deactivate(didID string, opts ...vdrapi.DIDMethodOption) error {
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	var deactivateOpt []deactivate.Option

	docResolution, err := v.Read(didID, opts...)
	if err != nil {
		return err
	}

	signingKey, err := v.keyRetriever.GetSigningKey(didID, Recover)
	if err != nil {
		return err
	}

	deactivateOpt = append(deactivateOpt, deactivate.WithSidetreeEndpoint(v.getSidetreeOperationEndpoints(didMethodOpts)),
		deactivate.WithSigningKey(signingKey),
		deactivate.WithOperationCommitment(docResolution.DocumentMetadata.Method.RecoveryCommitment))

	return v.sidetreeClient.DeactivateDID(didID, deactivateOpt...)
}

func getSidetreePublicKeys(didDoc *docdid.Doc) (map[string]*doc.PublicKey, error) {
	pksMap := make(map[string]*doc.PublicKey)

	if len(didDoc.VerificationMethod) > 0 {
		return nil,
			fmt.Errorf("verificationMethod not supported use other verificationMethod like Authentication")
	}

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

		value, ok := pksMap[v.VerificationMethod.ID]
		if ok {
			value.Purposes = append(value.Purposes, purpose)

			continue
		}

		if v.VerificationMethod.JSONWebKey() == nil {
			return nil, fmt.Errorf("verificationMethod JSONWebKey is nil")
		}

		pksMap[v.VerificationMethod.ID] = &doc.PublicKey{
			ID:       v.VerificationMethod.ID,
			Type:     v.VerificationMethod.Type,
			Purposes: []string{purpose},
			JWK:      *v.VerificationMethod.JSONWebKey(),
		}
	}

	return pksMap, nil
}

func (v *VDR) getSidetreeOperationEndpoints(didMethodOpts *vdrapi.DIDMethodOpts) func() ([]string, error) {
	if didMethodOpts.Values[OperationEndpointsOpt] == nil {
		return func() ([]string, error) {
			endpoint, err := v.configService.GetEndpoint(v.domain)
			if err != nil {
				return nil, fmt.Errorf("failed to get endpoints: %w", err)
			}

			return endpoint.OperationEndpoints, nil
		}
	}

	return func() ([]string, error) {
		v, ok := didMethodOpts.Values[OperationEndpointsOpt].([]string)
		if !ok {
			return nil, fmt.Errorf("operationEndpointsOpt not array of string")
		}

		return v, nil
	}
}

func getRemovedSvcKeysID(currentService, updatedService []docdid.Service) []update.Option {
	var updateOpt []update.Option

	for i := range currentService {
		exist := false

		for u := range updatedService {
			if currentService[i].ID == updatedService[u].ID {
				exist = true

				break
			}
		}

		if !exist {
			s := strings.Split(currentService[i].ID, "#")

			id := s[0]
			if len(s) > 1 {
				id = s[1]
			}

			updateOpt = append(updateOpt, update.WithRemoveService(id))
		}
	}

	return updateOpt
}

func getRemovedPKKeysID(currentVM, updatedVM []docdid.VerificationMethod) []update.Option {
	var updateOpt []update.Option

	for _, curr := range currentVM {
		exist := false

		for _, updated := range updatedVM {
			if curr.ID == updated.ID {
				exist = true

				break
			}
		}

		if !exist {
			s := strings.Split(curr.ID, "#")

			id := s[0]
			if len(s) > 1 {
				id = s[1]
			}

			updateOpt = append(updateOpt, update.WithRemovePublicKey(id))
		}
	}

	return updateOpt
}

func (v *VDR) sidetreeResolve(url, did string, opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	resolver, err := v.getHTTPVDR(url)
	if err != nil {
		return nil, fmt.Errorf("failed to create new sidetree vdr: %w", err)
	}

	docResolution, err := resolver.Read(did, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve did: %w", err)
	}

	return docResolution, nil
}

// canonicalizeDoc canonicalizes a DID doc using json-ld canonicalization.
func canonicalizeDoc(didDoc *docdid.Doc, docLoader ld.DocumentLoader) ([]byte, error) {
	marshaled, err := didDoc.JSONBytes()
	if err != nil {
		return nil, err
	}

	docMap := map[string]interface{}{}

	err = json.Unmarshal(marshaled, &docMap)
	if err != nil {
		return nil, err
	}

	proc := jsonld.Default()

	return proc.GetCanonicalDocument(docMap, jsonld.WithDocumentLoader(docLoader))
}

// Option configures the bloc vdr.
type Option func(opts *VDR)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *VDR) {
		opts.tlsConfig = tlsConfig
	}
}

// WithAuthToken add auth token.
func WithAuthToken(authToken string) Option {
	return func(opts *VDR) {
		opts.authToken = authToken
	}
}

// WithDomain option is setting domain.
func WithDomain(domain string) Option {
	return func(opts *VDR) {
		opts.domain = domain
	}
}

// WithDocumentLoader overrides the default JSONLD document loader used when processing JSONLD DID Documents.
func WithDocumentLoader(l ld.DocumentLoader) Option {
	return func(opts *VDR) {
		opts.docLoader = l
	}
}
