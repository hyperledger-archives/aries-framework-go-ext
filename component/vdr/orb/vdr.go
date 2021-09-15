/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package orb implement orb vdr
//
package orb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/hashlink"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/internal/ldcontext"
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
	httpTimeOut     = 20 * time.Second
	sha2_256        = 18 // multihash
	ipfsGlobal      = "https://ipfs.io"
	ipfsPrefix      = "ipfs://"
	httpsProtocol   = "https"
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

type discoveryService interface {
	GetEndpoint(domain string) (*models.Endpoint, error)
	GetEndpointFromAnchorOrigin(did string) (*models.Endpoint, error)
}

// VDR bloc.
type VDR struct {
	getHTTPVDR        func(url string) (vdr, error) // needed for unit test
	tlsConfig         *tls.Config
	authToken         string
	domain            string
	disableProofCheck bool
	sidetreeClient    sidetreeClient
	keyRetriever      KeyRetriever
	discoveryService  discoveryService
	documentLoader    jsonld.DocumentLoader
	ipfsEndpoint      string
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

	if v.documentLoader == nil {
		l, err := createJSONLDDocumentLoader()
		if err != nil {
			return nil, fmt.Errorf("failed to init default jsonld document loader: %w", err)
		}

		v.documentLoader = l
	}

	v.sidetreeClient = sidetree.New(sidetree.WithAuthToken(v.authToken), sidetree.WithTLSConfig(v.tlsConfig))

	v.getHTTPVDR = func(url string) (vdr, error) {
		return httpbinding.New(url,
			httpbinding.WithTLSConfig(v.tlsConfig), httpbinding.WithResolveAuthToken(v.authToken),
			httpbinding.WithTimeout(httpTimeOut))
	}

	v.keyRetriever = keyRetriever

	var err error

	c := &http.Client{
		Transport: &http.Transport{TLSClientConfig: v.tlsConfig},
	}

	v.discoveryService, err = client.New(v.documentLoader, &casReader{
		httpClient:   c,
		hl:           hashlink.New(),
		ipfsEndpoint: v.ipfsEndpoint,
	},
		client.WithDisableProofCheck(v.disableProofCheck), client.WithHTTPClient(c))
	if err != nil {
		return nil, err
	}

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

	defaultContexts, err := ldcontext.GetAll()
	if err != nil {
		return nil, err
	}

	documentLoader, err := ld.NewDocumentLoader(ldStore, ld.WithExtraContexts(defaultContexts...))
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return documentLoader, nil
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
// nolint: gocyclo
func (v *VDR) Create(did *docdid.Doc,
	opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	createOpt := make([]create.Option, 0)

	getEndpoints := v.getSidetreeOperationEndpoints(didMethodOpts)

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
		createOpt = append(createOpt, create.WithPublicKey(pks[k].publicKey))
	}

	createOpt = append(createOpt, create.WithSidetreeEndpoint(getEndpoints), create.WithAnchorOrigin(anchorOrigin),
		create.WithMultiHashAlgorithm(sha2_256), create.WithUpdatePublicKey(updatePublicKey),
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
	case strings.HasPrefix(did, fmt.Sprintf("did:%s:%s", DIDMethod, httpsProtocol)):
		hintDomain := strings.Split(did, ":")[3]

		endpoint, err = v.discoveryService.GetEndpoint(fmt.Sprintf("%s://%s", httpsProtocol, hintDomain))
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}

		for _, e := range endpoint.ResolutionEndpoints {
			if strings.Contains(e, hintDomain) {
				return v.sidetreeResolve(e, did, opts...)
			}
		}

		return nil, fmt.Errorf("discovery did not return hint domain")
	case v.domain != "":
		endpoint, err = v.discoveryService.GetEndpoint(v.domain)
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}
	default:
		endpoint, err = v.discoveryService.GetEndpointFromAnchorOrigin(did)
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}
	}

	// TODO this temp solution to resolve update DID from cache
	if len(endpoint.ResolutionEndpoints) > 1 {
		return nil, fmt.Errorf("multiple resolutionEndpoints not supported")
	}

	resp, err := v.sidetreeResolve(endpoint.ResolutionEndpoints[0], did, opts...)
	if err != nil {
		return nil, err
	}

	if v.domain != "" && resp.DocumentMetadata.Method.Published &&
		resp.DocumentMetadata.Method.AnchorOrigin != "" &&
		!strings.Contains(resp.DocumentMetadata.Method.AnchorOrigin, "ipns") &&
		resp.DocumentMetadata.Method.AnchorOrigin != v.domain {
		endpoint, err = v.discoveryService.GetEndpoint(resp.DocumentMetadata.Method.AnchorOrigin)
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}

		if len(endpoint.ResolutionEndpoints) > 1 {
			return nil, fmt.Errorf("multiple resolutionEndpoints not supported")
		}

		return v.sidetreeResolve(endpoint.ResolutionEndpoints[0], did, opts...)
	}

	return resp, nil
}

// Update did doc.
func (v *VDR) Update(didDoc *docdid.Doc, opts ...vdrapi.DIDMethodOption) error { //nolint:funlen,gocyclo
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	updateOpt := make([]update.Option, 0)

	docResolution, err := v.Read(didDoc.ID, opts...)
	if err != nil {
		return err
	}

	if !docResolution.DocumentMetadata.Method.Published {
		return fmt.Errorf("did is not published can't update")
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

		return v.recover(didDoc, v.getSidetreeOperationEndpoints(didMethodOpts),
			docResolution.DocumentMetadata.Method.RecoveryCommitment, anchorOrigin)
	}

	// get services
	for i := range didDoc.Service {
		updateOpt = append(updateOpt, update.WithAddService(&didDoc.Service[i]))
	}

	updateOpt = append(updateOpt, getRemovedSvcKeysID(docResolution.DIDDocument.Service, didDoc.Service)...)

	// get keys
	nextUpdatePublicKey, err := v.keyRetriever.GetNextUpdatePublicKey(didDoc.ID)
	if err != nil {
		return err
	}

	updateSigningKey, err := v.keyRetriever.GetSigningKey(didDoc.ID, Update)
	if err != nil {
		return err
	}

	updatedPKKeysID, err := getUpdatedPKKeysID(docResolution.DIDDocument, didDoc)
	if err != nil {
		return err
	}

	updateOpt = append(updateOpt, updatedPKKeysID...)

	updateOpt = append(updateOpt, update.WithSidetreeEndpoint(func() ([]string, error) {
		// TODO make sure it's latest anchor origin
		endpoint, err := v.discoveryService.GetEndpoint(docResolution.DocumentMetadata.Method.AnchorOrigin)
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}

		return endpoint.OperationEndpoints, nil
	}),
		update.WithNextUpdatePublicKey(nextUpdatePublicKey),
		update.WithMultiHashAlgorithm(sha2_256),
		update.WithSigningKey(updateSigningKey),
		update.WithOperationCommitment(docResolution.DocumentMetadata.Method.UpdateCommitment))

	return v.sidetreeClient.UpdateDID(didDoc.ID, updateOpt...)
}

func (v *VDR) recover(didDoc *docdid.Doc, getEndpoints func() ([]string, error),
	recoveryCommitment, anchorOrigin string) error {
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
		recoveryOpt = append(recoveryOpt, recovery.WithPublicKey(pks[k].publicKey))
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
		recovery.WithMultiHashAlgorithm(sha2_256),
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

type pk struct {
	value     []byte
	publicKey *doc.PublicKey
}

func getSidetreePublicKeys(didDoc *docdid.Doc) (map[string]*pk, error) { // nolint:funlen
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

		value, ok := pksMap[v.VerificationMethod.ID]
		if ok {
			value.publicKey.Purposes = append(value.publicKey.Purposes, purpose)

			continue
		}

		switch {
		case v.VerificationMethod.JSONWebKey() != nil:
			pksMap[v.VerificationMethod.ID] = &pk{
				publicKey: &doc.PublicKey{
					ID:       v.VerificationMethod.ID,
					Type:     v.VerificationMethod.Type,
					Purposes: []string{purpose},
					JWK:      *v.VerificationMethod.JSONWebKey(),
				},
				value: v.VerificationMethod.Value,
			}
		case v.VerificationMethod.Value != nil:
			pksMap[v.VerificationMethod.ID] = &pk{
				publicKey: &doc.PublicKey{
					ID:       v.VerificationMethod.ID,
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

func (v *VDR) getSidetreeOperationEndpoints(didMethodOpts *vdrapi.DIDMethodOpts) func() ([]string, error) {
	if didMethodOpts.Values[OperationEndpointsOpt] == nil {
		return func() ([]string, error) {
			endpoint, err := v.discoveryService.GetEndpoint(v.domain)
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
			if strings.Contains(currentService[i].ID, updatedService[u].ID) {
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

func getUpdatedPKKeysID(currentDID, updatedDID *docdid.Doc) ([]update.Option, error) { //nolint:gocognit,gocyclo
	var updateOpt []update.Option

	existKeys := make(map[string]struct{})

	currentPKS, err := getSidetreePublicKeys(currentDID)
	if err != nil {
		return nil, err
	}

	updatedPKS, err := getSidetreePublicKeys(updatedDID)
	if err != nil {
		return nil, err
	}

	for _, currPK := range currentPKS {
		exist := false

		for _, updatedPK := range updatedPKS {
			if strings.Contains(currPK.publicKey.ID, updatedPK.publicKey.ID) {
				if len(currPK.publicKey.Purposes) == len(updatedPK.publicKey.Purposes) {
					currPKPurposesMap := make(map[string]struct{})
					for _, v := range currPK.publicKey.Purposes {
						currPKPurposesMap[v] = struct{}{}
					}

					for _, v := range updatedPK.publicKey.Purposes {
						delete(currPKPurposesMap, v)
					}

					if bytes.Equal(currPK.value, updatedPK.value) && len(currPKPurposesMap) == 0 {
						existKeys[updatedPK.publicKey.ID] = struct{}{}
					}
				}

				exist = true

				break
			}
		}

		if !exist {
			s := strings.Split(currPK.publicKey.ID, "#")

			id := s[0]
			if len(s) > 1 {
				id = s[1]
			}

			updateOpt = append(updateOpt, update.WithRemovePublicKey(id))
		}
	}

	for k := range updatedPKS {
		if _, ok := existKeys[k]; !ok {
			updateOpt = append(updateOpt, update.WithAddPublicKey(updatedPKS[k].publicKey))
		}
	}

	return updateOpt, nil
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

// WithDisableProofCheck disable proof check.
func WithDisableProofCheck(disable bool) Option {
	return func(opts *VDR) {
		opts.disableProofCheck = disable
	}
}

// WithDocumentLoader overrides the default JSONLD document loader used when processing JSONLD DID Documents.
func WithDocumentLoader(l jsonld.DocumentLoader) Option {
	return func(opts *VDR) {
		opts.documentLoader = l
	}
}

// WithIPFSEndpoint overrides the global ipfs endpoint.
func WithIPFSEndpoint(endpoint string) Option {
	return func(opts *VDR) {
		opts.ipfsEndpoint = endpoint
	}
}

// casReader.
type casReader struct {
	httpClient   *http.Client
	hl           *hashlink.HashLink
	ipfsEndpoint string
}

func (c *casReader) Read(cidWithPossibleHint string) ([]byte, error) {
	links, err := c.getResourceHashWithPossibleLinks(cidWithPossibleHint)
	if err != nil {
		return nil, err
	}

	ipfsLinks, err := separateLinks(links)
	if err != nil {
		return nil, err
	}

	cid := ipfsLinks[0][len(ipfsPrefix):]

	if c.ipfsEndpoint != "" {
		return send(c.httpClient, nil, http.MethodPost, fmt.Sprintf("%s/cat?arg=%s", c.ipfsEndpoint, cid))
	}

	return send(c.httpClient, nil, http.MethodGet, fmt.Sprintf("%s/%s/%s", ipfsGlobal, "ipfs", cid))
}

func separateLinks(links []string) ([]string, error) {
	var ipfsLinks []string

	for _, link := range links {
		switch {
		case strings.HasPrefix(link, ipfsPrefix):
			ipfsLinks = append(ipfsLinks, link)
		default:
			return nil, fmt.Errorf("link '%s' not supported", link)
		}
	}

	return ipfsLinks, nil
}

func (c *casReader) getResourceHashWithPossibleLinks(hashWithPossibleHint string) ([]string, error) {
	var links []string

	hashWithPossibleHintParts := strings.Split(hashWithPossibleHint, ":")
	if len(hashWithPossibleHintParts) == 1 {
		return nil, fmt.Errorf("hashWithPossibleHint size not supported")
	}

	switch hashWithPossibleHintParts[0] {
	case "hl":
		hlInfo, err := c.hl.ParseHashLink(hashWithPossibleHint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse hash link: %w", err)
		}

		links = hlInfo.Links

	default:
		return nil, fmt.Errorf("hint '%s' not supported", hashWithPossibleHintParts[0])
	}

	return links, nil
}

func send(httpClient *http.Client, req []byte, method, endpointURL string) ([]byte, error) {
	var httpReq *http.Request

	var err error

	if len(req) == 0 {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	} else {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, bytes.NewBuffer(req))
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Errorf("Failed to close response body: %v", e)
	}
}
