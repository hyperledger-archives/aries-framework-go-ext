/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package orb implement orb vdr
package orb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	ldprocessor "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/orbclient/resolutionverifier"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"golang.org/x/net/http2"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/internal/ldcontext"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/lb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/tracing"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/api"
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
	// AnchorOriginOpt anchor origin opt this option is not mandatory.
	AnchorOriginOpt = "anchorOrigin"
	// CheckDIDAnchored check did is anchored.
	CheckDIDAnchored = "checkDIDAnchored"
	// CheckDIDUpdated check did is updated.
	CheckDIDUpdated = "checkDIDUpdated"
	// TracingCtxOpt tracing opt.
	TracingCtxOpt = "tracingCtxOpt"
	// VersionIDOpt version id opt this option is not mandatory.
	VersionIDOpt = httpbinding.VersionIDOpt
	// VersionTimeOpt version time opt this option is not mandatory.
	VersionTimeOpt = httpbinding.VersionTimeOpt
	httpTimeOut    = 20 * time.Second
	sha2_256       = 18 // multihash
	ipfsGlobal     = "https://ipfs.io"
	ipfsPrefix     = "ipfs://"
	httpsProtocol  = "https"
	httpProtocol   = "http"
	retry          = 3
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

// VerifyResolutionResultType verify resolution result type.
type VerifyResolutionResultType int

const (
	// All will verify document if it has unpublished or published operations.
	All VerifyResolutionResultType = iota
	// Unpublished will verify document only if it has unpublished operations.
	Unpublished
	// None will not verify document.
	None
)

// ResolveDIDRetry resolve did retry.
type ResolveDIDRetry struct {
	MaxNumber int
	SleepTime *time.Duration
}

type sidetreeClient interface {
	CreateDID(opts ...create.Option) (*docdid.DocResolution, error)
	UpdateDID(didID string, opts ...update.Option) error
	RecoverDID(did string, opts ...recovery.Option) error
	DeactivateDID(did string, opts ...deactivate.Option) error
}

type verifierResolutionResult interface {
	Verify(input *document.ResolutionResult) error
}

type vdr interface {
	Read(id string, opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type discoveryService interface {
	GetEndpoint(domain string) (*models.Endpoint, error)
	GetEndpointFromAnchorOrigin(did string) (*models.Endpoint, error)
}

// SelectDomainService select domain service.
type SelectDomainService interface {
	Choose(domains []string) (string, error)
}

type authTokenProvider interface {
	AuthToken() (string, error)
}

// VDR bloc.
type VDR struct {
	getHTTPVDR                 func(url string) (vdr, error) // needed for unit test
	tlsConfig                  *tls.Config
	unanchoredMaxLifeTime      *time.Duration
	authToken                  string
	authTokenProvider          authTokenProvider
	domains                    []string
	disableProofCheck          bool
	sidetreeClient             sidetreeClient
	keyRetriever               KeyRetriever
	discoveryService           discoveryService
	documentLoader             jsonld.DocumentLoader
	ipfsEndpoint               string
	selectDomainSvc            SelectDomainService
	verifyResolutionResultType VerifyResolutionResultType
	verifier                   verifierResolutionResult
	httpClient                 *http.Client
}

// KeyRetriever key retriever.
type KeyRetriever interface {
	GetNextRecoveryPublicKey(didID, commitment string) (crypto.PublicKey, error)
	GetNextUpdatePublicKey(didID, commitment string) (crypto.PublicKey, error)
	GetSigner(didID string, ot OperationType, commitment string) (api.Signer, error)
}

// New creates new orb VDR.
func New(keyRetriever KeyRetriever, opts ...Option) (*VDR, error) {
	v := &VDR{domains: make([]string, 0), selectDomainSvc: lb.NewRoundRobin(), verifyResolutionResultType: Unpublished}

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

	v.verifier, err = resolutionverifier.New(fmt.Sprintf("did:%s", DIDMethod))
	if err != nil {
		return nil, err
	}

	v.keyRetriever = keyRetriever

	if v.httpClient == nil {
		v.httpClient = &http.Client{
			Timeout: 20 * time.Second, //nolint: gomnd
			Transport: &http2.Transport{
				TLSClientConfig: v.tlsConfig,
			},
		}
	}

	v.sidetreeClient = sidetree.New(sidetree.WithAuthToken(v.authToken), sidetree.WithHTTPClient(v.httpClient),
		sidetree.WithAuthTokenProvider(v.authTokenProvider))

	v.getHTTPVDR = func(url string) (vdr, error) {
		return httpbinding.New(url,
			httpbinding.WithHTTPClient(v.httpClient), httpbinding.WithResolveAuthToken(v.authToken),
			httpbinding.WithTimeout(httpTimeOut), httpbinding.WithResolveAuthTokenProvider(v.authTokenProvider))
	}

	v.discoveryService, err = client.New(v.documentLoader, &casReader{
		httpClient:   v.httpClient,
		hl:           hashlink.New(),
		ipfsEndpoint: v.ipfsEndpoint,
		authToken:    v.authToken,
	},
		client.WithDisableProofCheck(v.disableProofCheck), client.WithHTTPClient(v.httpClient),
		client.WithAuthToken(v.authToken), client.WithAuthTokenProvider(v.authTokenProvider))
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
// nolint: gocyclo,funlen
func (v *VDR) Create(did *docdid.Doc,
	opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	createOpt := make([]create.Option, 0)

	// Select domain
	domain, err := v.selectDomainSvc.Choose(v.domains)
	if err != nil {
		return nil, err
	}

	getEndpoints := v.getSidetreeOperationEndpoints(didMethodOpts, domain)

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

	anchorOrigin := domain

	if didMethodOpts.Values[AnchorOriginOpt] != nil {
		anchorOrigin, ok = didMethodOpts.Values[AnchorOriginOpt].(string)
		if !ok {
			return nil, fmt.Errorf("anchorOrigin is not string")
		}
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

	createOpt = append(createOpt, create.WithSidetreeEndpoint(getEndpoints), create.WithAnchorOrigin(anchorOrigin),
		create.WithMultiHashAlgorithm(sha2_256), create.WithUpdatePublicKey(updatePublicKey),
		create.WithRecoveryPublicKey(recoveryPublicKey))

	createdDID, err := v.sidetreeClient.CreateDID(createOpt...)
	if err != nil {
		return nil, err
	}

	if didMethodOpts.Values[CheckDIDAnchored] == nil {
		return createdDID, nil
	}

	resolveDIDRetry, ok := didMethodOpts.Values[CheckDIDAnchored].(*ResolveDIDRetry)
	if !ok {
		return nil, fmt.Errorf("resolveDIDRetry is not ResolveDIDRetry struct")
	}

	return v.checkDID(createdDID.DIDDocument.ID, resolveDIDRetry, "", true, opts...)
}

// Read Orb DID.
// nolint: funlen,gocyclo,gocognit
func (v *VDR) Read(did string, opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	var ctx context.Context

	if didMethodOpts.Values[TracingCtxOpt] != nil {
		var ok bool

		ctx, ok = didMethodOpts.Values[TracingCtxOpt].(context.Context)
		if !ok {
			return nil, fmt.Errorf("tracingOpt not type of span")
		}
	}

	if didMethodOpts.Values[ResolutionEndpointsOpt] != nil {
		endpoints, ok := didMethodOpts.Values[ResolutionEndpointsOpt].([]string)
		if !ok {
			return nil, fmt.Errorf("resolutionEndpointsOpt not array of string")
		}

		return v.sidetreeResolve(ctx, endpoints[0], did, opts...)
	}

	var endpoint *models.Endpoint

	var err error

	switch {
	case strings.HasPrefix(did, fmt.Sprintf("did:%s:%s", DIDMethod, httpsProtocol)) ||
		strings.HasPrefix(did, fmt.Sprintf("did:%s:%s", DIDMethod, httpProtocol)):
		hintDomain := strings.Split(did, ":")[3]

		endpoint, err = v.discoveryService.GetEndpoint(
			fmt.Sprintf("%s://%s", strings.Split(did, ":")[2], hintDomain))
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}

		for _, e := range endpoint.ResolutionEndpoints {
			if strings.Contains(e, hintDomain) {
				docRes, errResolve := v.sidetreeResolve(ctx, e, did, opts...)
				if errResolve != nil {
					return nil, errResolve
				}

				if errCheck := v.verifyDID(docRes); errCheck != nil {
					return nil, errCheck
				}

				return docRes, nil
			}
		}

		return nil, fmt.Errorf("discovery did not return hint domain")
	case len(v.domains) != 0:
		// Select domain
		domain, errChoose := v.selectDomainSvc.Choose(v.domains)
		if errChoose != nil {
			return nil, errChoose
		}

		endpoint, err = v.discoveryService.GetEndpoint(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}
	default:
		endpoint, err = v.discoveryService.GetEndpointFromAnchorOrigin(did)
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}
	}

	var docResolution *docdid.DocResolution

	var docBytes []byte

	minResolver := 0

	// Resolve the DID at each of the n chosen links.
	// Ensure that the DID resolution result matches (other than resolver-specific metadata such as timestamps).
	// In case of a mismatch, additional links may need to be chosen until the client has n matches.

	for _, e := range endpoint.ResolutionEndpoints {
		resp, err := v.sidetreeResolve(ctx, e, did, opts...)
		if err != nil {
			return nil, err
		}

		respBytes, err := canonicalizeDoc(resp.DIDDocument, v.documentLoader)
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

	if err := v.verifyDID(docResolution); err != nil {
		return nil, err
	}

	return docResolution, nil
}

func (v *VDR) verifyDID(didRes *docdid.DocResolution) error { // nolint:gocognit,gocyclo,funlen
	check := false

	// verify resolution result
	if didRes.DocumentMetadata != nil && didRes.DocumentMetadata.Method != nil {
		if len(didRes.DocumentMetadata.Method.UnpublishedOperations) > 0 &&
			(v.verifyResolutionResultType == Unpublished || v.verifyResolutionResultType == All) {
			check = true
		} else if len(didRes.DocumentMetadata.Method.PublishedOperations) > 0 && v.verifyResolutionResultType == All {
			check = true
		}
	}

	if check { //nolint: nestif
		docRes := &document.ResolutionResult{}

		didDocBytes, err := didRes.DIDDocument.JSONBytes()
		if err != nil {
			return err
		}

		docRes.Document, err = document.FromBytes(didDocBytes)
		if err != nil {
			return err
		}

		documentMetadataBytes, err := json.Marshal(didRes.DocumentMetadata)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(documentMetadataBytes, &docRes.DocumentMetadata); err != nil {
			return err
		}

		if ctx, ok := didRes.Context.(string); ok {
			docRes.Context = ctx
		} else {
			docRes.Context = didRes.Context.([]string)[0]
		}

		if err := v.verifier.Verify(docRes); err != nil {
			return err
		}
	}

	// verify unanchored max life time
	if v.unanchoredMaxLifeTime == nil {
		return nil
	}

	for _, o := range didRes.DocumentMetadata.Method.UnpublishedOperations {
		if o.Type == "create" || o.Type == "update" {
			rejectTime := time.Unix(o.TransactionTime, 0).UTC().Add(*v.unanchoredMaxLifeTime)

			if time.Now().In(time.UTC).After(rejectTime) {
				if o.Type == "update" {
					return fmt.Errorf("cached updated DID reach max time for usage")
				}

				return fmt.Errorf("unanchored DID reach max time for usage")
			}
		}
	}

	return nil
}

// Update did doc.
func (v *VDR) Update(didDoc *docdid.Doc, opts ...vdrapi.DIDMethodOption) error { //nolint:funlen,gocyclo,gocognit
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

	// check recover option
	if didMethodOpts.Values[RecoverOpt] != nil {
		// Select domain
		domain, errChoose := v.selectDomainSvc.Choose(v.domains)
		if errChoose != nil {
			return errChoose
		}

		anchorOrigin := docResolution.DocumentMetadata.Method.AnchorOrigin

		if didMethodOpts.Values[AnchorOriginOpt] != nil {
			var ok bool

			anchorOrigin, ok = didMethodOpts.Values[AnchorOriginOpt].(string)
			if !ok {
				return fmt.Errorf("anchorOrigin is not string")
			}
		}

		return v.recover(didDoc, v.getSidetreeOperationEndpoints(didMethodOpts, domain),
			docResolution.DocumentMetadata.Method.RecoveryCommitment, anchorOrigin)
	}

	// get services
	for i := range didDoc.Service {
		svc := &didDoc.Service[i]

		s := strings.Split(svc.ID, "#")

		id := s[0]
		if len(s) > 1 {
			id = s[1]
		}

		svc.ID = id

		updateOpt = append(updateOpt, update.WithAddService(svc))
	}

	updateOpt = append(updateOpt, getRemovedSvcKeysID(docResolution.DIDDocument.Service, didDoc.Service)...)

	// get keys
	nextUpdatePublicKey, err := v.keyRetriever.GetNextUpdatePublicKey(didDoc.ID,
		docResolution.DocumentMetadata.Method.UpdateCommitment)
	if err != nil {
		return err
	}

	signer, err := v.keyRetriever.GetSigner(didDoc.ID, Update,
		docResolution.DocumentMetadata.Method.UpdateCommitment)
	if err != nil {
		return err
	}

	updatedPKKeysID, err := getUpdatedPKKeysID(docResolution.DIDDocument, didDoc)
	if err != nil {
		return err
	}

	updateOpt = append(updateOpt, updatedPKKeysID...)

	updatedAlsoKnownAsOpts := getUpdatedAlsoKnownAs(docResolution.DIDDocument.AlsoKnownAs, didDoc.AlsoKnownAs)

	updateOpt = append(updateOpt, updatedAlsoKnownAsOpts...)

	updateOpt = append(updateOpt, update.WithSidetreeEndpoint(func() ([]string, error) {
		endpoint, errGet := v.discoveryService.GetEndpoint(docResolution.DocumentMetadata.Method.AnchorOrigin)
		if errGet != nil {
			logger.Warnf("failed to get anchor origin %s endpoints will choose random domain: %w",
				docResolution.DocumentMetadata.Method.AnchorOrigin, errGet)

			for i := 1; i <= retry; i++ {
				domain, errChoose := v.selectDomainSvc.Choose(v.domains)
				if err != nil {
					return nil, errChoose
				}

				domainEndpoint, errEndpoint := v.discoveryService.GetEndpoint(domain)
				if err != nil {
					if i == retry {
						return nil, fmt.Errorf("failed to get endpoints: %w", errEndpoint)
					}

					continue
				}

				return domainEndpoint.OperationEndpoints, nil
			}
		}

		return endpoint.OperationEndpoints, nil
	}),
		update.WithNextUpdatePublicKey(nextUpdatePublicKey),
		update.WithMultiHashAlgorithm(sha2_256),
		update.WithSigner(signer),
		update.WithOperationCommitment(docResolution.DocumentMetadata.Method.UpdateCommitment))

	if errUpdateDID := v.sidetreeClient.UpdateDID(didDoc.ID, updateOpt...); errUpdateDID != nil {
		return errUpdateDID
	}

	if didMethodOpts.Values[CheckDIDUpdated] == nil {
		return nil
	}

	resolveDIDRetry, ok := didMethodOpts.Values[CheckDIDUpdated].(*ResolveDIDRetry)
	if !ok {
		return fmt.Errorf("resolveDIDRetry is not ResolveDIDRetry struct")
	}

	nextUpdateKey, err := pubkey.GetPublicKeyJWK(nextUpdatePublicKey)
	if err != nil {
		return fmt.Errorf("failed to get next update key : %w", err)
	}

	nextUpdateCommitment, err := commitment.GetCommitment(nextUpdateKey, sha2_256)
	if err != nil {
		return err
	}

	_, err = v.checkDID(didDoc.ID, resolveDIDRetry, nextUpdateCommitment, false, opts...)

	return err
}

func (v *VDR) recover(didDoc *docdid.Doc, getEndpoints func() ([]string, error),
	recoveryCommitment, anchorOrigin string) error {
	recoveryOpt := make([]recovery.Option, 0)

	// get services
	for i := range didDoc.Service {
		svc := &didDoc.Service[i]

		s := strings.Split(svc.ID, "#")

		id := s[0]
		if len(s) > 1 {
			id = s[1]
		}

		svc.ID = id

		recoveryOpt = append(recoveryOpt, recovery.WithService(svc))
	}

	// get verification method
	pks, err := getSidetreePublicKeys(didDoc)
	if err != nil {
		return err
	}

	for k := range pks {
		recoveryOpt = append(recoveryOpt, recovery.WithPublicKey(pks[k].publicKey))
	}

	// get also known as
	for i := range didDoc.AlsoKnownAs {
		recoveryOpt = append(recoveryOpt, recovery.WithAlsoKnownAs(didDoc.AlsoKnownAs[i]))
	}

	// get keys
	nextUpdatePublicKey, err := v.keyRetriever.GetNextUpdatePublicKey(didDoc.ID, recoveryCommitment)
	if err != nil {
		return err
	}

	nextRecoveryPublicKey, err := v.keyRetriever.GetNextRecoveryPublicKey(didDoc.ID, recoveryCommitment)
	if err != nil {
		return err
	}

	signer, err := v.keyRetriever.GetSigner(didDoc.ID, Recover, recoveryCommitment)
	if err != nil {
		return err
	}

	recoveryOpt = append(recoveryOpt, recovery.WithSidetreeEndpoint(getEndpoints),
		recovery.WithNextUpdatePublicKey(nextUpdatePublicKey),
		recovery.WithNextRecoveryPublicKey(nextRecoveryPublicKey),
		recovery.WithMultiHashAlgorithm(sha2_256),
		recovery.WithSigner(signer),
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

	signer, err := v.keyRetriever.GetSigner(didID, Recover,
		docResolution.DocumentMetadata.Method.RecoveryCommitment)
	if err != nil {
		return err
	}

	// Select domain
	domain, err := v.selectDomainSvc.Choose(v.domains)
	if err != nil {
		return err
	}

	deactivateOpt = append(deactivateOpt,
		deactivate.WithSidetreeEndpoint(v.getSidetreeOperationEndpoints(didMethodOpts, domain)),
		deactivate.WithSigner(signer),
		deactivate.WithOperationCommitment(docResolution.DocumentMetadata.Method.RecoveryCommitment))

	return v.sidetreeClient.DeactivateDID(didID, deactivateOpt...)
}

type pk struct {
	value     []byte
	publicKey *doc.PublicKey
}

func getSidetreePublicKeys(didDoc *docdid.Doc) (map[string]*pk, error) { // nolint:funlen,gocyclo
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

func (v *VDR) getSidetreeOperationEndpoints(didMethodOpts *vdrapi.DIDMethodOpts,
	domain string) func() ([]string, error) {
	if didMethodOpts.Values[OperationEndpointsOpt] == nil {
		return func() ([]string, error) {
			endpoint, err := v.discoveryService.GetEndpoint(domain)
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

func getUpdatedAlsoKnownAs(current, updated []string) []update.Option {
	var updateOpt []update.Option

	currentMap := sliceToMap(current)
	updatedMap := sliceToMap(updated)

	for _, val := range updated {
		_, ok := currentMap[val]
		if !ok {
			// new URI - append it to add URIs
			updateOpt = append(updateOpt, update.WithAddAlsoKnownAs(val))
		}
	}

	for _, val := range current {
		_, ok := updatedMap[val]
		if !ok {
			// missing URI - append it to remove URIs
			updateOpt = append(updateOpt, update.WithRemoveAlsoKnownAs(val))
		}
	}

	return updateOpt
}

func sliceToMap(values []string) map[string]bool {
	m := make(map[string]bool)
	for _, value := range values {
		m[value] = true
	}

	return m
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

func (v *VDR) sidetreeResolve(ctx context.Context, url, did string,
	opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	resolver, err := v.getHTTPVDR(url)
	if err != nil {
		return nil, fmt.Errorf("failed to create new sidetree vdr: %w", err)
	}

	span, _ := tracing.StartChildSpan(ctx, "vdr_read_resolve_did")

	docResolution, err := resolver.Read(did, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve did: %w", err)
	}

	if span != nil {
		span.SetTag("did-id", did)

		span.Finish()
	}

	return docResolution, nil
}

// nolint: gocyclo
func (v *VDR) checkDID(did string, resolveDIDRetry *ResolveDIDRetry, updateCommitment string,
	checkAnchored bool, opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	if resolveDIDRetry.MaxNumber < 1 {
		return nil, fmt.Errorf("resolve did retry max number is less than one")
	}

	if resolveDIDRetry.SleepTime == nil {
		return nil, fmt.Errorf("resolve did retry sleep time is nil")
	}

	var docResolution *docdid.DocResolution

	for i := 1; i <= resolveDIDRetry.MaxNumber; i++ {
		var err error
		docResolution, err = v.Read(did, opts...)

		if checkAnchored && err == nil && docResolution.DocumentMetadata.Method.Published {
			break
		}

		if !checkAnchored && err == nil && docResolution.DocumentMetadata.Method.UpdateCommitment == updateCommitment {
			break
		}

		if err != nil && !errors.Is(err, vdrapi.ErrNotFound) {
			return nil, err
		}

		if i == resolveDIDRetry.MaxNumber {
			if err == nil {
				if checkAnchored {
					return nil, fmt.Errorf("did is not published")
				}

				return nil, fmt.Errorf("did is not updated")
			}

			return nil, err
		}

		time.Sleep(*resolveDIDRetry.SleepTime)
	}

	return docResolution, nil
}

// Option configures the bloc vdr.
type Option func(opts *VDR)

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(opts *VDR) {
		opts.httpClient = httpClient
	}
}

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *VDR) {
		opts.tlsConfig = tlsConfig
	}
}

// WithUnanchoredMaxLifeTime option is max time for unanchored to be trusted .
func WithUnanchoredMaxLifeTime(duration time.Duration) Option {
	return func(opts *VDR) {
		opts.unanchoredMaxLifeTime = &duration
	}
}

// WithVerifyResolutionResultType option is set verify resolution result type.
func WithVerifyResolutionResultType(v VerifyResolutionResultType) Option {
	return func(opts *VDR) {
		opts.verifyResolutionResultType = v
	}
}

// WithAuthToken add auth token.
func WithAuthToken(authToken string) Option {
	return func(opts *VDR) {
		opts.authToken = authToken
	}
}

// WithAuthTokenProvider add auth token provider.
func WithAuthTokenProvider(p authTokenProvider) Option {
	return func(opts *VDR) {
		opts.authTokenProvider = p
	}
}

// WithDomain option is setting domain.
// to set multiple domains call this option multiple times.
func WithDomain(domain string) Option {
	return func(opts *VDR) {
		opts.domains = append(opts.domains, domain)
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
	httpClient        httpClient
	hl                *hashlink.HashLink
	ipfsEndpoint      string
	authToken         string
	authTokenProvider authTokenProvider
}

func (c *casReader) Read(cidWithPossibleHint string) ([]byte, error) {
	links, err := c.getResourceHashWithPossibleLinks(cidWithPossibleHint)
	if err != nil {
		return nil, err
	}

	webcasLinks, ipfsLinks, err := separateLinks(links)
	if err != nil {
		return nil, err
	}

	if len(webcasLinks) == 0 {
		cid := ipfsLinks[0][len(ipfsPrefix):]

		if c.ipfsEndpoint != "" {
			return send(c.httpClient, nil,
				http.MethodPost, fmt.Sprintf("%s/cat?arg=%s", c.ipfsEndpoint, cid), "", nil)
		}

		return send(c.httpClient, nil, http.MethodGet, fmt.Sprintf("%s/%s/%s", ipfsGlobal, "ipfs", cid), "",
			nil)
	}

	var errMsgs []string

	for _, webCASEndpoint := range webcasLinks {
		data, err := send(c.httpClient, nil, http.MethodGet, webCASEndpoint, c.authToken, c.authTokenProvider)
		if err != nil {
			errMsg := fmt.Sprintf("endpoint[%s]: %s", webCASEndpoint, err.Error())

			errMsgs = append(errMsgs, errMsg)

			continue
		}

		return data, nil
	}

	return nil, fmt.Errorf("%s", errMsgs)
}

func separateLinks(links []string) (webcasLinks, ipfsLinks []string, err error) {
	for _, link := range links {
		switch {
		case strings.HasPrefix(link, httpsProtocol) || strings.HasPrefix(link, httpProtocol):
			webcasLinks = append(webcasLinks, link)
		case strings.HasPrefix(link, ipfsPrefix):
			ipfsLinks = append(ipfsLinks, link)
		default:
			return nil, nil, fmt.Errorf("link '%s' not supported", link)
		}
	}

	return webcasLinks, ipfsLinks, nil
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

func send(httpClient httpClient, req []byte, method, endpointURL, token string, p authTokenProvider) ([]byte, error) {
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

	authToken := token

	if p != nil {
		v, errToken := p.AuthToken()
		if errToken != nil {
			return nil, errToken
		}

		authToken = "Bearer " + v
	}

	if authToken != "" {
		httpReq.Header.Add("Authorization", "Bearer "+authToken)
	}

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

// canonicalizeDoc canonicalizes a DID doc using json-ld canonicalization.
func canonicalizeDoc(didDoc *docdid.Doc, docLoader jsonld.DocumentLoader) ([]byte, error) {
	marshaled, err := didDoc.JSONBytes()
	if err != nil {
		return nil, err
	}

	docMap := map[string]interface{}{}

	err = json.Unmarshal(marshaled, &docMap)
	if err != nil {
		return nil, err
	}

	proc := ldprocessor.Default()

	return proc.GetCanonicalDocument(docMap, ldprocessor.WithDocumentLoader(docLoader))
}
