/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package trustbloc implement trustbloc vdr
//
package trustbloc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"strings"
	"time"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	log "github.com/sirupsen/logrus"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/create"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/deactivate"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/recovery"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/update"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/config/httpconfig"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/config/memorycacheconfig"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/config/signatureconfig"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/config/updatevalidationconfig"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/config/verifyingconfig"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/didconfiguration"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/discovery/staticdiscovery"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/endpoint"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/selection/staticselection"
)

const (
	// DIDMethod did method.
	DIDMethod = "trustbloc"
	// EndpointsOpt endpoints opt.
	EndpointsOpt = "endpoints"
	// UpdatePublicKeyOpt update public key opt.
	UpdatePublicKeyOpt = "updatePublicKey"
	// RecoveryPublicKeyOpt recovery public key opt.
	RecoveryPublicKeyOpt = "recoveryPublicKey"
	// RecoverOpt recover opt.
	RecoverOpt = "recover"
)

// OperationType operation type.
type OperationType int

const (
	// Update operation.
	Update OperationType = iota
	// Recover operation.
	Recover
)

type configService interface {
	GetConsortium(string, string) (*models.ConsortiumFileData, error)
	GetStakeholder(string, string) (*models.StakeholderFileData, error)
	GetSidetreeConfig(url string) (*models.SidetreeConfig, error)
}

type sidetreeClient interface {
	CreateDID(opts ...create.Option) (*docdid.DocResolution, error)
	UpdateDID(didID string, opts ...update.Option) error
	RecoverDID(did string, opts ...recovery.Option) error
	DeactivateDID(did string, opts ...deactivate.Option) error
}

type endpointService interface {
	GetEndpoints(domain string) ([]*models.Endpoint, error)
}

type didConfigService interface {
	VerifyStakeholder(domain string, doc *docdid.Doc) error
}

type vdri interface {
	Create(keyManager kms.KeyManager, did *docdid.Doc, opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error)
	Read(id string, opts ...vdrapi.ResolveOption) (*docdid.DocResolution, error)
}

// VDRI bloc.
type VDRI struct {
	resolverURL                 string
	domain                      string
	configService               configService
	endpointService             endpointService
	didConfigService            didConfigService
	getHTTPVDRI                 func(url string) (vdri, error) // needed for unit test
	tlsConfig                   *tls.Config
	authToken                   string
	validatedConsortium         map[string]bool
	enableSignatureVerification bool
	useUpdateValidation         bool
	updateValidationService     *updatevalidationconfig.ConfigService
	genesisFiles                []genesisFileData
	sidetreeClient              sidetreeClient
	keyRetriever                KeyRetriever
}

type genesisFileData struct {
	url      string
	domain   string
	fileData []byte
}

// KeyRetriever key retriever.
type KeyRetriever interface {
	GetNextRecoveryPublicKey(didID string) (crypto.PublicKey, error)
	GetNextUpdatePublicKey(didID string) (crypto.PublicKey, error)
	GetSigningKey(didID string, ot OperationType) (crypto.PrivateKey, error)
}

// New creates new bloc vdri.
func New(keyRetriever KeyRetriever, opts ...Option) *VDRI {
	v := &VDRI{}

	for _, opt := range opts {
		opt(v)
	}

	v.sidetreeClient = sidetree.New(sidetree.WithAuthToken(v.authToken), sidetree.WithTLSConfig(v.tlsConfig))

	v.getHTTPVDRI = func(url string) (vdri, error) {
		return httpbinding.New(url,
			httpbinding.WithTLSConfig(v.tlsConfig), httpbinding.WithResolveAuthToken(v.authToken))
	}

	configService := httpconfig.NewService(httpconfig.WithTLSConfig(v.tlsConfig))

	switch {
	case v.useUpdateValidation:
		verifyingService := signatureconfig.NewService(verifyingconfig.NewService(configService))
		v.updateValidationService = updatevalidationconfig.NewService(verifyingService)
		v.configService = memorycacheconfig.NewService(v.updateValidationService)
	case v.enableSignatureVerification:
		verifyingService := signatureconfig.NewService(verifyingconfig.NewService(configService))
		v.configService = memorycacheconfig.NewService(verifyingService)
	default:
		v.configService = memorycacheconfig.NewService(verifyingconfig.NewService(configService))
	}

	v.endpointService = endpoint.NewService(
		staticdiscovery.NewService(v.configService),
		staticselection.NewService(v.configService))

	v.didConfigService = didconfiguration.NewService(didconfiguration.WithTLSConfig(v.tlsConfig))

	v.validatedConsortium = map[string]bool{}

	v.keyRetriever = keyRetriever

	return v
}

// Accept did method.
func (v *VDRI) Accept(method string) bool {
	return method == DIDMethod
}

// Close vdri.
func (v *VDRI) Close() error {
	return nil
}

// Create did doc.
// nolint: funlen,gocyclo
func (v *VDRI) Create(keyManager kms.KeyManager, did *docdid.Doc,
	opts ...vdrapi.DIDMethodOption) (*docdid.DocResolution, error) {
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	createOpt := make([]create.Option, 0)

	getEndpoints := v.getSidetreeEndpoints(didMethodOpts)

	// get sidetree config
	endpoints, err := getEndpoints()
	if err != nil {
		return nil, err
	}

	sidetreeConfig, err := v.configService.GetSidetreeConfig(endpoints[0])
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

	// get services
	for i := range did.Service {
		createOpt = append(createOpt, create.WithService(&did.Service[i]))
	}

	// get verification method
	pks, err := getSidetreePublicKeys(did.VerificationMethod)
	if err != nil {
		return nil, err
	}

	for i := range pks {
		createOpt = append(createOpt, create.WithPublicKey(&pks[i]))
	}

	createOpt = append(createOpt, create.WithSidetreeEndpoint(getEndpoints),
		create.WithMultiHashAlgorithm(sidetreeConfig.MultiHashAlgorithm), create.WithUpdatePublicKey(updatePublicKey),
		create.WithRecoveryPublicKey(recoveryPublicKey))

	return v.sidetreeClient.CreateDID(createOpt...)
}

// Update did doc.
func (v *VDRI) Update(didDoc *docdid.Doc, opts ...vdrapi.DIDMethodOption) error { //nolint:funlen,gocyclo
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	updateOpt := make([]update.Option, 0)

	getEndpoints := v.getSidetreeEndpoints(didMethodOpts)

	// get sidetree config
	endpoints, err := getEndpoints()
	if err != nil {
		return err
	}

	sidetreeConfig, err := v.configService.GetSidetreeConfig(endpoints[0])
	if err != nil {
		return err
	}

	docResolution, err := v.sidetreeResolve(endpoints[0]+"/identifiers", didDoc.ID)
	if err != nil {
		return err
	}

	// check recover option
	if didMethodOpts.Values[RecoverOpt] != nil {
		return v.recover(didDoc, sidetreeConfig, getEndpoints, docResolution.DocumentMetadata.Method.RecoveryCommitment)
	}

	// get services
	for i := range didDoc.Service {
		updateOpt = append(updateOpt, update.WithAddService(&didDoc.Service[i]))
	}

	updateOpt = append(updateOpt, getRemovedSvcKeysID(docResolution.DIDDocument.Service, didDoc.Service)...)

	// get verification method
	pks, err := getSidetreePublicKeys(didDoc.VerificationMethod)
	if err != nil {
		return err
	}

	for i := range pks {
		updateOpt = append(updateOpt, update.WithAddPublicKey(&pks[i]))
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

	updateOpt = append(updateOpt, update.WithSidetreeEndpoint(getEndpoints),
		update.WithNextUpdatePublicKey(nextUpdatePublicKey),
		update.WithMultiHashAlgorithm(sidetreeConfig.MultiHashAlgorithm),
		update.WithSigningKey(updateSigningKey),
		update.WithOperationCommitment(docResolution.DocumentMetadata.Method.UpdateCommitment))

	return v.sidetreeClient.UpdateDID(didDoc.ID, updateOpt...)
}

func (v *VDRI) recover(didDoc *docdid.Doc, sidetreeConfig *models.SidetreeConfig,
	getEndpoints func() ([]string, error), recoveryCommitment string) error {
	recoveryOpt := make([]recovery.Option, 0)

	// get services
	for i := range didDoc.Service {
		recoveryOpt = append(recoveryOpt, recovery.WithService(&didDoc.Service[i]))
	}

	// get verification method
	pks, err := getSidetreePublicKeys(didDoc.VerificationMethod)
	if err != nil {
		return err
	}

	for i := range pks {
		recoveryOpt = append(recoveryOpt, recovery.WithPublicKey(&pks[i]))
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
		recovery.WithOperationCommitment(recoveryCommitment))

	return v.sidetreeClient.RecoverDID(didDoc.ID, recoveryOpt...)
}

// Deactivate did doc.
func (v *VDRI) Deactivate(didID string, opts ...vdrapi.DIDMethodOption) error {
	didMethodOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}

	// Apply options
	for _, opt := range opts {
		opt(didMethodOpts)
	}

	var deactivateOpt []deactivate.Option

	getEndpoints := v.getSidetreeEndpoints(didMethodOpts)

	endpoints, err := getEndpoints()
	if err != nil {
		return err
	}

	docResolution, err := v.sidetreeResolve(endpoints[0]+"/identifiers", didID)
	if err != nil {
		return err
	}

	signingKey, err := v.keyRetriever.GetSigningKey(didID, Recover)
	if err != nil {
		return err
	}

	deactivateOpt = append(deactivateOpt, deactivate.WithSidetreeEndpoint(getEndpoints),
		deactivate.WithSigningKey(signingKey),
		deactivate.WithOperationCommitment(docResolution.DocumentMetadata.Method.RecoveryCommitment))

	return v.sidetreeClient.DeactivateDID(didID, deactivateOpt...)
}

func getSidetreePublicKeys(verificationMethod []docdid.VerificationMethod) ([]doc.PublicKey, error) {
	pks := make([]doc.PublicKey, 0)

	for _, vm := range verificationMethod {
		if vm.JSONWebKey() == nil {
			return nil, fmt.Errorf("verificationMethod JSONWebKey is nil")
		}

		pks = append(pks, doc.PublicKey{
			ID:       vm.ID,
			Type:     vm.Type,
			Purposes: []string{doc.KeyPurposeAuthentication}, // TODO add did method option for Purposes
			JWK:      vm.JSONWebKey().JSONWebKey,
		})
	}

	return pks, nil
}

func (v *VDRI) getSidetreeEndpoints(didMethodOpts *vdrapi.DIDMethodOpts) func() ([]string, error) {
	if didMethodOpts.Values[EndpointsOpt] == nil {
		return func() ([]string, error) {
			var result []string

			endpoints, err := v.endpointService.GetEndpoints(v.domain)
			if err != nil {
				return nil, fmt.Errorf("failed to get endpoints: %w", err)
			}

			for _, v := range endpoints {
				result = append(result, v.URL)
			}

			return result, nil
		}
	}

	return func() ([]string, error) {
		v, ok := didMethodOpts.Values[EndpointsOpt].([]string)
		if !ok {
			return nil, fmt.Errorf("endpointsOpt not array of string")
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

func (v *VDRI) loadGenesisFiles() error {
	for _, genesisFile := range v.genesisFiles {
		err := v.updateValidationService.AddGenesisFile(genesisFile.url, genesisFile.domain, genesisFile.fileData)
		if err != nil {
			return fmt.Errorf("error loading consortium genesis config: %w", err)
		}
	}

	v.genesisFiles = nil

	return nil
}

func (v *VDRI) sidetreeResolve(url, did string, opts ...vdrapi.ResolveOption) (*docdid.DocResolution, error) {
	resolver, err := v.getHTTPVDRI(url)
	if err != nil {
		return nil, fmt.Errorf("failed to create new sidetree vdri: %w", err)
	}

	docResolution, err := resolver.Read(did, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve did: %w", err)
	}

	return docResolution, nil
}

const (
	expectedTrustblocDIDParts = 4
	domainDIDPart             = 2
)

func (v *VDRI) Read(did string, opts ...vdrapi.ResolveOption) (*docdid.DocResolution, error) { //nolint: gocyclo,funlen
	err := v.loadGenesisFiles()
	if err != nil {
		return nil, fmt.Errorf("invalid genesis file: %w", err)
	}

	if v.resolverURL != "" {
		return v.sidetreeResolve(v.resolverURL, did, opts...)
	}

	// parse did
	didParts := strings.Split(did, ":")
	if len(didParts) != expectedTrustblocDIDParts {
		return nil, fmt.Errorf("wrong did %s", did)
	}

	domain := didParts[domainDIDPart]
	if v.domain != "" {
		domain = v.domain
	}

	if v.enableSignatureVerification {
		if _, ok := v.validatedConsortium[domain]; !ok {
			_, err = v.ValidateConsortium(domain)
			if err != nil {
				return nil, fmt.Errorf("invalid consortium: %w", err)
			}

			v.validatedConsortium[domain] = true
		}
	}

	endpoints, err := v.endpointService.GetEndpoints(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints: %w", err)
	}

	if len(endpoints) == 0 {
		return nil, errors.New("list of endpoints is empty")
	}

	var docResolution *docdid.DocResolution

	var docBytes []byte

	for _, e := range endpoints {
		resp, err := v.sidetreeResolve(e.URL+"/identifiers", did, opts...)
		if err != nil {
			return nil, err
		}

		respBytes, err := canonicalizeDoc(resp.DIDDocument)
		if err != nil {
			return nil, fmt.Errorf("cannot canonicalize resolved doc: %w", err)
		}

		if docResolution != nil && !bytes.Equal(docBytes, respBytes) {
			log.Debugf("mismatch in document contents for did %s. Doc 1: %s, Doc 2: %s",
				did, string(docBytes), string(respBytes))
		}

		docResolution = resp
		docBytes = respBytes
	}

	return docResolution, nil
}

// ValidateConsortium validate the config and endorsement of a consortium and its stakeholders
// returns the duration after which the consortium config expires and needs re-validation.
func (v *VDRI) ValidateConsortium(consortiumDomain string) (*time.Duration, error) {
	consortiumConfig, err := v.configService.GetConsortium(consortiumDomain, consortiumDomain)
	if err != nil {
		return nil, fmt.Errorf("consortium invalid: %w", err)
	}

	stakeholders, err := v.selectStakeholders(consortiumConfig.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch stakeholders: %w", err)
	}

	n := consortiumConfig.Config.Policy.NumQueries
	if n == 0 || n > len(consortiumConfig.Config.Members) {
		n = len(consortiumConfig.Config.Members)
	}

	numVerifications := 0

	verificationErrors := ""

	for _, sfd := range stakeholders {
		e := v.verifyStakeholder(consortiumConfig, sfd)
		if e != nil {
			verificationErrors += e.Error() + ", "

			continue
		}

		numVerifications++
	}

	if numVerifications < n {
		return nil, fmt.Errorf("insufficient stakeholders verified, all errors: [%s]", verificationErrors)
	}

	lifetime, err := consortiumConfig.CacheLifetime()
	if err != nil {
		return nil, fmt.Errorf("consortium lifetime error: %w", err)
	}

	return &lifetime, nil
}

func (v *VDRI) verifyStakeholder(cfd *models.ConsortiumFileData, sfd *models.StakeholderFileData) error {
	s := sfd.Config
	if s == nil {
		return fmt.Errorf("stakeholder has nil config")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s.Endpoints))))
	if err != nil {
		return err
	}

	ep := s.Endpoints[n.Uint64()]

	docResolution, e := v.sidetreeResolve(ep+"/identifiers", s.DID)
	if e != nil {
		return fmt.Errorf("can't resolve stakeholder DID: %w", e)
	}

	// verify did configuration
	e = v.didConfigService.VerifyStakeholder(s.Domain, docResolution.DIDDocument)
	if e != nil {
		return fmt.Errorf("stakeholder did configuration failed to verify: %w", e)
	}

	_, e = didconfiguration.VerifyDIDSignature(cfd.JWS, docResolution.DIDDocument)
	if e != nil {
		return fmt.Errorf("stakeholder does not sign consortium: %w", e)
	}

	_, e = didconfiguration.VerifyDIDSignature(sfd.JWS, docResolution.DIDDocument)
	if e != nil {
		return fmt.Errorf("stakeholder does not sign itself: %w", e)
	}

	return nil
}

// select n random stakeholders from the consortium (where n is the consortium's numQueries policy parameter.
func (v *VDRI) selectStakeholders(consortium *models.Consortium) ([]*models.StakeholderFileData, error) {
	n := consortium.Policy.NumQueries
	if n == 0 || n > len(consortium.Members) {
		n = len(consortium.Members)
	}

	perm := mathrand.Perm(len(consortium.Members))

	successCount := 0

	var out []*models.StakeholderFileData

	for i := 0; i < len(consortium.Members) && successCount < n; i++ {
		sle := consortium.Members[perm[i]]

		s, err := v.configService.GetStakeholder(sle.Domain, sle.Domain)
		if err != nil {
			continue
		}

		out = append(out, s)

		successCount++
	}

	if successCount < n {
		return nil, fmt.Errorf("insufficient valid stakeholders")
	}

	return out, nil
}

// canonicalizeDoc canonicalizes a DID doc using json-ld canonicalization.
func canonicalizeDoc(didDoc *docdid.Doc) ([]byte, error) {
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

	return proc.GetCanonicalDocument(docMap)
}

// Option configures the bloc vdri.
type Option func(opts *VDRI)

// WithResolverURL option is setting resolver url.
func WithResolverURL(resolverURL string) Option {
	return func(opts *VDRI) {
		opts.resolverURL = resolverURL
	}
}

// WithDomain option is setting domain.
func WithDomain(domain string) Option {
	return func(opts *VDRI) {
		opts.domain = domain
	}
}

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *VDRI) {
		opts.tlsConfig = tlsConfig
	}
}

// WithAuthToken add auth token.
func WithAuthToken(authToken string) Option {
	return func(opts *VDRI) {
		opts.authToken = authToken
	}
}

// EnableSignatureVerification enables signature verification.
func EnableSignatureVerification(enable bool) Option {
	return func(opts *VDRI) {
		opts.enableSignatureVerification = enable
	}
}

// UseGenesisFile adds a consortium genesis file to the VDRI and enables consortium config update validation.
func UseGenesisFile(url, domain string, genesisFile []byte) Option {
	return func(opts *VDRI) {
		opts.genesisFiles = append(opts.genesisFiles, genesisFileData{
			url:      url,
			domain:   domain,
			fileData: genesisFile,
		})
		opts.useUpdateValidation = true
	}
}
