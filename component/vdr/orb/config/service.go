/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package config implement orb config
//
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/orbclient"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/models"
)

var logger = log.New("aries-framework-ext/vdr/orb") //nolint: gochecknoglobals

const (
	// default hashes for sidetree.
	sha2_256             = 18 // multihash
	maxAge               = 3600
	minResolvers         = "https://trustbloc.dev/ns/min-resolvers"
	anchorOriginProperty = "https://trustbloc.dev/ns/anchor-origin"
	// did method.
	didMethod  = "orb"
	ipfsGlobal = "https://ipfs.io"
	didParts   = 5
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type orbClient interface {
	GetAnchorOrigin(cid, suffix string) (interface{}, error)
}

// Service fetches configs, caching results in-memory.
type Service struct {
	sidetreeConfigCache        gcache.Cache
	endpointsCache             gcache.Cache
	endpointsAnchorOriginCache gcache.Cache
	httpClient                 httpClient
	authToken                  string
	disableProofCheck          bool
	docLoader                  ld.DocumentLoader
	orbClient                  orbClient
}

type req struct {
	did, domain string
}

// NewService create new ConfigService.
func NewService(docLoader ld.DocumentLoader, opts ...Option) (*Service, error) {
	configService := &Service{docLoader: docLoader, httpClient: &http.Client{}}

	for _, opt := range opts {
		opt(configService)
	}

	var orbclientOpts []orbclient.Option

	orbclientOpts = append(orbclientOpts, orbclient.WithJSONLDDocumentLoader(docLoader))

	if configService.disableProofCheck {
		orbclientOpts = append(orbclientOpts, orbclient.WithDisableProofCheck(configService.disableProofCheck))
	} else {
		orbclientOpts = append(orbclientOpts, orbclient.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(vdr.New(vdr.WithVDR(&webVDR{
				http: configService.httpClient,
				VDR:  web.New(),
			}),
			)).PublicKeyFetcher()))
	}

	orbClient, err := orbclient.New(fmt.Sprintf("did:%s", didMethod), &casReader{s: configService}, orbclientOpts...)
	if err != nil {
		return nil, err
	}

	configService.orbClient = orbClient

	configService.sidetreeConfigCache = makeCache(
		configService.getNewCacheable(func(did, domain string) (cacheable, error) {
			return configService.getSidetreeConfig()
		}))

	configService.endpointsCache = makeCache(
		configService.getNewCacheable(func(did, domain string) (cacheable, error) {
			return configService.getEndpoint(domain)
		}))

	configService.endpointsAnchorOriginCache = makeCache(
		configService.getNewCacheable(func(did, domain string) (cacheable, error) {
			return configService.getEndpointAnchorOrigin(did)
		}))

	return configService, nil
}

func makeCache(fetcher func(did, domain string) (interface{}, *time.Duration, error)) gcache.Cache {
	return gcache.New(0).LoaderExpireFunc(func(key interface{}) (interface{}, *time.Duration, error) {
		r, ok := key.(req)
		if !ok {
			return nil, nil, fmt.Errorf("key must be stringPair")
		}

		return fetcher(r.did, r.domain)
	}).Build()
}

type cacheable interface {
	CacheLifetime() (time.Duration, error)
}

func (cs *Service) getNewCacheable(
	fetcher func(did, domain string) (cacheable, error),
) func(did, domain string) (interface{}, *time.Duration, error) {
	return func(did, domain string) (interface{}, *time.Duration, error) {
		data, err := fetcher(did, domain)
		if err != nil {
			return nil, nil, fmt.Errorf("fetching cacheable object: %w", err)
		}

		expiryTime, err := data.CacheLifetime()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get object expiry time: %w", err)
		}

		return data, &expiryTime, nil
	}
}

func getEntryHelper(cache gcache.Cache, key interface{}, objectName string) (interface{}, error) {
	data, err := cache.Get(key)
	if err != nil {
		return nil, fmt.Errorf("getting %s from cache: %w", objectName, err)
	}

	return data, nil
}

// GetSidetreeConfig returns the sidetree config.
func (cs *Service) GetSidetreeConfig() (*models.SidetreeConfig, error) {
	sidetreeConfigDataInterface, err := getEntryHelper(cs.sidetreeConfigCache, req{
		domain: "",
	}, "sidetreeconfig")
	if err != nil {
		return nil, err
	}

	return sidetreeConfigDataInterface.(*models.SidetreeConfig), nil
}

// GetEndpoint fetches endpoints from domain, caching the value.
func (cs *Service) GetEndpoint(domain string) (*models.Endpoint, error) {
	endpoint, err := getEntryHelper(cs.endpointsCache, req{
		domain: domain,
	}, "endpoint")
	if err != nil {
		return nil, err
	}

	return endpoint.(*models.Endpoint), nil
}

// GetEndpointFromAnchorOrigin fetches endpoints from anchor origin, caching the value.
func (cs *Service) GetEndpointFromAnchorOrigin(didURI string) (*models.Endpoint, error) {
	endpoint, err := getEntryHelper(cs.endpointsAnchorOriginCache, req{
		did: didURI,
	}, "endpointAnchorOrigin")
	if err != nil {
		return nil, err
	}

	return endpoint.(*models.Endpoint), nil
}

func (cs *Service) getSidetreeConfig() (*models.SidetreeConfig, error) { //nolint:unparam
	// TODO fetch sidetree config
	// for now return default values
	return &models.SidetreeConfig{MultiHashAlgorithm: sha2_256, MaxAge: maxAge}, nil
}

func (cs *Service) getEndpoint(domain string) (*models.Endpoint, error) {
	var wellKnownResponse restapi.WellKnownResponse

	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}

	err := cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s/.well-known/did-orb", domain), &wellKnownResponse)
	if err != nil {
		return nil, err
	}

	var jrd restapi.JRD

	parsedURL, err := url.Parse(wellKnownResponse.ResolutionEndpoint)
	if err != nil {
		return nil, err
	}

	endpoint, err := cs.populateResolutionEndpoint(fmt.Sprintf("%s://%s/.well-known/webfinger?resource=%s",
		parsedURL.Scheme, parsedURL.Host, url.PathEscape(wellKnownResponse.ResolutionEndpoint)))
	if err != nil {
		return nil, err
	}

	err = cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s://%s/.well-known/webfinger?resource=%s",
		parsedURL.Scheme, parsedURL.Host, url.PathEscape(wellKnownResponse.OperationEndpoint)), &jrd)
	if err != nil {
		return nil, err
	}

	for _, v := range jrd.Links {
		endpoint.OperationEndpoints = append(endpoint.OperationEndpoints, v.Href)
	}

	return endpoint, nil
}

func (cs *Service) populateAnchorResolutionEndpoint(
	jrd *restapi.JRD) (*models.Endpoint, error) {
	endpoint := &models.Endpoint{}

	min, ok := jrd.Properties[minResolvers].(float64)
	if !ok {
		return nil, fmt.Errorf("%s property is not float64", minResolvers)
	}

	endpoint.MinResolvers = int(min)

	for _, v := range jrd.Links {
		if v.Type == "application/did+ld+json" {
			endpoint.ResolutionEndpoints = append(endpoint.ResolutionEndpoints,
				v.Href[:strings.Index(v.Href, fmt.Sprintf("did:%s", didMethod))-1])
		}
	}

	return endpoint, nil
}

//nolint: funlen,gocyclo
func (cs *Service) populateResolutionEndpoint(webFingerURL string) (*models.Endpoint, error) {
	var jrd restapi.JRD

	err := cs.sendRequest(nil, http.MethodGet, webFingerURL, &jrd)
	if err != nil {
		return nil, err
	}

	endpoint := &models.Endpoint{}

	min, ok := jrd.Properties[minResolvers].(float64)
	if !ok {
		return nil, fmt.Errorf("%s property is not float64", minResolvers)
	}

	endpoint.MinResolvers = int(min)

	m := make(map[string]struct{})

	for _, v := range jrd.Links {
		m[v.Href] = struct{}{}
	}

	// Fetches the configurations at each chosen link using WebFinger.
	// Validates that each well-known configuration has the same policy for n and that all of the
	// chosen links are listed in the n fetched configurations.

	for _, v := range jrd.Links {
		if v.Rel != "self" { //nolint: nestif
			var webFingerResp restapi.JRD

			parsedURL, err := url.Parse(v.Href)
			if err != nil {
				return nil, err
			}

			err = cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s://%s/.well-known/webfinger?resource=%s",
				parsedURL.Scheme, parsedURL.Host, url.PathEscape(v.Href)), &webFingerResp)
			if err != nil {
				return nil, err
			}

			min, ok = webFingerResp.Properties[minResolvers].(float64)
			if !ok {
				return nil, fmt.Errorf("%s property is not float64", minResolvers)
			}

			if int(min) != endpoint.MinResolvers {
				logger.Warnf("%s has different policy for n %s", v.Href, minResolvers)

				continue
			}

			if len(webFingerResp.Links) != len(jrd.Links) {
				logger.Warnf("%s has different link", v.Href, minResolvers)

				continue
			}

			for _, link := range webFingerResp.Links {
				if _, ok = m[link.Href]; !ok {
					logger.Warnf("%s has different link", v.Href, minResolvers)

					continue
				}
			}
		}

		endpoint.ResolutionEndpoints = append(endpoint.ResolutionEndpoints, v.Href)
	}

	return endpoint, nil
}

func (cs *Service) getEndpointAnchorOrigin(didURI string) (*models.Endpoint, error) {
	didSplit := strings.Split(didURI, ":")

	if len(didSplit) < didParts {
		return nil, fmt.Errorf("did format is wrong")
	}

	result, err := cs.orbClient.GetAnchorOrigin(didSplit[3], didSplit[4])
	if err != nil {
		return nil, err
	}

	anchorOrigin, ok := result.(string)
	if !ok {
		return nil, fmt.Errorf("get anchor origin didn't return string")
	}

	currentAnchorOrigin := anchorOrigin

	var currentWebFingerRespone *restapi.JRD

	for {
		jrdLatestAnchorOrigin, errGet := cs.getLatestAnchorOrigin(currentAnchorOrigin, didURI)
		if errGet != nil {
			return nil, errGet
		}

		latestAnchorOrigin, ok := jrdLatestAnchorOrigin.Properties[anchorOriginProperty].(string)
		if !ok {
			return nil, fmt.Errorf("%s property is not string", anchorOriginProperty)
		}

		if latestAnchorOrigin == currentAnchorOrigin {
			currentWebFingerRespone = jrdLatestAnchorOrigin

			break
		}

		currentAnchorOrigin = latestAnchorOrigin
	}

	return cs.populateAnchorResolutionEndpoint(currentWebFingerRespone)
}

func (cs *Service) getWebFingerURL(anchorOrigin string) (string, error) {
	if strings.HasPrefix(anchorOrigin, "ipns://") {
		anchorOriginSplit := strings.Split(anchorOrigin, "ipns://")

		return fmt.Sprintf("%s/%s/%s/.well-known/host-meta.json", ipfsGlobal, "ipns",
			anchorOriginSplit[1]), nil
	} else if strings.HasPrefix(anchorOrigin, "http://") || strings.HasPrefix(anchorOrigin, "https://") {
		parsedURL, err := url.Parse(anchorOrigin)
		if err != nil {
			return "", err
		}

		urlValue := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

		return fmt.Sprintf("%s/.well-known/host-meta.json", urlValue), nil
	}

	return "", fmt.Errorf("anchorOrigin %s not supported", anchorOrigin)
}

func (cs *Service) getLatestAnchorOrigin(anchorOrigin, didURI string) (*restapi.JRD, error) {
	var jrd restapi.JRD

	webFingerURL, err := cs.getWebFingerURL(anchorOrigin)
	if err != nil {
		return nil, err
	}

	err = cs.sendRequest(nil, http.MethodGet, webFingerURL, &jrd)
	if err != nil {
		return nil, err
	}

	templateURL := ""

	for _, v := range jrd.Links {
		if v.Rel == "self" && v.Type == "application/jrd+json" {
			templateURL = strings.ReplaceAll(v.Template, "{uri}", didURI)

			break
		}
	}

	if templateURL == "" {
		return nil, fmt.Errorf("failed to find template url in webfinger doc")
	}

	err = cs.sendRequest(nil, http.MethodGet, templateURL, &jrd)
	if err != nil {
		return nil, err
	}

	return &jrd, nil
}

func (cs *Service) send(req []byte, method, endpointURL string) ([]byte, error) {
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

	resp, err := cs.httpClient.Do(httpReq)
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

func (cs *Service) sendRequest(req []byte, method, endpointURL string, respObj interface{}) error { //nolint: unparam
	responseBytes, err := cs.send(req, method, endpointURL)
	if err != nil {
		return err
	}

	return json.Unmarshal(responseBytes, &respObj)
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		logger.Errorf("Failed to close response body: %v", e)
	}
}

// Option is a config service instance option.
type Option func(opts *Service)

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient httpClient) Option {
	return func(opts *Service) {
		opts.httpClient = httpClient
	}
}

// WithAuthToken add auth token.
func WithAuthToken(authToken string) Option {
	return func(opts *Service) {
		opts.authToken = "Bearer " + authToken
	}
}

// WithDisableProofCheck disable proof check.
func WithDisableProofCheck(disable bool) Option {
	return func(opts *Service) {
		opts.disableProofCheck = disable
	}
}

type webVDR struct {
	http httpClient
	*web.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return w.VDR.Read(didID, append(opts, vdrapi.WithOption(web.HTTPClientOpt, w.http))...)
}

// casReader.
type casReader struct {
	s *Service
}

func (c *casReader) Read(key string) ([]byte, error) {
	return c.s.send(nil, http.MethodGet, fmt.Sprintf("%s/%s/%s", ipfsGlobal, "ipfs", key))
}
