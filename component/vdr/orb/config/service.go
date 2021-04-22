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
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/models"
)

var logger = log.New("aries-framework-ext/vdr/orb") //nolint: gochecknoglobals

const (
	// default hashes for sidetree.
	sha2_256     = 18 // multihash
	maxAge       = 3600
	minResolvers = "https://trustbloc.dev/ns/min-resolvers"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Service fetches configs, caching results in-memory.
type Service struct {
	sidetreeConfigCache gcache.Cache
	endpointsCache      gcache.Cache
	httpClient          httpClient
	authToken           string
}

type req struct {
	domain string
}

// NewService create new ConfigService.
func NewService(opts ...Option) *Service {
	configService := &Service{httpClient: &http.Client{}}

	for _, opt := range opts {
		opt(configService)
	}

	configService.sidetreeConfigCache = makeCache(
		configService.getNewCacheable(func(domain string) (cacheable, error) {
			return configService.getSidetreeConfig()
		}))

	configService.endpointsCache = makeCache(
		configService.getNewCacheable(func(domain string) (cacheable, error) {
			return configService.getEndpoint(domain)
		}))

	return configService
}

func makeCache(fetcher func(domain string) (interface{}, *time.Duration, error)) gcache.Cache {
	return gcache.New(0).LoaderExpireFunc(func(key interface{}) (interface{}, *time.Duration, error) {
		r, ok := key.(req)
		if !ok {
			return nil, nil, fmt.Errorf("key must be request")
		}

		return fetcher(r.domain)
	}).Build()
}

type cacheable interface {
	CacheLifetime() (time.Duration, error)
}

func (cs *Service) getNewCacheable(
	fetcher func(domain string) (cacheable, error),
) func(domain string) (interface{}, *time.Duration, error) {
	return func(domain string) (interface{}, *time.Duration, error) {
		data, err := fetcher(domain)
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

func (cs *Service) getSidetreeConfig() (*models.SidetreeConfig, error) { //nolint:unparam
	// TODO fetch sidetree config
	// for now return default values
	return &models.SidetreeConfig{MultiHashAlgorithm: sha2_256, MaxAge: maxAge}, nil
}

func (cs *Service) getEndpoint(domain string) (*models.Endpoint, error) { //nolint: funlen,gocyclo
	var wellKnownResponse restapi.WellKnownResponse

	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}

	err := cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s/.well-known/did-orb", domain), &wellKnownResponse)
	if err != nil {
		return nil, err
	}

	var webFingerResponse restapi.WebFingerResponse

	err = cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s/.well-known/webfinger?resource=%s",
		domain, url.PathEscape(wellKnownResponse.ResolutionEndpoint)), &webFingerResponse)
	if err != nil {
		return nil, err
	}

	endpoint := &models.Endpoint{}

	min, ok := webFingerResponse.Properties[minResolvers].(float64)
	if !ok {
		return nil, fmt.Errorf("%s property is not float64", minResolvers)
	}

	endpoint.MinResolvers = int(min)

	m := make(map[string]struct{})

	for _, v := range webFingerResponse.Links {
		m[v.Href] = struct{}{}
	}

	// Fetches the configurations at each chosen link using WebFinger.
	// Validates that each well-known configuration has the same policy for n and that all of the
	// chosen links are listed in the n fetched configurations.

	for _, v := range webFingerResponse.Links {
		if v.Rel != "self" { //nolint: nestif
			var webFingerResp restapi.WebFingerResponse

			err = cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s/.well-known/webfinger?resource=%s",
				domain, url.PathEscape(v.Href)), &webFingerResp)
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

			if len(webFingerResp.Links) != len(webFingerResponse.Links) {
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

	err = cs.sendRequest(nil, http.MethodGet, fmt.Sprintf("%s/.well-known/webfinger?resource=%s",
		domain, url.PathEscape(wellKnownResponse.OperationEndpoint)), &webFingerResponse)
	if err != nil {
		return nil, err
	}

	for _, v := range webFingerResponse.Links {
		endpoint.OperationEndpoints = append(endpoint.OperationEndpoints, v.Href)
	}

	return endpoint, nil
}

func (cs *Service) sendRequest(req []byte, method, endpointURL string, respObj interface{}) error { //nolint: unparam
	var httpReq *http.Request

	var err error

	if len(req) == 0 {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, nil)
		if err != nil {
			return fmt.Errorf("failed to create http request: %w", err)
		}
	} else {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, bytes.NewBuffer(req))
		if err != nil {
			return fmt.Errorf("failed to create http request: %w", err)
		}
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := cs.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response : %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	if err := json.Unmarshal(responseBytes, &respObj); err != nil {
		return err
	}

	return nil
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
