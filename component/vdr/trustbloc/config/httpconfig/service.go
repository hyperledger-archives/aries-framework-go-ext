/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package httpconfig implement httpconfig
//
package httpconfig

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

const (
	// default hashes for sidetree.
	sha2_256 = 18 // multihash
	maxAge   = 3600
)

// ConfigService fetches consortium and stakeholder configs over http.
type ConfigService struct {
	httpClient *http.Client
	tlsConfig  *tls.Config
	authToken  string
}

// NewService create new ConfigService.
func NewService(opts ...Option) *ConfigService {
	configService := &ConfigService{httpClient: &http.Client{}}

	for _, opt := range opts {
		opt(configService)
	}

	configService.httpClient.Transport = &http.Transport{TLSClientConfig: configService.tlsConfig}

	return configService
}

const (
	consortiumURLInfix  = "/.well-known/did-trustbloc/"
	consortiumURLSuffix = ".json"
)

func configURL(urlDomain, consortiumDomain string) string {
	prefix := ""
	if !strings.HasPrefix(urlDomain, "http://") && !strings.HasPrefix(urlDomain, "https://") {
		prefix = "https://"
	}

	return prefix + urlDomain + consortiumURLInfix + consortiumDomain + consortiumURLSuffix
}

// GetConsortium fetches and parses the consortium file at the given domain.
func (cs *ConfigService) GetConsortium(url, domain string) (*models.ConsortiumFileData, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, configURL(url, domain), nil)
	if err != nil {
		return nil, err
	}

	res, err := cs.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// nolint: errcheck
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		// TODO retry https://github.com/trustbloc/trustbloc-did-method/issues/159
		return nil, fmt.Errorf("consortium config request failed: error %d, `%s`", res.StatusCode, string(body))
	}

	return models.ParseConsortium(body)
}

// GetSidetreeConfig get sidetree config.
func (cs *ConfigService) GetSidetreeConfig(url string) (*models.SidetreeConfig, error) {
	url = fmt.Sprintf("%s/%s", url, "version")

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	if cs.authToken != "" {
		httpReq.Header.Add("Authorization", cs.authToken)
	}

	resp, err := cs.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	config := models.SidetreeConfig{MultiHashAlgorithm: sha2_256, MaxAge: maxAge}

	if resp.StatusCode != http.StatusOK {
		log.Warnf("return unexpected response from %s status '%d' body %s, will return default sidetree config",
			url, resp.StatusCode, responseBytes)

		return &config, nil
	}

	if err := json.Unmarshal(responseBytes, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// GetStakeholder fetches and parses a stakeholder file under the given url with the given domain.
func (cs *ConfigService) GetStakeholder(url, domain string) (*models.StakeholderFileData, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, configURL(url, domain), nil)
	if err != nil {
		return nil, err
	}

	res, err := cs.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// nolint: errcheck
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		// TODO retry https://github.com/trustbloc/trustbloc-did-method/issues/159
		return nil, fmt.Errorf("stakeholder config request failed: error %d, `%s`", res.StatusCode, string(body))
	}

	return models.ParseStakeholder(body)
}

// Option is a config service instance option.
type Option func(opts *ConfigService)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *ConfigService) {
		opts.tlsConfig = tlsConfig
	}
}

// WithAuthToken add auth token.
func WithAuthToken(authToken string) Option {
	return func(opts *ConfigService) {
		opts.authToken = "Bearer " + authToken
	}
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		log.Errorf("Failed to close response body: %v", e)
	}
}
