/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package didconfiguration implement didconfiguration service
//
package didconfiguration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

// Service fetches and verifies DID-configurations.
type Service struct {
	httpClient *http.Client
	tlsConfig  *tls.Config
}

// NewService create new didconfiguration Service.
func NewService(opts ...Option) *Service {
	service := &Service{
		httpClient: &http.Client{},
	}

	for _, opt := range opts {
		opt(service)
	}

	service.httpClient.Transport = &http.Transport{TLSClientConfig: service.tlsConfig}

	return service
}

// VerifyStakeholder verify the DID configuration on a stakeholder server.
func (s *Service) VerifyStakeholder(domain string, doc *did.Doc) error {
	conf, err := s.getConfiguration(domain)
	if err != nil {
		return fmt.Errorf("can't get stakeholder `%s` did configuration: %w", domain, err)
	}

	_, err = VerifyDIDConfiguration(domain, conf, doc)
	if err != nil {
		return fmt.Errorf("stakeholder did configuration invalid: %w", err)
	}

	return nil
}

func (s *Service) getConfiguration(domain string) (*models.DIDConfiguration, error) {
	var url string
	if strings.HasPrefix(domain, "http") {
		url = domain
	} else {
		url = "https://" + domain
	}

	url += "/.well-known/did-configuration.json"

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	res, err := s.httpClient.Do(req)
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
		return nil, fmt.Errorf("stakeholder did-configuration request failed: error %d, `%s`", res.StatusCode, string(body))
	}

	var didConfig models.DIDConfiguration

	err = json.Unmarshal(body, &didConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse did configurations from body `%s` at url %s: %w", string(body), url, err)
	}

	return &didConfig, nil
}

// Option is a didconfiguration service instance option.
type Option func(opts *Service)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Service) {
		opts.tlsConfig = tlsConfig
	}
}
