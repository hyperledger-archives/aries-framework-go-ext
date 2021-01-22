/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package memorycacheconfig implement memorycacheconfig
//
package memorycacheconfig

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
)

type config interface {
	GetConsortium(string, string) (*models.ConsortiumFileData, error)
	GetStakeholder(string, string) (*models.StakeholderFileData, error)
	GetSidetreeConfig(url string) (*models.SidetreeConfig, error)
}

// ConfigService fetches consortium and stakeholder configs using a wrapped config service, caching results in-memory.
type ConfigService struct {
	config              config
	cCache              gcache.Cache
	sCache              gcache.Cache
	sidetreeConfigCache gcache.Cache
}

// NewService create new ConfigService.
func NewService(config config) *ConfigService {
	configService := &ConfigService{
		config: config,
	}

	configService.cCache = makeCache(
		configService.getNewCacheable(func(url, domain string) (cacheable, error) {
			return configService.config.GetConsortium(url, domain)
		}))

	configService.sCache = makeCache(
		configService.getNewCacheable(func(url, domain string) (cacheable, error) {
			return configService.config.GetStakeholder(url, domain)
		}))

	configService.sidetreeConfigCache = makeCache(
		configService.getNewCacheable(func(url, domain string) (cacheable, error) {
			return configService.config.GetSidetreeConfig(url)
		}))

	return configService
}

type stringPair struct {
	url, domain string
}

func makeCache(fetcher func(url, domain string) (interface{}, *time.Duration, error)) gcache.Cache {
	return gcache.New(0).LoaderExpireFunc(func(key interface{}) (interface{}, *time.Duration, error) {
		keyStrPair, ok := key.(stringPair)
		if !ok {
			return nil, nil, fmt.Errorf("key must be stringPair")
		}

		return fetcher(keyStrPair.url, keyStrPair.domain)
	}).Build()
}

type cacheable interface {
	CacheLifetime() (time.Duration, error)
}

func (cs *ConfigService) getNewCacheable(
	fetcher func(url, domain string) (cacheable, error),
) func(url, domain string) (interface{}, *time.Duration, error) {
	return func(url, domain string) (interface{}, *time.Duration, error) {
		data, err := fetcher(url, domain)
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

// GetConsortium fetches and parses the consortium file at the given domain, caching the value.
func (cs *ConfigService) GetConsortium(url, domain string) (*models.ConsortiumFileData, error) {
	consortiumDataInterface, err := getEntryHelper(cs.cCache, stringPair{
		url:    url,
		domain: domain,
	}, "consortium")
	if err != nil {
		return nil, err
	}

	return consortiumDataInterface.(*models.ConsortiumFileData), nil
}

// GetStakeholder returns the stakeholder config file fetched by the wrapped config service, caching the value.
func (cs *ConfigService) GetStakeholder(url, domain string) (*models.StakeholderFileData, error) {
	stakeholderDataInterface, err := getEntryHelper(cs.sCache, stringPair{
		url:    url,
		domain: domain,
	}, "stakeholder")
	if err != nil {
		return nil, err
	}

	return stakeholderDataInterface.(*models.StakeholderFileData), nil
}

// GetSidetreeConfig returns the sidetree config.
func (cs *ConfigService) GetSidetreeConfig(url string) (*models.SidetreeConfig, error) {
	sidetreeConfigDataInterface, err := getEntryHelper(cs.sidetreeConfigCache, stringPair{
		url: url,
	}, "sidetreeconfig")
	if err != nil {
		return nil, err
	}

	return sidetreeConfigDataInterface.(*models.SidetreeConfig), nil
}
