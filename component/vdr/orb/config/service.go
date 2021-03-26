/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package config implement orb config
//
package config

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb/models"
)

const (
	// default hashes for sidetree.
	sha2_256 = 18 // multihash
	maxAge   = 3600
)

// Service fetches configs, caching results in-memory.
type Service struct {
	sidetreeConfigCache gcache.Cache
}

// NewService create new ConfigService.
func NewService() *Service {
	configService := &Service{}

	configService.sidetreeConfigCache = makeCache(
		configService.getNewCacheable(func() (cacheable, error) {
			return configService.getSidetreeConfig()
		}))

	return configService
}

func makeCache(fetcher func() (interface{}, *time.Duration, error)) gcache.Cache {
	return gcache.New(0).LoaderExpireFunc(func(key interface{}) (interface{}, *time.Duration, error) {
		return fetcher()
	}).Build()
}

type cacheable interface {
	CacheLifetime() (time.Duration, error)
}

func (cs *Service) getNewCacheable(
	fetcher func() (cacheable, error),
) func() (interface{}, *time.Duration, error) {
	return func() (interface{}, *time.Duration, error) {
		data, err := fetcher()
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
	sidetreeConfigDataInterface, err := getEntryHelper(cs.sidetreeConfigCache, nil, "sidetreeconfig")
	if err != nil {
		return nil, err
	}

	return sidetreeConfigDataInterface.(*models.SidetreeConfig), nil
}

func (cs *Service) getSidetreeConfig() (*models.SidetreeConfig, error) { //nolint:unparam
	// TODO fetch sidetree config
	// for now return default values
	return &models.SidetreeConfig{MultiHashAlgorithm: sha2_256, MaxAge: maxAge}, nil
}
