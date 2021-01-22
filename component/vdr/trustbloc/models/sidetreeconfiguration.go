/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"time"
)

// SidetreeConfig sidetree configuration.
type SidetreeConfig struct {
	MultiHashAlgorithm uint `json:"multihashAlgorithm"`
	MaxAge             uint `json:"-"`
}

// CacheLifetime returns the cache lifetime of the sidetree config file before it needs to be checked for an update.
func (c SidetreeConfig) CacheLifetime() (time.Duration, error) {
	return time.Duration(c.MaxAge) * time.Second, nil
}
