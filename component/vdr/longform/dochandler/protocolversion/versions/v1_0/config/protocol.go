/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

// GetProtocolConfig returns protocol config for this version.
func GetProtocolConfig() protocol.Protocol {
	p := protocol.Protocol{
		GenesisTime:                  0,
		MultihashAlgorithms:          []uint{18},
		MaxOperationCount:            10000,
		MaxOperationSize:             2500,
		MaxOperationHashLength:       100,
		MaxDeltaSize:                 1700,
		MaxCasURILength:              500,
		CompressionAlgorithm:         "GZIP",
		MaxChunkFileSize:             10000000,
		MaxProvisionalIndexFileSize:  1000000,
		MaxCoreIndexFileSize:         1000000,
		MaxProofFileSize:             2500000,
		Patches:                      []string{"replace", "add-public-keys", "remove-public-keys", "add-services", "remove-services", "add-also-known-as", "remove-also-known-as"}, //nolint:lll
		SignatureAlgorithms:          []string{"EdDSA", "ES256", "ES256K"},
		KeyAlgorithms:                []string{"Ed25519", "P-256", "P-384", "secp256k1"},
		MaxMemoryDecompressionFactor: 3,
		NonceSize:                    16,
	}

	return p
}
