//go:build !testver
// +build !testver

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientregistry

import v1_0 "github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/versions/v1_0/client"

const (
	// V1_0 ...
	V1_0 = "1.0"
)

func addVersions(registry *Registry) {
	// register supported versions
	registry.Register(V1_0, v1_0.New())
}
