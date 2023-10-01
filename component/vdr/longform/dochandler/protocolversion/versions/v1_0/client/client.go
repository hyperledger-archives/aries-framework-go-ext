/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"github.com/trustbloc/sidetree-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-go/pkg/versions/1_0/doccomposer"
	"github.com/trustbloc/sidetree-go/pkg/versions/1_0/doctransformer/didtransformer"
	"github.com/trustbloc/sidetree-go/pkg/versions/1_0/docvalidator/didvalidator"
	"github.com/trustbloc/sidetree-go/pkg/versions/1_0/operationapplier"
	"github.com/trustbloc/sidetree-go/pkg/versions/1_0/operationparser"

	vcommon "github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/versions/common"
	protocolcfg "github.com/hyperledger/aries-framework-go-ext/component/vdr/longform/dochandler/protocolversion/versions/v1_0/config"
)

// Factory implements version 0.1 of the client factory.
type Factory struct{}

// New returns a version 1.0 implementation of the Sidetree protocol.
func New() *Factory {
	return &Factory{}
}

// Create returns a 1.0 client version.
func (v *Factory) Create(version string, config *vcommon.ProtocolConfig) (protocol.Version, error) {
	p := protocolcfg.GetProtocolConfig()

	op := operationparser.New(p)

	dc := doccomposer.New()
	oa := operationapplier.New(p, op, dc)

	dv := didvalidator.New()
	dt := didtransformer.New(
		didtransformer.WithMethodContext(config.MethodContext),
		didtransformer.WithBase(config.EnableBase))

	return &vcommon.ProtocolVersion{
		VersionStr:     version,
		P:              p,
		OpParser:       op,
		OpApplier:      oa,
		DocComposer:    dc,
		DocValidator:   dv,
		DocTransformer: dt,
	}, nil
}
