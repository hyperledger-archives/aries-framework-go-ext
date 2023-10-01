/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"github.com/trustbloc/sidetree-go/pkg/api/protocol"
)

// ProtocolVersion implements the protocol.Version interface.
type ProtocolVersion struct {
	VersionStr     string
	P              protocol.Protocol
	OpParser       protocol.OperationParser
	OpApplier      protocol.OperationApplier
	DocComposer    protocol.DocumentComposer
	DocValidator   protocol.DocumentValidator
	DocTransformer protocol.DocumentTransformer
}

// Version returns the protocol parameters.
func (h *ProtocolVersion) Version() string {
	return h.VersionStr
}

// Protocol returns the protocol parameters.
func (h *ProtocolVersion) Protocol() protocol.Protocol {
	return h.P
}

// OperationParser returns the operation parser.
func (h *ProtocolVersion) OperationParser() protocol.OperationParser {
	return h.OpParser
}

// OperationApplier returns the operation applier.
func (h *ProtocolVersion) OperationApplier() protocol.OperationApplier {
	return h.OpApplier
}

// DocumentComposer returns the document composer.
func (h *ProtocolVersion) DocumentComposer() protocol.DocumentComposer {
	return h.DocComposer
}

// DocumentValidator returns the document validator.
func (h *ProtocolVersion) DocumentValidator() protocol.DocumentValidator {
	return h.DocValidator
}

// DocumentTransformer returns the document transformer.
func (h *ProtocolVersion) DocumentTransformer() protocol.DocumentTransformer {
	return h.DocTransformer
}

// ProtocolConfig hold setting for client protocol configuration.
type ProtocolConfig struct {
	MethodContext []string
	EnableBase    bool
}
