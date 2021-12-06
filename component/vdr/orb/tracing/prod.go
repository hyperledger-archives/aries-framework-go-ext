// +build !trace

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package tracing implement trace
//
package tracing

import (
	"context"

	"github.com/opentracing/opentracing-go"
)

// StartChildSpan returns a started child Span and context loaded with the Span.
func StartChildSpan(ctx context.Context, name string) (opentracing.Span, context.Context) {
	return nil, context.TODO()
}
