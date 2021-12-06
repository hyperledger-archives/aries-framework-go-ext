// +build trace

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package tracing

import (
	"context"

	"github.com/opentracing/opentracing-go"
)

// StartChildSpan returns a started child Span and context loaded with the Span.
func StartChildSpan(ctx context.Context, name string) (opentracing.Span, context.Context) {
	if ctx != nil {
		if span := opentracing.SpanFromContext(ctx); span != nil {
			childSpan := opentracing.StartSpan(name, opentracing.ChildOf(span.Context()))
			childCtx := opentracing.ContextWithSpan(context.Background(), childSpan)

			return childSpan, childCtx
		}
	}

	return nil, context.TODO()
}
