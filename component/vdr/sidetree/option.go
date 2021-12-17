/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package sidetree

import (
	"net/http"
)

// Option is a DID client instance option.
type Option func(opts *Client)

// WithHTTPClient option is for custom http client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(opts *Client) {
		opts.client = httpClient
	}
}

// WithAuthToken add auth token.
func WithAuthToken(authToken string) Option {
	return func(opts *Client) {
		opts.authToken = "Bearer " + authToken
	}
}
