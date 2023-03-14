/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package resolver provides a resolver for remotely-stored credential status list VCs.
package resolver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// Resolver resolves credential status list VCs.
type Resolver struct {
	client      *http.Client
	bearerToken string
}

// NewResolver creates a Resolver.
func NewResolver(client *http.Client, bearerToken string) *Resolver {
	return &Resolver{
		client:      client,
		bearerToken: bearerToken,
	}
}

// Resolve fetches the VC at the given URI.
func (r *Resolver) Resolve(statusListVCURI string) (*verifiable.Credential, error) {
	var (
		vcBytes []byte
		err     error
	)

	if strings.HasPrefix(statusListVCURI, "did:") {
		return nil, fmt.Errorf("did-uri status list VC resolution not supported")
	}

	req, e := http.NewRequestWithContext(context.Background(), http.MethodGet, statusListVCURI, nil)
	if e != nil {
		return nil, e
	}

	vcBytes, err = r.sendHTTPRequest(req, http.StatusOK, r.bearerToken)

	if err != nil {
		return nil, fmt.Errorf("unable to resolve statusListVCURI: %w", err)
	}

	// TODO: need to verify proof on vc - consider if validation also needs to be done (json-ld and json schema)
	vc, err := verifiable.ParseCredential(
		vcBytes,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithCredDisableValidation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify status vc: %w", err)
	}

	return vc, nil
}

func (r *Resolver) sendHTTPRequest(req *http.Request, status int, token string) ([]byte, error) {
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			fmt.Printf("failed to close message body: %v", e)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response, code=%d: %w", resp.StatusCode, err)
	}

	if resp.StatusCode != status {
		return nil, fmt.Errorf("expected response code %d, got %d", status, resp.StatusCode)
	}

	return body, nil
}
