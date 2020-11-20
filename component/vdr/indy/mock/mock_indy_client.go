/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package mock contains mocks for testing against Indy VDR.
//
package mock

import (
	"github.com/hyperledger/indy-vdr/wrappers/golang/vdr"
)

// IndyClient is a mock for the Indy VDR.
type IndyClient struct {
	GetNymErr      error
	GetNymValue    *vdr.ReadReply
	GetEndpointErr error
	GetEndpointVal *vdr.ReadReply
	RefreshErr     error
	CloseErr       error
}

// GetNym mocks the GetNym method.
func (r *IndyClient) GetNym(did string) (*vdr.ReadReply, error) {
	if r.GetNymErr != nil {
		return nil, r.GetNymErr
	}

	return r.GetNymValue, nil
}

// GetEndpoint mocks the GetEndpoint method.
func (r *IndyClient) GetEndpoint(did string) (*vdr.ReadReply, error) {
	if r.GetEndpointErr != nil {
		return nil, r.GetEndpointErr
	}

	return r.GetEndpointVal, nil
}

// RefreshPool mocks the RefreshPool method.
func (r *IndyClient) RefreshPool() error {
	return r.RefreshErr
}

// Close mocks the close method.
func (r *IndyClient) Close() error {
	return r.CloseErr
}

// GetPoolStatus mocks the GetPoolStatus method.
func (r *IndyClient) GetPoolStatus() (*vdr.PoolStatus, error) {
	return &vdr.PoolStatus{}, nil
}
