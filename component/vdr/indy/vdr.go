/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package indy implements a VDR interface for Aries (aries-framework-go).
//
package indy

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/indy-vdr/wrappers/golang/vdr"
)

const (
	// DefaultServiceType default service type.
	DefaultServiceType = "defaultServiceType"
	// DefaultServiceEndpoint default service endpoint.
	DefaultServiceEndpoint = "defaultServiceEndpoint"
)

// Client is the API for interacting with the Indy VDR client.
type Client interface {
	GetNym(did string) (*vdr.ReadReply, error)
	GetEndpoint(did string) (*vdr.ReadReply, error)
	GetPoolStatus() (*vdr.PoolStatus, error)
	RefreshPool() error
	Close() error
}

// VDR represents a Verifiable Data Registry for use with Indy ledgers.
type VDR struct {
	MethodName string
	Refresh    bool
	Client     Client
}

// New creates an instance of an Indy VDR.
func New(methodName string, opts ...Option) (*VDR, error) {
	vdri := &VDR{MethodName: methodName}

	for _, opt := range opts {
		opt(vdri)
	}

	if vdri.Client == nil {
		return nil, errors.New("an Indy Ledger client must be set with an option to New")
	}

	if vdri.Refresh {
		err := vdri.Client.RefreshPool()
		if err != nil {
			return nil, fmt.Errorf("refreshing indy pool failed: %w", err)
		}
	}

	return vdri, nil
}

// Accept the did method.
func (v *VDR) Accept(method string) bool {
	return method == v.MethodName
}

// Update did doc.
func (v *VDR) Update(didDoc *diddoc.Doc, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(did string, opts ...vdrapi.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Close the client connection.
func (v *VDR) Close() error {
	return v.Client.Close()
}

// Option configures the Indy vdri.
type Option func(opts *VDR)

// WithRefresh option configuring an initial refresh of the Indy pool.
func WithRefresh(refresh bool) Option {
	return func(opts *VDR) {
		opts.Refresh = refresh
	}
}

// WithIndyClient configures the VDR with an existing Indy Client.
func WithIndyClient(client Client) Option {
	return func(opts *VDR) {
		opts.Client = client
	}
}

// WithIndyVDRGenesisFile configures the VDR with a genesis file.
func WithIndyVDRGenesisFile(genesisFile string) Option {
	return func(opts *VDR) {
		gfr, err := os.Open(filepath.Clean(genesisFile))
		if err != nil {
			log.Println("unable to open genesis file", err)

			return
		}

		opts.Client, err = vdr.New(gfr)
		if err != nil {
			err = fmt.Errorf("error connecting to indy ledger: (%w)", err)
			log.Println(err)
		}
	}
}

// WithIndyVDRGenesisReader configures the VDR with a genesis reader.
func WithIndyVDRGenesisReader(genesisData io.ReadCloser) Option {
	return func(opts *VDR) {
		var err error

		opts.Client, err = vdr.New(genesisData)
		if err != nil {
			err = fmt.Errorf("error connecting to indy ledger: (%w)", err)
			log.Println(err)
		}
	}
}
