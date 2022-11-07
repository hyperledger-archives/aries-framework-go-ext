/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verprovider

import (
	"fmt"
	"sort"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

// ClientVersionProvider implements client versions.
type ClientVersionProvider struct {
	versions []protocol.Version
	current  protocol.Version
}

// Option is an option for client.
type Option func(opts *ClientVersionProvider)

// WithCurrentProtocolVersion sets optional current client protocol version (defaults to last registered protocol).
func WithCurrentProtocolVersion(version string) Option {
	return func(opts *ClientVersionProvider) {
		for _, p := range opts.versions {
			if p.Version() == version {
				opts.current = p

				return
			}
		}
	}
}

// New creates new client version provider.
func New(clientVersions []protocol.Version, opts ...Option) (*ClientVersionProvider, error) {
	if len(clientVersions) == 0 {
		return nil, fmt.Errorf("must provide at least one client version")
	}

	// Creating the list of the client versions
	var versions []protocol.Version

	versions = append(versions, clientVersions...)

	// Sorting the client version list based on version genesis time
	sort.SliceStable(versions, func(i, j int) bool {
		return versions[j].Protocol().GenesisTime > versions[i].Protocol().GenesisTime
	})

	client := &ClientVersionProvider{
		versions: versions,
		current:  versions[len(versions)-1],
	}

	// apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// Current returns the latest version of client.
func (c *ClientVersionProvider) Current() (protocol.Version, error) {
	return c.current, nil
}

// Get gets client version based on version time.
func (c *ClientVersionProvider) Get(versionTime uint64) (protocol.Version, error) {
	for i := len(c.versions) - 1; i >= 0; i-- {
		cv := c.versions[i]
		p := cv.Protocol()

		if versionTime == p.GenesisTime {
			return cv, nil
		}
	}

	return nil, fmt.Errorf("client version is not defined for version genesis time: %d", versionTime)
}
