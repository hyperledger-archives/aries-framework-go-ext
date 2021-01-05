/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/vdr/indy"
)

func TestVDRI_Build(t *testing.T) {
	t.Run("illegal key type", func(t *testing.T) {
		r := &VDR{
			MethodName: "sov",
		}

		pubKey := &vdrapi.PubKey{
			ID:    "test",
			Value: []byte("test"),
			Type:  "Not Valid",
		}

		doc, err := r.Build(pubKey)
		require.Nil(t, doc)
		require.Error(t, err)
	})

	t.Run("valid key", func(t *testing.T) {
		r := &VDR{
			MethodName: "sov",
		}

		k := ed25519.NewKeyFromSeed([]byte("b2352b32947e188eb72871093ac6217e"))
		pubKey := &vdrapi.PubKey{
			ID:    "test",
			Value: []byte(base58.Encode(k)),
			Type:  "Ed25519VerificationKey2018",
		}

		doc, err := r.Build(pubKey)
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.Equal(t, "did:sov:D8HmB7s9KCGuPGbi5Ymiqr", doc.ID)
		require.NotNil(t, doc.Context)
		require.NotNil(t, doc.Updated)
		require.NotNil(t, doc.Created)
		require.Len(t, doc.Authentication, 1)
		require.Len(t, doc.VerificationMethod, 1)
		require.Nil(t, doc.Service)
	})

	t.Run("valid key with service endpoint", func(t *testing.T) {
		r := &VDR{
			MethodName: "sov",
		}

		k := ed25519.NewKeyFromSeed([]byte("b2352b32947e188eb72871093ac6217e"))
		pubKey := &vdrapi.PubKey{
			ID:    "test",
			Value: []byte(base58.Encode(k)),
			Type:  "Ed25519VerificationKey2018",
		}

		ep := "http://127.0.0.1:8080"
		doc, err := r.Build(pubKey, vdrapi.WithDefaultServiceType(vdrapi.DIDCommServiceType),
			vdrapi.WithDefaultServiceEndpoint(ep))
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.Equal(t, "did:sov:D8HmB7s9KCGuPGbi5Ymiqr", doc.ID)
		require.NotNil(t, doc.Context)
		require.NotNil(t, doc.Updated)
		require.NotNil(t, doc.Created)
		require.Len(t, doc.Authentication, 1)
		require.Len(t, doc.VerificationMethod, 1)

		require.NotNil(t, doc.Service)
		require.Len(t, doc.Service, 1)
		require.Equal(t, ep, doc.Service[0].ServiceEndpoint)
	})
}
