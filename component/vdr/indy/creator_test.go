/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/vdr/indy"
)

func TestVDRI_Build(t *testing.T) {
	t.Run("illegal key type", func(t *testing.T) {
		r := &VDR{
			MethodName: "sov",
		}

		pubKeys := []did.VerificationMethod{{
			ID:    "test",
			Value: []byte("test"),
			Type:  "Not Valid",
		}}

		services := []did.Service{{
			Type: "did-communication",
		}}

		doc, err := r.Create(
			&did.Doc{
				VerificationMethod: pubKeys,
				Service:            services,
			})
		require.Nil(t, doc)
		require.Error(t, err)
	})

	t.Run("valid key", func(t *testing.T) {
		r := &VDR{
			MethodName: "sov",
		}

		k := ed25519.NewKeyFromSeed([]byte("b2352b32947e188eb72871093ac6217e"))

		pubKeys := []did.VerificationMethod{{
			ID:    "test",
			Value: []byte(base58.Encode(k)),
			Type:  "Ed25519VerificationKey2018",
		}}

		doc, err := r.Create(
			&did.Doc{
				ID:                 "did:sov:D8HmB7s9KCGuPGbi5Ymiqr",
				VerificationMethod: pubKeys,
			})

		require.NotNil(t, doc)
		require.NoError(t, err)

		didDoc := doc.DIDDocument

		require.NotNil(t, didDoc)
		require.Equal(t, "did:sov:D8HmB7s9KCGuPGbi5Ymiqr", didDoc.ID)
		require.NotNil(t, didDoc.Context)
		require.NotNil(t, didDoc.Updated)
		require.NotNil(t, didDoc.Created)
		require.Len(t, didDoc.Authentication, 1)
		require.Len(t, didDoc.VerificationMethod, 1)
		require.Nil(t, didDoc.Service)
	})

	t.Run("valid key with service endpoint", func(t *testing.T) {
		r := &VDR{
			MethodName: "sov",
		}

		k := ed25519.NewKeyFromSeed([]byte("b2352b32947e188eb72871093ac6217e"))
		pubKeys := []did.VerificationMethod{{
			ID:    "test",
			Value: []byte(base58.Encode(k)),
			Type:  "Ed25519VerificationKey2018",
		}}

		ep := "http://127.0.0.1:8080"

		services := []did.Service{{
			Type:            "did-communication",
			ServiceEndpoint: ep,
		}}

		doc, err := r.Create(
			&did.Doc{
				ID:                 "did:sov:D8HmB7s9KCGuPGbi5Ymiqr",
				VerificationMethod: pubKeys,
				Service:            services,
			})

		require.NoError(t, err)
		require.NotNil(t, doc)

		didDoc := doc.DIDDocument

		require.Equal(t, "did:sov:D8HmB7s9KCGuPGbi5Ymiqr", didDoc.ID)
		require.NotNil(t, didDoc.Context)
		require.NotNil(t, didDoc.Updated)
		require.NotNil(t, didDoc.Created)
		require.Len(t, didDoc.Authentication, 1)
		require.Len(t, didDoc.VerificationMethod, 1)

		require.NotNil(t, didDoc.Service)
		require.Len(t, didDoc.Service, 1)
		require.Equal(t, ep, didDoc.Service[0].ServiceEndpoint)
	})
}
