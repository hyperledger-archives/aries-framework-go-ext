/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package sidetree_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	vdrdoc "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/deactivate"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/recovery"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/update"
)

type didResolution struct {
	Context          interface{}     `json:"@context"`
	DIDDocument      json.RawMessage `json:"didDocument"`
	ResolverMetadata json.RawMessage `json:"resolverMetadata"`
	MethodMetadata   json.RawMessage `json:"methodMetadata"`
}

func TestClient_DeactivateDID(t *testing.T) {
	t.Run("test signing key empty", func(t *testing.T) {
		v := sidetree.New()

		err := v.DeactivateDID("did:ex:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "signing key is required")
	})

	t.Run("test reveal value is empty", func(t *testing.T) {
		v := sidetree.New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123", deactivate.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "reveal value is required")
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := sidetree.New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123", deactivate.WithSigningKey(privKey),
			deactivate.WithRevealValue("value"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "sidetree get endpoints func is required")

		err = v.DeactivateDID("did:ex:123", deactivate.WithRevealValue("value"),
			deactivate.WithSigningKey(privKey),
			deactivate.WithSidetreeEndpoint(func() ([]string, error) {
				return nil, fmt.Errorf("failed to get endpoint")
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoint")
	})

	t.Run("test unsupported signing key", func(t *testing.T) {
		v := sidetree.New()

		err := v.DeactivateDID("did:ex:123", deactivate.WithRevealValue("value"),
			deactivate.WithSigningKey("www"), deactivate.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported")
	})

	t.Run("test error from unique suffix", func(t *testing.T) {
		v := sidetree.New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("wrong", deactivate.WithRevealValue("value"), deactivate.WithSigningKey(privKey),
			deactivate.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unique suffix not provided in id")
	})

	t.Run("test error from send request", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v := sidetree.New(sidetree.WithAuthToken("tk1"))

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123", deactivate.WithRevealValue("value"),
			deactivate.WithSigningKey(privKey), deactivate.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send deactivate sidetree request")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer serv.Close()

		v := sidetree.New(sidetree.WithAuthToken("tk1"))

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(pubKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123", deactivate.WithSigningKey(privKey),
			deactivate.WithRevealValue(rv), deactivate.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{serv.URL}, nil
			}), deactivate.WithSigningKeyID("k1"))
		require.NoError(t, err)
	})
}

func TestClient_RecoverDID(t *testing.T) {
	t.Run("test next recovery key empty", func(t *testing.T) {
		v := sidetree.New()

		err := v.RecoverDID("did:ex:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery public key is required")
	})

	t.Run("test next update key empty", func(t *testing.T) {
		v := sidetree.New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithNextRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "next update public key is required")
	})

	t.Run("test signing key empty", func(t *testing.T) {
		v := sidetree.New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "signing key is required")
	})

	t.Run("test reveal value is empty", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "reveal value is required")
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithRevealValue("value"),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "sidetree get endpoints func is required")

		err = v.RecoverDID("did:ex:123", recovery.WithRevealValue("value"),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithSigningKey(privKey), recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return nil, fmt.Errorf("failed to get endpoint")
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoint")
	})

	t.Run("test failed to get next recovery key", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithRevealValue("value"), recovery.WithSigningKey(privKey),
			recovery.WithNextRecoveryPublicKey([]byte("wrong")), recovery.WithNextUpdatePublicKey(pubKey),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next recovery key")
	})

	t.Run("test failed to get next update key", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithRevealValue("value"), recovery.WithSigningKey(privKey),
			recovery.WithNextUpdatePublicKey([]byte("wrong")), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next update key")
	})

	t.Run("test unsupported signing key", func(t *testing.T) {
		v := sidetree.New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithRevealValue("value"),
			recovery.WithSigningKey("www"), recovery.WithNextUpdatePublicKey(pubKey),
			recovery.WithNextRecoveryPublicKey(pubKey), recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported")
	})

	t.Run("test error from unique suffix", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("wrong", recovery.WithRevealValue("value"), recovery.WithSigningKey(privKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unique suffix not provided in id")
	})

	t.Run("test error parse public key", func(t *testing.T) {
		v := sidetree.New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithRevealValue("value"), recovery.WithSigningKey(ecPrivKey),
			recovery.WithSigningKeyID("k1"), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}), recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&vdrdoc.PublicKey{
				ID:   "key3",
				Type: doc.JWSVerificationKey2020,
				JWK:  gojose.JSONWebKey{},
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported")
	})

	t.Run("test error from send request", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v := sidetree.New(sidetree.WithAuthToken("tk1"))

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithRevealValue("value"),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{serv.URL}, nil
			}), recovery.WithSigningKey(ecPrivKey), recovery.WithSigningKeyID("k1"),
			recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&vdrdoc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  gojose.JSONWebKey{Key: pubKey},
			}),
			recovery.WithService(&did.Service{ID: "svc3"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send recover sidetree request")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			b, err := json.Marshal(didResolution{
				Context:     "https://www.w3.org/ns/did-resolution/v1",
				DIDDocument: bytes,
			})
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := sidetree.New(sidetree.WithAuthToken("tk1"))

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(&signingKey.PublicKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithSidetreeEndpoint(func() ([]string, error) {
			return []string{serv.URL}, nil
		}), recovery.WithSigningKey(signingKey), recovery.WithRevealValue(rv),
			recovery.WithSigningKeyID("k1"), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&vdrdoc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  gojose.JSONWebKey{Key: pubKey},
			}),
			recovery.WithService(&did.Service{ID: "svc3"}))
		require.NoError(t, err)
	})
}

func TestClient_UpdateDID(t *testing.T) {
	t.Run("test signing key empty", func(t *testing.T) {
		v := sidetree.New()

		err := v.UpdateDID("did:ex:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "signing public key is required")
	})

	t.Run("test next updates key empty", func(t *testing.T) {
		v := sidetree.New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "next update public key is required")
	})

	t.Run("reveal value is empty", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithSigningKey(privKey), update.WithNextUpdatePublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "reveal value is required")
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithRevealValue("value"), update.WithNextUpdatePublicKey(pubKey),
			update.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "sidetree get endpoints func is required")

		err = v.UpdateDID("did:ex:123", update.WithRevealValue("value"), update.WithNextUpdatePublicKey(pubKey),
			update.WithSigningKey(privKey), update.WithSidetreeEndpoint(func() ([]string, error) {
				return nil, fmt.Errorf("failed to get endpoints")
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoints")
	})

	t.Run("test failed to get next update key", func(t *testing.T) {
		v := sidetree.New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithRevealValue("value"), update.WithSigningKey(privKey),
			update.WithNextUpdatePublicKey([]byte("wrong")), update.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next update key")
	})

	t.Run("test unsupported signing key", func(t *testing.T) {
		v := sidetree.New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithRevealValue("value"), update.WithSigningKey("www"),
			update.WithNextUpdatePublicKey(pubKey), update.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported")
	})

	t.Run("test error from unique suffix", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("wrong", update.WithRevealValue("value"), update.WithSigningKey(privKey),
			update.WithNextUpdatePublicKey(pubKey), update.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unique suffix not provided in id")
	})

	t.Run("test failed to send update did request", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v := sidetree.New(sidetree.WithAuthToken("tk1"))

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(&signingKey.PublicKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithSidetreeEndpoint(func() ([]string, error) {
			return []string{serv.URL}, nil
		}), update.WithSigningKey(signingKey), update.WithRevealValue(rv),
			update.WithNextUpdatePublicKey(pubKey), update.WithRemoveService("svc1"),
			update.WithRemoveService("svc1"), update.WithRemovePublicKey("k1"),
			update.WithRemovePublicKey("k2"), update.WithAddPublicKey(&vdrdoc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  gojose.JSONWebKey{Key: pubKey},
			}),
			update.WithAddService(&did.Service{ID: "svc3"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send update did request")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer serv.Close()

		v := sidetree.New(sidetree.WithAuthToken("tk1"))

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(&signingKey.PublicKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithSidetreeEndpoint(func() ([]string, error) {
			return []string{serv.URL}, nil
		}), update.WithSigningKey(signingKey), update.WithRevealValue(rv),
			update.WithNextUpdatePublicKey(pubKey), update.WithRemoveService("svc1"),
			update.WithRemoveService("svc1"), update.WithRemovePublicKey("k1"),
			update.WithRemovePublicKey("k2"), update.WithAddPublicKey(&vdrdoc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  gojose.JSONWebKey{Key: pubKey},
			}),
			update.WithAddService(&did.Service{ID: "svc3"}))
		require.NoError(t, err)
	})
}

func TestClient_CreateDID(t *testing.T) {
	t.Run("test error from get endpoints", func(t *testing.T) {
		v := sidetree.New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didResol, err := v.CreateDID(create.WithUpdatePublicKey(pubKey), create.WithRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "sidetree get endpoints func is required")
		require.Nil(t, didResol)

		didResol, err = v.CreateDID(create.WithUpdatePublicKey(pubKey), create.WithRecoveryPublicKey(pubKey),
			create.WithEndpoints(func() ([]string, error) {
				return nil, fmt.Errorf("failed to get endpoints")
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoints")
		require.Nil(t, didResol)
	})

	t.Run("test error from send create sidetree request", func(t *testing.T) {
		v := sidetree.New()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ed25519UpdatePubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithEndpoints(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send request")
		require.Nil(t, didResol)

		// test http status not equal 200
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		didResol, err = v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithEndpoints(func() ([]string, error) {
				return []string{serv.URL}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response")
		require.Nil(t, didResol)

		// test failed to parse did
		serv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err1 := (&did.Doc{ID: "did1"}).JSONBytes()
			require.NoError(t, err1)
			_, err1 = fmt.Fprint(w, string(bytes))
			require.NoError(t, err1)
		}))
		defer serv.Close()

		didResol, err = v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithEndpoints(func() ([]string, error) {
				return []string{serv.URL}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse did document")
		require.Nil(t, didResol)
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			b, err := json.Marshal(didResolution{
				Context:     "https://www.w3.org/ns/did-resolution/v1",
				DIDDocument: bytes,
			})
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecUpdatePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		v := sidetree.New(sidetree.WithTLSConfig(nil))

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithEndpoints(func() ([]string, error) {
				return []string{serv.URL}, nil
			}), create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithPublicKey(&vdrdoc.PublicKey{
				ID:       "key1",
				Type:     doc.JWSVerificationKey2020,
				JWK:      gojose.JSONWebKey{Key: ed25519RecoveryPubKey},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}),
			create.WithPublicKey(&vdrdoc.PublicKey{
				ID:       "key2",
				Type:     doc.JWSVerificationKey2020,
				JWK:      gojose.JSONWebKey{Key: ecPrivKey.Public()},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}),
			create.WithService(&did.Service{
				ID:              "srv1",
				Type:            "type",
				ServiceEndpoint: "http://example.com",
				Properties:      map[string]interface{}{"priority": "1"},
			}))
		require.NoError(t, err)
		require.Equal(t, "did1", didResol.DIDDocument.ID)
	})

	t.Run("test error unmarshal result", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "{{")
			require.NoError(t, err)
		}))
		defer serv.Close()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecUpdatePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		v := sidetree.New(sidetree.WithTLSConfig(nil))

		_, err = v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithEndpoints(func() ([]string, error) {
				return []string{serv.URL}, nil
			}), create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithService(&did.Service{
				ID:              "srv1",
				Type:            "type",
				ServiceEndpoint: "http://example.com",
				Properties:      map[string]interface{}{"priority": "1"},
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse document resolution")
	})

	t.Run("test unsupported recovery public key type", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := sidetree.New()

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey("wrongkey"),
			create.WithUpdatePublicKey("wrongvalue"), create.WithEndpoints(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get recovery key")
		require.Nil(t, didResol)
	})

	t.Run("test recovery public key empty", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := sidetree.New()

		didResol, err := v.CreateDID()
		require.Error(t, err)
		require.Contains(t, err.Error(), "recovery public key is required")
		require.Nil(t, didResol)
	})

	t.Run("test update public key empty", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v := sidetree.New()

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(pubKey),
			create.WithEndpoints(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "update public key is required")
		require.Nil(t, didResol)
	})
}
