/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package sidetree_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	gojose "github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/edsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/client"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/option/create"
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
		require.Contains(t, err.Error(), "signer is required")
	})

	t.Run("test operation commitment is empty", func(t *testing.T) {
		v := sidetree.New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123", deactivate.WithSigner(newSignerMock(t, privKey)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "operation commitment is required")
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(pubKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123",
			deactivate.WithSigner(newSignerMock(t, privKey)),
			deactivate.WithOperationCommitment(rv))
		require.Error(t, err)
		require.Contains(t, err.Error(), "sidetree get endpoints func is required")

		err = v.DeactivateDID("did:ex:123",
			deactivate.WithOperationCommitment(rv),
			deactivate.WithSigner(newSignerMock(t, privKey)),
			deactivate.WithSidetreeEndpoint(func() ([]string, error) {
				return nil, fmt.Errorf("failed to get endpoint")
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoint")
	})

	t.Run("test error from unique suffix", func(t *testing.T) {
		v := sidetree.New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("wrong", deactivate.WithOperationCommitment("value"),
			deactivate.WithSigner(newSignerMock(t, privKey)),
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

		v := sidetree.New(sidetree.WithAuthTokenProvider(&tokenProvider{}))

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(pubKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123",
			deactivate.WithOperationCommitment(rv),
			deactivate.WithSigner(newSignerMock(t, privKey)), deactivate.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send deactivate sidetree request")
	})

	t.Run("test error from get reveal value", func(t *testing.T) {
		v := sidetree.New(sidetree.WithAuthToken("tk1"))

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123",
			deactivate.WithOperationCommitment("value"),
			deactivate.WithSigner(newSignerMock(t, privKey)), deactivate.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get decoded multihash")
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

		err = v.DeactivateDID("did:ex:123", deactivate.WithSigner(newSignerMock(t, privKey)),
			deactivate.WithOperationCommitment(rv), deactivate.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{serv.URL}, nil
			}))
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
		require.Contains(t, err.Error(), "signer is required")
	})

	t.Run("test operation commitment is empty", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithSigner(newSignerMock(t, privKey)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "operation commitment is required")
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := sidetree.New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(&signingKey.PublicKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123",
			recovery.WithSigner(newSignerMock(t, signingKey)), recovery.WithOperationCommitment(rv),
			recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: pubKey}},
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "sidetree get endpoints func is required")

		err = v.RecoverDID("did:ex:123",
			recovery.WithSigner(newSignerMock(t, signingKey)), recovery.WithOperationCommitment(rv),
			recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: pubKey}},
			}),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return nil, fmt.Errorf("failed to get endpoint")
			}))

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoint")
	})

	t.Run("test failed to get next recovery key", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithOperationCommitment("value"),
			recovery.WithSigner(newSignerMock(t, privKey)),
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

		err = v.RecoverDID("did:ex:123", recovery.WithOperationCommitment("value"),
			recovery.WithSigner(newSignerMock(t, privKey)),
			recovery.WithNextUpdatePublicKey([]byte("wrong")), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next update key")
	})

	t.Run("test error from unique suffix", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("wrong", recovery.WithOperationCommitment("value"),
			recovery.WithSigner(newSignerMock(t, privKey)),
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

		err = v.RecoverDID("did:ex:123", recovery.WithOperationCommitment("value"),
			recovery.WithSigner(newSignerMock(t, ecPrivKey)), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}), recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{
				ID:   "key3",
				Type: doc.JWSVerificationKey2020,
				JWK:  jwk.JWK{},
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key must contain either a jwk or base58 key")
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

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(&ecPrivKey.PublicKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithOperationCommitment(rv),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{serv.URL}, nil
			}), recovery.WithSigner(newSignerMock(t, ecPrivKey)),
			recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: pubKey}},
			}),
			recovery.WithService(&did.Service{ID: "svc3"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send recover sidetree request")
	})

	t.Run("test error from reveal value", func(t *testing.T) {
		v := sidetree.New(sidetree.WithAuthToken("tk1"))

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", recovery.WithOperationCommitment("value"),
			recovery.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}), recovery.WithSigner(newSignerMock(t, ecPrivKey)),
			recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: pubKey}},
			}),
			recovery.WithService(&did.Service{ID: "svc3"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get decoded multihash")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.ContextV1}}).JSONBytes()
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
		}), recovery.WithSigner(newSignerMock(t, signingKey)), recovery.WithOperationCommitment(rv),
			recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: pubKey}},
			}),
			recovery.WithService(&did.Service{ID: "svc3"}),
			recovery.WithAlsoKnownAs("firstIdentityURI"),
			recovery.WithAlsoKnownAs("secondIdentityURI"))
		require.NoError(t, err)
	})
}

func TestClient_UpdateDID(t *testing.T) {
	t.Run("test signing key empty", func(t *testing.T) {
		v := sidetree.New()

		err := v.UpdateDID("did:ex:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "signer is required")
	})

	t.Run("test next updates key empty", func(t *testing.T) {
		v := sidetree.New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithSigner(newSignerMock(t, privKey)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "next update public key is required")
	})

	t.Run("operation commitment is empty", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithSigner(newSignerMock(t, privKey)), update.WithNextUpdatePublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "operation commitment is required")
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := sidetree.New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(&signingKey.PublicKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123",
			update.WithSigner(newSignerMock(t, signingKey)),
			update.WithOperationCommitment(rv),
			update.WithNextUpdatePublicKey(pubKey),
			update.WithRemoveService("svc1"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "sidetree get endpoints func is required")

		err = v.UpdateDID("did:ex:123",
			update.WithSigner(newSignerMock(t, signingKey)),
			update.WithOperationCommitment(rv),
			update.WithNextUpdatePublicKey(pubKey),
			update.WithSidetreeEndpoint(func() ([]string, error) {
				return nil, fmt.Errorf("failed to get endpoints")
			}),
			update.WithRemoveService("svc1"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoints")
	})

	t.Run("test failed to get next update key", func(t *testing.T) {
		v := sidetree.New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithOperationCommitment("value"),
			update.WithSigner(newSignerMock(t, privKey)),
			update.WithNextUpdatePublicKey([]byte("wrong")), update.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next update key")
	})

	t.Run("error from update patches", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		defaultOptions := []update.Option{
			update.WithOperationCommitment("value"),
			update.WithSigner(newSignerMock(t, privKey)),
			update.WithNextUpdatePublicKey(pubKey),
			update.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}),
		}

		t.Run("public key error: no jwk in JsonWebKey2020 key", func(t *testing.T) {
			err = v.UpdateDID("did:ex:123", append(defaultOptions,
				update.WithAddPublicKey(&doc.PublicKey{
					ID:     "key3",
					Type:   doc.JWK2020Type,
					B58Key: base58.Encode(pubKey),
				}),
			)...)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no valid jwk in JsonWebKey2020 key")
		})
	})

	t.Run("test error from unique suffix", func(t *testing.T) {
		v := sidetree.New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("wrong", update.WithOperationCommitment("value"),
			update.WithSigner(newSignerMock(t, privKey)),
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
		}), update.WithSigner(newSignerMock(t, signingKey)), update.WithOperationCommitment(rv),
			update.WithNextUpdatePublicKey(pubKey), update.WithRemoveService("svc1"),
			update.WithRemoveService("svc1"), update.WithRemovePublicKey("k1"),
			update.WithRemovePublicKey("k2"), update.WithAddPublicKey(&doc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: pubKey}},
			}),
			update.WithAddService(&did.Service{ID: "svc3"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send update did request")
	})

	t.Run("test failed from reveal value", func(t *testing.T) {
		v := sidetree.New(sidetree.WithAuthToken("tk1"))

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", update.WithSidetreeEndpoint(func() ([]string, error) {
			return []string{"url"}, nil
		}), update.WithSigner(newSignerMock(t, signingKey)), update.WithOperationCommitment("value"),
			update.WithNextUpdatePublicKey(pubKey), update.WithRemoveService("svc1"),
			update.WithRemoveService("svc1"), update.WithRemovePublicKey("k1"),
			update.WithRemovePublicKey("k2"), update.WithAddPublicKey(&doc.PublicKey{
				ID:   "key3",
				Type: doc.Ed25519VerificationKey2018,
				JWK:  jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: pubKey}},
			}),
			update.WithAddService(&did.Service{ID: "svc3"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get decoded multihash")
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
		}), update.WithSigner(newSignerMock(t, signingKey)), update.WithOperationCommitment(rv),
			update.WithNextUpdatePublicKey(pubKey), update.WithRemoveService("svc1"),
			update.WithRemoveService("svc1"), update.WithRemovePublicKey("k1"),
			update.WithRemovePublicKey("k2"), update.WithAddPublicKey(&doc.PublicKey{
				ID:     "key3",
				Type:   doc.Ed25519VerificationKey2018,
				B58Key: base58.Encode(pubKey),
			}),
			update.WithAddService(&did.Service{ID: "svc3"}),
			update.WithAddAlsoKnownAs("firstIdentityURI"),
			update.WithAddAlsoKnownAs("secondIdentityURI"),
			update.WithRemoveAlsoKnownAs("removeIdentityURI"))
		require.NoError(t, err)
	})
}

func TestClient_CreateDID(t *testing.T) {
	t.Run("test error from get endpoints", func(t *testing.T) {
		v := sidetree.New()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecUpdatePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithPublicKey(&doc.PublicKey{
				ID:       "key1",
				Type:     doc.JWSVerificationKey2020,
				JWK:      jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: ed25519RecoveryPubKey}},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}))

		require.Contains(t, err.Error(), "sidetree get endpoints func is required")
		require.Nil(t, didResol)

		didResol, err = v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithPublicKey(&doc.PublicKey{
				ID:       "key1",
				Type:     doc.JWSVerificationKey2020,
				JWK:      jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: ed25519RecoveryPubKey}},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}),
			create.WithSidetreeEndpoint(func() ([]string, error) {
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
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithSidetreeEndpoint(func() ([]string, error) {
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
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithSidetreeEndpoint(func() ([]string, error) {
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
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{serv.URL}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse did document")
		require.Nil(t, didResol)
	})

	t.Run("test error from sidetree operation request function", func(t *testing.T) {
		v := sidetree.New(sidetree.WithSidetreeOperationRequestFnc(func(req []byte, getEndpoints func() ([]string, error)) ([]byte, error) {
			return nil, fmt.Errorf("send operation request error")
		}))

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ed25519UpdatePubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithUpdatePublicKey(ed25519UpdatePubKey), create.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"https://www.domain.com"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send create sidetree request: send operation request error")
		require.Nil(t, didResol)
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.ContextV1}}).JSONBytes()
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

		v := sidetree.New(sidetree.WithHTTPClient(&http.Client{}))

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{serv.URL}, nil
			}), create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithAlsoKnownAs("https://first.blog.example"),
			create.WithAlsoKnownAs("https://second.blog.example"),
			create.WithPublicKey(&doc.PublicKey{
				ID:       "key1",
				Type:     doc.JWSVerificationKey2020,
				JWK:      jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: ed25519RecoveryPubKey}},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}),
			create.WithPublicKey(&doc.PublicKey{
				ID:       "key2",
				Type:     doc.JWSVerificationKey2020,
				JWK:      jwk.JWK{JSONWebKey: gojose.JSONWebKey{Key: ecPrivKey.Public()}},
				Purposes: []string{doc.KeyPurposeAuthentication},
			}),
			create.WithService(&did.Service{
				ID:   "srv1",
				Type: "type",
				ServiceEndpoint: model.NewDIDCommV2Endpoint([]model.DIDCommV2Endpoint{
					{
						URI:         "http://example.com",
						RoutingKeys: []string{"key1"},
					},
				}),
				Properties: map[string]interface{}{"priority": "1"},
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

		v := sidetree.New(sidetree.WithHTTPClient(&http.Client{}))

		_, err = v.CreateDID(create.WithRecoveryPublicKey(ed25519RecoveryPubKey),
			create.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{serv.URL}, nil
			}), create.WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			create.WithService(&did.Service{
				ID:              "srv1",
				Type:            "type",
				ServiceEndpoint: model.NewDIDCommV1Endpoint("http://example.com"),
				Properties:      map[string]interface{}{"priority": "1"},
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse document resolution")
	})

	t.Run("test unsupported recovery public key type", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.ContextV1}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := sidetree.New()

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey("wrongkey"),
			create.WithUpdatePublicKey("wrongvalue"),
			create.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get recovery key")
		require.Nil(t, didResol)
	})

	t.Run("test recovery public key empty", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.ContextV1}}).JSONBytes()
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
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.ContextV1}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v := sidetree.New()

		didResol, err := v.CreateDID(create.WithRecoveryPublicKey(pubKey),
			create.WithSidetreeEndpoint(func() ([]string, error) {
				return []string{"url"}, nil
			}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "update public key is required")
		require.Nil(t, didResol)
	})
}

type signerMock struct {
	signer    client.Signer
	publicKey *jws.JWK
}

func newSignerMock(t *testing.T, signingkey crypto.PrivateKey) *signerMock {
	t.Helper()

	switch key := signingkey.(type) {
	case *ecdsa.PrivateKey:
		updateKey, err := pubkey.GetPublicKeyJWK(key.Public())
		require.NoError(t, err)

		return &signerMock{signer: ecsigner.New(key, "ES256", "k1"), publicKey: updateKey}
	case ed25519.PrivateKey:
		updateKey, err := pubkey.GetPublicKeyJWK(key.Public())
		require.NoError(t, err)

		return &signerMock{signer: edsigner.New(key, "EdDSA", "k1"), publicKey: updateKey}
	}

	return nil
}

func (s *signerMock) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

func (s *signerMock) Headers() jws.Headers {
	return s.signer.Headers()
}

func (s *signerMock) PublicKeyJWK() *jws.JWK {
	return s.publicKey
}

type tokenProvider struct{}

func (t *tokenProvider) AuthToken() (string, error) {
	return "newTK", nil
}
