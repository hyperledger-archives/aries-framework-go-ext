/*
Copyright Avast Software. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package status_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/vc/status/api"
	"github.com/hyperledger/aries-framework-go-ext/component/vc/status/internal/bitstring"
	"github.com/hyperledger/aries-framework-go-ext/component/vc/status/resolver"
	"github.com/hyperledger/aries-framework-go-ext/component/vc/status/validator"
	"github.com/hyperledger/aries-framework-go-ext/component/vc/status/validator/statuslist2021"

	. "github.com/hyperledger/aries-framework-go-ext/component/vc/status"
)

const issuerID = "issuer-id"

func TestClient_VerifyStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client := Client{
			ValidatorGetter: validator.GetValidator,
			Resolver:        resolver.NewResolver(http.DefaultClient, &vdr.MockVDRegistry{}, ""),
		}

		statusServer := httptest.NewServer(mockStatusResponseHandler(t, mockStatusVC(t, issuerID, isRevoked{false, true})))

		defer func() {
			statusServer.Close()
		}()

		// status: not revoked
		err := client.VerifyStatus(&verifiable.Credential{
			Issuer: verifiable.Issuer{
				ID: issuerID,
			},
			Status: &verifiable.TypedID{
				ID:   "foo-bar",
				Type: statuslist2021.StatusList2021Type,
				CustomFields: map[string]interface{}{
					statuslist2021.StatusPurpose:        "foo",
					statuslist2021.StatusListCredential: statusServer.URL,
					statuslist2021.StatusListIndex:      "0",
				},
			},
		})
		require.NoError(t, err)

		// status: revoked
		err = client.VerifyStatus(&verifiable.Credential{
			Issuer: verifiable.Issuer{
				ID: issuerID,
			},

			Status: &verifiable.TypedID{
				ID:   "foo-bar",
				Type: statuslist2021.StatusList2021Type,
				CustomFields: map[string]interface{}{
					statuslist2021.StatusPurpose:        "foo",
					statuslist2021.StatusListCredential: statusServer.URL,
					statuslist2021.StatusListIndex:      "1",
				},
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), RevokedMessage)
	})

	t.Run("fail", func(t *testing.T) {
		t.Run("missing status field", func(t *testing.T) {
			client := &Client{}
			err := client.VerifyStatus(&verifiable.Credential{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "vc missing status list field")
		})

		t.Run("no validator found for status type", func(t *testing.T) {
			expectErr := errors.New("expected error")

			client := &Client{
				ValidatorGetter: func(_ string) (api.Validator, error) {
					return nil, expectErr
				},
			}
			err := client.VerifyStatus(&verifiable.Credential{
				Status: &verifiable.TypedID{},
			})
			require.Error(t, err)
			require.ErrorIs(t, err, expectErr)
		})

		t.Run("status field validation error", func(t *testing.T) {
			expectErr := errors.New("expected error")

			client := &Client{
				ValidatorGetter: func(string) (api.Validator, error) {
					return &mockValidator{
						ValidateStatusErr: expectErr,
					}, nil
				},
			}
			err := client.VerifyStatus(&verifiable.Credential{
				Status: &verifiable.TypedID{},
			})
			require.Error(t, err)
			require.ErrorIs(t, err, expectErr)
		})

		t.Run("getting status list index", func(t *testing.T) {
			expectErr := errors.New("expected error")

			client := &Client{
				ValidatorGetter: func(string) (api.Validator, error) {
					return &mockValidator{
						GetStatusListIndexErr: expectErr,
					}, nil
				},
			}
			err := client.VerifyStatus(&verifiable.Credential{
				Status: &verifiable.TypedID{},
			})
			require.Error(t, err)
			require.ErrorIs(t, err, expectErr)
		})

		t.Run("getting status VC URI", func(t *testing.T) {
			expectErr := errors.New("expected error")

			client := &Client{
				ValidatorGetter: func(string) (api.Validator, error) {
					return &mockValidator{
						GetStatusVCURIErr: expectErr,
					}, nil
				},
			}
			err := client.VerifyStatus(&verifiable.Credential{
				Status: &verifiable.TypedID{},
			})
			require.Error(t, err)
			require.ErrorIs(t, err, expectErr)
		})

		t.Run("resolving status VC", func(t *testing.T) {
			expectErr := errors.New("expected error")

			client := &Client{
				ValidatorGetter: func(string) (api.Validator, error) {
					return &mockValidator{}, nil
				},
				Resolver: &mockResolver{
					Err: expectErr,
				},
			}
			err := client.VerifyStatus(&verifiable.Credential{
				Status: &verifiable.TypedID{},
			})
			require.Error(t, err)
			require.ErrorIs(t, err, expectErr)
		})

		t.Run("issuer fields don't match", func(t *testing.T) {
			client := &Client{
				ValidatorGetter: func(string) (api.Validator, error) {
					return &mockValidator{}, nil
				},
				Resolver: &mockResolver{
					Cred: &verifiable.Credential{
						Issuer: verifiable.Issuer{
							ID: "bar",
						},
					},
				},
			}
			err := client.VerifyStatus(&verifiable.Credential{
				Issuer: verifiable.Issuer{
					ID: "foo",
				},
				Status: &verifiable.TypedID{},
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "issuer of the credential does not match status list vc issuer")
		})

		t.Run("subject has unexpected type", func(t *testing.T) {
			client := &Client{
				ValidatorGetter: func(string) (api.Validator, error) {
					return &mockValidator{}, nil
				},
				Resolver: &mockResolver{
					Cred: &verifiable.Credential{
						Subject: &mockValidator{},
					},
				},
			}
			err := client.VerifyStatus(&verifiable.Credential{
				Status: &verifiable.TypedID{},
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid subject field structure")
		})

		t.Run("status bitstring has invalid format", func(t *testing.T) {
			client := &Client{
				ValidatorGetter: func(string) (api.Validator, error) {
					return &mockValidator{}, nil
				},
				Resolver: &mockResolver{
					Cred: &verifiable.Credential{
						Subject: []verifiable.Subject{
							{
								CustomFields: map[string]interface{}{
									"encodedList": ":( this is not base-64 data",
								},
							},
						},
					},
				},
			}
			err := client.VerifyStatus(&verifiable.Credential{
				Status: &verifiable.TypedID{},
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to decode bits")
		})
	})
}

type mockValidator struct {
	ValidateStatusErr     error
	GetStatusVCURIVal     string
	GetStatusVCURIErr     error
	GetStatusListIndexVal int
	GetStatusListIndexErr error
}

func (m *mockValidator) ValidateStatus(*verifiable.TypedID) error {
	return m.ValidateStatusErr
}

func (m *mockValidator) GetStatusVCURI(*verifiable.TypedID) (string, error) {
	return m.GetStatusVCURIVal, m.GetStatusVCURIErr
}

func (m *mockValidator) GetStatusListIndex(*verifiable.TypedID) (int, error) {
	return m.GetStatusListIndexVal, m.GetStatusListIndexErr
}

type mockResolver struct {
	Cred *verifiable.Credential
	Err  error
}

func (m *mockResolver) Resolve(string) (*verifiable.Credential, error) {
	return m.Cred, m.Err
}

type isRevoked []bool

func bool2bits(data []bool) []byte {
	numBytes := len(data) / 8

	if len(data)%8 != 0 {
		numBytes++
	}

	out := make([]byte, numBytes)

	for i, datum := range data {
		if datum {
			out[i/8] |= 1 << (i % 8)
		}
	}

	return out
}

func mockStatusVC(t *testing.T, issuerID string, vcStatus isRevoked) *verifiable.Credential {
	t.Helper()

	statusBits := bool2bits(vcStatus)

	statusEncoded, err := bitstring.Encode(statusBits)
	require.NoError(t, err)

	return &verifiable.Credential{
		Context: []string{verifiable.ContextURI},
		Types:   []string{verifiable.VCType},
		Issuer: verifiable.Issuer{
			ID: issuerID,
		},
		Subject: []verifiable.Subject{
			{
				CustomFields: map[string]interface{}{
					"encodedList": statusEncoded,
				},
			},
		},
	}
}

func mockStatusResponseHandler(t *testing.T, statusVC *verifiable.Credential) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, req *http.Request) {
		vcBytes, err := statusVC.MarshalJSON()
		require.NoError(t, err)

		_, err = w.Write(vcBytes)
		require.NoError(t, err)
	}
}
