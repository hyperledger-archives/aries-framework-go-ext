/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy_test

import (
	"errors"
	"testing"

	vdri "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/indy-vdr/wrappers/golang/vdr"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/vdr/indy"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/indy/mock"
)

func TestVDRI_Read(t *testing.T) {
	type fields struct {
		methodName string
		client     Client
	}

	type args struct {
		did  string
		opts []vdri.DIDMethodOpts
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    func(t require.TestingT, object interface{}, msgAndArgs ...interface{})
		wantErr bool
	}{
		{
			name:    "invalid did string",
			fields:  fields{},
			args:    args{"dXd:invalid", []vdri.DIDMethodOpts{}},
			want:    require.Nil,
			wantErr: true,
		},
		{
			name: "invalid method name for this VDR",
			fields: fields{
				methodName: "sov",
			},
			args:    args{"did:peer:abc123", []vdri.DIDMethodOpts{}},
			want:    require.Nil,
			wantErr: true,
		},
		{
			name: "GetNym fails",
			fields: fields{
				methodName: "sov",
				client: &mock.IndyClient{
					GetNymErr: errors.New("boom"),
				},
			},
			args:    args{"did:sov:abc123", []vdri.DIDMethodOpts{}},
			want:    require.Nil,
			wantErr: true,
		},
		{
			name: "Invalid JSON response from GetNym",
			fields: fields{
				methodName: "sov",
				client: &mock.IndyClient{
					GetNymValue: &vdr.ReadReply{Data: `_not JSON_`},
					GetNymErr:   nil,
				},
			},
			args:    args{"did:sov:abc123", []vdri.DIDMethodOpts{}},
			want:    require.Nil,
			wantErr: true,
		},
		{
			name: "Invalid JSON response from GetEndpoint",
			fields: fields{
				methodName: "sov",
				client: &mock.IndyClient{
					GetNymValue:    &vdr.ReadReply{Data: `{"dest": "did:sov:abc123", "verkey": "3mJr7AoUCHxNqd"}`},
					GetNymErr:      nil,
					GetEndpointVal: &vdr.ReadReply{Data: `_ not JSON_`},
				},
			},
			args:    args{"did:sov:abc123", []vdri.DIDMethodOpts{}},
			want:    require.NotNil,
			wantErr: false,
		},
		{
			name: "No endpoint from GetEndpoint",
			fields: fields{
				methodName: "sov",
				client: &mock.IndyClient{
					GetNymValue:    &vdr.ReadReply{Data: `{"dest": "did:sov:abc123", "verkey": "3mJr7AoUCHxNqd"}`},
					GetNymErr:      nil,
					GetEndpointVal: &vdr.ReadReply{Data: `{}`},
				},
			},
			args:    args{"did:sov:abc123", []vdri.DIDMethodOpts{}},
			want:    require.NotNil,
			wantErr: false,
		},
		{
			name: "No nested endpoint from GetEndpoint",
			fields: fields{
				methodName: "sov",
				client: &mock.IndyClient{
					GetNymValue:    &vdr.ReadReply{Data: `{"dest": "did:sov:abc123", "verkey": "3mJr7AoUCHxNqd"}`},
					GetNymErr:      nil,
					GetEndpointVal: &vdr.ReadReply{Data: `{"endpoint": {}}`},
				},
			},
			args:    args{"did:sov:abc123", []vdri.DIDMethodOpts{}},
			want:    require.NotNil,
			wantErr: false,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		thisTest := tt
		t.Run(tt.name, func(t *testing.T) {
			r := &VDR{
				MethodName: thisTest.fields.methodName,
				Client:     thisTest.fields.client,
			}
			got, err := r.Read(thisTest.args.did)
			if (err != nil) != thisTest.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, thisTest.wantErr)

				return
			}
			thisTest.want(t, got)
		})
	}

	t.Run("did with no service endpoint", func(t *testing.T) {
		did := "did:sov:abc123"
		indycl := &mock.IndyClient{
			GetNymValue:    &vdr.ReadReply{Data: `{"dest": "did:sov:abc123", "verkey": "3mJr7AoUCHxNqd"}`},
			GetNymErr:      nil,
			GetEndpointErr: errors.New("not found"),
		}
		r := &VDR{
			MethodName: "sov",
			Client:     indycl,
		}
		doc, err := r.Read(did)
		require.NoError(t, err)
		require.NotNil(t, doc)

		didDoc := doc.DIDDocument

		require.Equal(t, did, didDoc.ID)
		require.NotNil(t, didDoc.Context)
		require.NotNil(t, didDoc.Updated)
		require.NotNil(t, didDoc.Created)
		require.Len(t, didDoc.Authentication, 1)
		require.Len(t, didDoc.VerificationMethod, 1)
		require.Nil(t, didDoc.Service)
	})

	t.Run("did with service endpoint", func(t *testing.T) {
		did := "did:sov:abc123"
		indycl := &mock.IndyClient{
			GetNymValue:    &vdr.ReadReply{Data: `{"dest": "did:sov:abc123", "verkey": "3mJr7AoUCHxNqd"}`},
			GetNymErr:      nil,
			GetEndpointVal: &vdr.ReadReply{Data: `{"endpoint": {"endpoint": "127.0.0.1:8080"}}`},
		}
		r := &VDR{
			MethodName: "sov",
			Client:     indycl,
		}
		doc, err := r.Read(did)
		require.NoError(t, err)
		require.NotNil(t, doc)

		didDoc := doc.DIDDocument

		require.NoError(t, err)
		require.NotNil(t, doc)
		require.Equal(t, did, didDoc.ID)
		require.NotNil(t, didDoc.Context)
		require.NotNil(t, didDoc.Updated)
		require.NotNil(t, didDoc.Created)
		require.NotNil(t, didDoc.Service)
		require.Len(t, didDoc.Authentication, 1)
		require.Len(t, didDoc.VerificationMethod, 1)
	})
}
