/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

//nolint: testpackage
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
)

func TestConfigService_GetSidetreeConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cs, err := NewService(nil)
		require.NoError(t, err)

		conf, err := cs.GetSidetreeConfig()
		require.NoError(t, err)

		require.Equal(t, uint(18), conf.MultiHashAlgorithm)
	})
}

func TestConfigService_GetEndpointIPNS(t *testing.T) {
	t.Run("test wrong did", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"))
		require.NoError(t, err)

		_, err = cs.getEndpointIPNS("did")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did format is wrong")
	})

	t.Run("test error from orb client", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return nil, fmt.Errorf("failed to get anchor origin")
		}}

		_, err = cs.getEndpointIPNS("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get anchor origin")
	})

	t.Run("test get anchor origin return not string", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return []byte(""), nil
		}}

		_, err = cs.getEndpointIPNS("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get anchor origin didn't return string")
	})

	t.Run("test get anchor origin return not string", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return []byte(""), nil
		}}

		_, err = cs.getEndpointIPNS("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get anchor origin didn't return string")
	})

	t.Run("test get anchor origin return not ipns", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return "wrong", nil
		}}

		_, err = cs.getEndpointIPNS("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor origin is not ipns")
	})

	t.Run("test error fetch ipns webfinger", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"))
		require.NoError(t, err)

		cs.orbClient = &mockOrbClient{getAnchorOriginFunc: func(cid, suffix string) (interface{}, error) {
			return "ipns://wwrrww", nil
		}}

		_, err = cs.getEndpointIPNS("did:orb:ipfs:a:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from")
	})
}

func TestConfigService_GetEndpoint(t *testing.T) { //nolint: gocyclo,gocognit
	t.Run("success", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve1",
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "op") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Links: []restapi.WebFingerLink{{Href: "https://localhost/op1"}, {Href: "https://localhost/op2"}},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve1") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.WebFingerLink{
							{Href: "https://localhost/resolve1", Rel: "self"},
							{Href: "https://localhost/resolve2", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve2") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.WebFingerLink{
							{Href: "https://localhost/resolve2", Rel: "self"},
							{Href: "https://localhost/resolve1", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return nil, nil
			}}))
		require.NoError(t, err)

		endpoint, err := cs.GetEndpoint("d1")
		require.NoError(t, err)

		require.Equal(t, endpoint.ResolutionEndpoints, []string{"https://localhost/resolve1", "https://localhost/resolve2"})
		require.Equal(t, endpoint.OperationEndpoints, []string{"https://localhost/op1", "https://localhost/op2"})
		require.Equal(t, endpoint.MinResolvers, 2)
	})

	t.Run("failed to fetch webfinger links", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve1",
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve1") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.WebFingerLink{
							{Href: "https://localhost/resolve1", Rel: "self"},
							{Href: "https://localhost/resolve2", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve2") {
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
					}, nil
				}

				return nil, nil
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from "+
			"https://localhost/.well-known/webfinger?resource=https:%2F%2Flocalhost%2Fresolve2 status")
	})

	t.Run("webfinger link return different min resolver", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve1",
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "op") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Links: []restapi.WebFingerLink{{Href: "https://localhost/op1"}, {Href: "https://localhost/op2"}},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve1") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.WebFingerLink{
							{Href: "https://localhost/resolve1", Rel: "self"},
							{Href: "https://localhost/resolve2", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve2") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(3)},
						Links: []restapi.WebFingerLink{
							{Href: "https://localhost/resolve2", Rel: "self"},
							{Href: "https://localhost/resolve1", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return nil, nil
			}}))
		require.NoError(t, err)

		endpoint, err := cs.GetEndpoint("d1")
		require.NoError(t, err)

		require.Equal(t, endpoint.ResolutionEndpoints, []string{"https://localhost/resolve1"})
		require.Equal(t, endpoint.OperationEndpoints, []string{"https://localhost/op1", "https://localhost/op2"})
		require.Equal(t, endpoint.MinResolvers, 2)
	})

	t.Run("webfinger link return different list of endpoints", func(t *testing.T) {
		cs, err := NewService(nil, WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve1",
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "op") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Links: []restapi.WebFingerLink{{Href: "https://localhost/op1"}, {Href: "https://localhost/op2"}},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve1") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.WebFingerLink{
							{Href: "https://localhost/resolve1", Rel: "self"},
							{Href: "https://localhost/resolve2", Rel: "alternate"},
						},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve2") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.WebFingerLink{
							{Href: "https://localhost/resolve2", Rel: "self"},
						},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return nil, nil
			}}))
		require.NoError(t, err)

		endpoint, err := cs.GetEndpoint("d1")
		require.NoError(t, err)

		require.Equal(t, []string{"https://localhost/resolve1"}, endpoint.ResolutionEndpoints)
		require.Equal(t, []string{"https://localhost/op1", "https://localhost/op2"}, endpoint.OperationEndpoints)
		require.Equal(t, endpoint.MinResolvers, 2)
	})

	t.Run("fail to send request for well-known", func(t *testing.T) {
		cs, err := NewService(nil, WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("failed to send")
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send")
	})

	t.Run("well-known return 500 status", func(t *testing.T) {
		cs, err := NewService(nil, WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
				}, nil
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from https://d1/.well-known/did-orb status")
	})

	t.Run("web finger resolution return 500 status", func(t *testing.T) {
		cs, err := NewService(nil, WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve",
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
				}, nil
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"got unexpected response from https://localhost/.well-known"+
				"/webfinger?resource=https:%2F%2Flocalhost%2Fresolve status")
	})

	t.Run("web finger operation return 500 status", func(t *testing.T) {
		cs, err := NewService(nil, WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "https://localhost/op",
						ResolutionEndpoint: "https://localhost/resolve",
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links: []restapi.WebFingerLink{
							{Href: "https://localhost/resolve1"},
							{Href: "https://localhost/resolve2"},
						},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
				}, nil
			}}))
		require.NoError(t, err)

		_, err = cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"got unexpected response from https://localhost/.well-known/"+
				"webfinger?resource=https:%2F%2Flocalhost%2Fop status")
	})
}

type mockHTTPClient struct {
	doFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.doFunc != nil {
		return m.doFunc(req)
	}

	return nil, nil
}

type mockOrbClient struct {
	getAnchorOriginFunc func(cid, suffix string) (interface{}, error)
}

func (m *mockOrbClient) GetAnchorOrigin(cid, suffix string) (interface{}, error) {
	if m.getAnchorOriginFunc != nil {
		return m.getAnchorOriginFunc(cid, suffix)
	}

	return nil, nil
}
