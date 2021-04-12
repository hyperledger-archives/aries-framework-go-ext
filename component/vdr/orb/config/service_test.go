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
		cs := NewService()

		conf, err := cs.GetSidetreeConfig()
		require.NoError(t, err)

		require.Equal(t, uint(18), conf.MultiHashAlgorithm)
	})
}

func TestConfigService_GetEndpoint(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cs := NewService(WithAuthToken("t1"), WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "/op",
						ResolutionEndpoint: "/resolve",
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "op") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Links: []restapi.WebFingerLink{{Href: "/op1"}, {Href: "/op2"}},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links:      []restapi.WebFingerLink{{Href: "/resolve1"}, {Href: "/resolve2"}},
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				return nil, nil
			}}))

		endpoint, err := cs.GetEndpoint("d1")
		require.NoError(t, err)

		require.Equal(t, endpoint.ResolutionEndpoints, []string{"/resolve1", "/resolve2"})
		require.Equal(t, endpoint.OperationEndpoints, []string{"/op1", "/op2"})
		require.Equal(t, endpoint.MinResolvers, 2)
	})

	t.Run("fail to send request for well-known", func(t *testing.T) {
		cs := NewService(WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("failed to send")
			}}))

		_, err := cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send")
	})

	t.Run("well-known return 500 status", func(t *testing.T) {
		cs := NewService(WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
				}, nil
			}}))

		_, err := cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from d1/.well-known/did-orb status")
	})

	t.Run("web finger resolution return 500 status", func(t *testing.T) {
		cs := NewService(WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "/op",
						ResolutionEndpoint: "/resolve",
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

		_, err := cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"got unexpected response from d1/.well-known/webfinger?resource=%2Fresolve status")
	})

	t.Run("web finger operation return 500 status", func(t *testing.T) {
		cs := NewService(WithHTTPClient(
			&mockHTTPClient{doFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, ".well-known/did-orb") {
					b, err := json.Marshal(restapi.WellKnownResponse{
						OperationEndpoint:  "/op",
						ResolutionEndpoint: "/resolve",
					})
					require.NoError(t, err)
					r := ioutil.NopCloser(bytes.NewReader(b))

					return &http.Response{StatusCode: http.StatusOK, Body: r}, nil
				}

				if strings.Contains(req.URL.Path, ".well-known/webfinger") &&
					strings.Contains(req.URL.RawQuery, "resolve") {
					b, err := json.Marshal(restapi.WebFingerResponse{
						Properties: map[string]interface{}{minResolvers: float64(2)},
						Links:      []restapi.WebFingerLink{{Href: "/resolve1"}, {Href: "/resolve2"}},
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

		_, err := cs.GetEndpoint("d1")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"got unexpected response from d1/.well-known/webfinger?resource=%2Fop status")
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
