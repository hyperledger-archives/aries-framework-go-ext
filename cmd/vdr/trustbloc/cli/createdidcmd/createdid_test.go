/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createdidcmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/stretchr/testify/require"
)

const (
	flag          = "--"
	publickeyData = `
[
 {
  "id": "key1",
  "type": "Ed25519VerificationKey2018",
  "purposes": ["authentication"],
  "jwkPath": "%s"
 },
 {
  "id": "key2",
  "type": "JwsVerificationKey2020",
  "purposes": ["authentication"],
  "jwkPath": "%s"
 }
]`

	jwk1Data = `
{
  "kty":"OKP",
  "crv":"Ed25519",
  "x":"o1bG1U7G3CNbtALMafUiFOq8ODraTyVTmPtRDO1QUWg",
  "y":""
}`
	jwk2Data = `
{
  "kty":"EC",
  "crv":"P-256",
  "x":"bGM9aNufpKNPxlkyacU1hGhQXm_aC8hIzSVeKDpwjBw",
  "y":"PfdmCOtIdVY2B6ucR4oQkt6evQddYhOyHoDYCaI2BJA"
}`

	recoveryKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErOnEHb7wH+YOYA6XQroWbeNrR18Y
f4HEGojknkxuXjFKGyI821aUlIO7xT+I6dPlfsWyXRSLYeJoFA9rLLjOjA==
-----END PUBLIC KEY-----`

	updateKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFoxLiiZZYCh8XOZE0MXUYIgCrwIq
ho+LGIVUXDNaduiNfpLmk5MXS5Q7WQAMgaJBRyRldIvbrNWqph4DH2gdKQ==
-----END PUBLIC KEY-----`

	servicesData = `[
  {
    "id": "svc1",
    "type": "type1",
    "priority": 1,
    "routingKeys": ["key1"],
    "recipientKeys": ["key1"],
    "serviceEndpoint": "http://www.example.com"
  },
  {
    "id": "svc2",
    "type": "type2",
    "priority": 2,
    "routingKeys": ["key2"],
    "recipientKeys": ["key2"],
    "serviceEndpoint": "http://www.example.com"
  }
]`
)

func TestKeys(t *testing.T) {
	t.Run("test recovery key empty", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		var args []string
		args = append(args, domainArg()...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--recoverykey) or key file (--recoverykey-file) is required")
	})
}

func TestService(t *testing.T) {
	t.Run("test services wrong path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		recoveryKeyFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = recoveryKeyFile.WriteString(recoveryKeyPEM)
		require.NoError(t, err)

		updateKeyFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = updateKeyFile.WriteString(updateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, recoveryKeyFileFlagNameArg(recoveryKeyFile.Name())...)
		args = append(args, updateKeyFileFlagNameArg(updateKeyFile.Name())...)
		args = append(args, servicesFileArg("./wrong")...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})
}

func TestCreateDID(t *testing.T) {
	type didResolution struct {
		Context          interface{}     `json:"@context"`
		DIDDocument      json.RawMessage `json:"didDocument"`
		ResolverMetadata json.RawMessage `json:"resolverMetadata"`
		MethodMetadata   json.RawMessage `json:"methodMetadata"`
	}

	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
		require.NoError(t, err)
		b, err := json.Marshal(didResolution{Context: "https://www.w3.org/ns/did-resolution/v1",
			DIDDocument: bytes})
		require.NoError(t, err)
		_, err = fmt.Fprint(w, string(b))
		require.NoError(t, err)
	}))

	recoveryKeyFile, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = recoveryKeyFile.WriteString(recoveryKeyPEM)
	require.NoError(t, err)

	updateKeyFile, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = updateKeyFile.WriteString(updateKeyPEM)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, os.Remove(recoveryKeyFile.Name()))
		require.NoError(t, os.Remove(updateKeyFile.Name()))
	}()

	servicesFile, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = servicesFile.WriteString(servicesData)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(servicesFile.Name())) }()

	jwk1File, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = jwk1File.WriteString(jwk1Data)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(jwk1File.Name())) }()

	jwk2File, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = jwk2File.WriteString(jwk2Data)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(jwk2File.Name())) }()

	publicKeyFile, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = publicKeyFile.WriteString(fmt.Sprintf(publickeyData, jwk1File.Name(), jwk2File.Name()))
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(publicKeyFile.Name())) }()

	t.Run("test failed to create did", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		var args []string
		args = append(args, sidetreeURLArg("wrongurl")...)
		args = append(args, recoveryKeyFileFlagNameArg(recoveryKeyFile.Name())...)
		args = append(args, updateKeyFileFlagNameArg(updateKeyFile.Name())...)
		args = append(args, servicesFileArg(servicesFile.Name())...)
		args = append(args, publicKeyFileArg(publicKeyFile.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create did")
	})

	t.Run("success", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		var args []string
		args = append(args, sidetreeURLArg(serv.URL)...)
		args = append(args, recoveryKeyFileFlagNameArg(recoveryKeyFile.Name())...)
		args = append(args, updateKeyFileFlagNameArg(updateKeyFile.Name())...)
		args = append(args, servicesFileArg(servicesFile.Name())...)
		args = append(args, publicKeyFileArg(publicKeyFile.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.NoError(t, err)
	})
}

func TestGetPublicKeys(t *testing.T) {
	t.Run("test public key invalid path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, publicKeyFileArg("./wrongfile")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "open wrongfile: no such file or directory")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	os.Clearenv()

	startCmd := GetCreateDIDCmd()

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func domainArg() []string {
	return []string{flag + domainFlagName, "domain"}
}

func publicKeyFileArg(value string) []string {
	return []string{flag + publicKeyFileFlagName, value}
}

func recoveryKeyFileFlagNameArg(value string) []string {
	return []string{flag + recoveryKeyFileFlagName, value}
}

func updateKeyFileFlagNameArg(value string) []string {
	return []string{flag + updateKeyFileFlagName, value}
}

func servicesFileArg(value string) []string {
	return []string{flag + serviceFileFlagName, value}
}

func sidetreeURLArg(value string) []string {
	return []string{flag + sidetreeURLFlagName, value}
}
