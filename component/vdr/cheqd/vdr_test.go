package cheqd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheqdDIDResolver(t *testing.T) {
	t.Run("test cheqd resolve did success", func(t *testing.T) {
		did := "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY#key1"
		v := New()
		docResolution, err := v.ReadCheqd(did)
		require.Nil(t, err)

		require.Equal(t, 1, len(docResolution.DIDDocument.Context))
		require.Equal(t, "https://www.w3.org/ns/did/v1", docResolution.DIDDocument.Context[0])

		require.Equal(t, "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY", docResolution.DIDDocument.ID)

		require.Equal(t, 1, len(docResolution.DIDDocument.VerificationMethod))
		require.Equal(t, "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY#key1", docResolution.DIDDocument.VerificationMethod[0].ID)
		require.Equal(t, "Ed25519VerificationKey2020", docResolution.DIDDocument.VerificationMethod[0].Type)
		require.Equal(t, "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY", docResolution.DIDDocument.VerificationMethod[0].Controller)

		require.Equal(t, 1, len(docResolution.DIDDocument.Service))
		require.Equal(t, "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY#website", docResolution.DIDDocument.Service[0].ID)
		require.Equal(t, "LinkedDomains", docResolution.DIDDocument.Service[0].Type)
		require.Equal(t, "https://www.cheqd.io", docResolution.DIDDocument.Service[0].ServiceEndpoint)

		require.Equal(t, 1, len(docResolution.DIDDocument.Authentication))
		require.Equal(t, "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY#key1", docResolution.DIDDocument.Authentication[0].VerificationMethod.ID)
		require.Equal(t, "Ed25519VerificationKey2020", docResolution.DIDDocument.Authentication[0].VerificationMethod.Type)
		require.Equal(t, "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY", docResolution.DIDDocument.Authentication[0].VerificationMethod.Controller)
	})
}
