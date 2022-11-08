# Long Form VDR
Long form VDR is used to resolve long form DID and to create long-form DID. 
Update, recover and deactivate operations are currently not supported.

## New VDR
```
import (
	"crypto"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform"
)

vdr, err := longform.New()
	if err != nil {
		return err
}
```

## Create DID
For creating DID use vdr create and pass DID document. 

```
import (
"crypto"
"crypto/ed25519"
"crypto/rand"
"fmt"

ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"

"github.com/hyperledger/aries-framework-go-ext/component/vdr/longform"
)

recoveryKey, recoveryKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
	return err
}

updateKey, updateKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
	return err
}

didPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
	return err
}

jwk, err := jose.JWKFromKey(didPublicKey)
if err != nil {
	return err
}

vm,err:=ariesdid.NewVerificationMethodFromJWK("key1", "Ed25519VerificationKey2018", "", jwk)
if err != nil {
	return err
}

didDoc := &ariesdid.Doc{}

// add did keys
didDoc.Authentication = append(didDoc.Authentication, *ariesdid.NewReferencedVerification(vm,
		ariesdid.Authentication))

// add did services
didDoc.Service = []ariesdid.Service{{ID: "svc1", Type: "type", ServiceEndpoint: "http://www.example.com/"}}

// create did
createdDocResolution, err := vdr.Create(didDoc,
		vdrapi.WithOption(longform.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(longform.UpdatePublicKeyOpt, updateKey),
if err != nil {
	return err
}

fmt.Println(createdDocResolution.DIDDocument.ID)

// recovery private key should be saved for future use.
keyRetrieverImpl.recoverKey = recoveryKeyPrivateKey
// update private key should be saved for future use.
keyRetrieverImpl.updateKey = updateKeyPrivateKey


longFormDID := createdDocResolution.DIDDocument.ID
```

## Resolve DID
For resolving DID use vdr read and pass long form DID. 

```
docResolution, err := vdr.Read(longFormDID)
if err != nil {
	return err
}

fmt.Println(docResolution.DIDDocument.ID)
```

## Update DID
Not supported.

## Recover DID
Not supported.

## Deactivate DID
Not supported.
