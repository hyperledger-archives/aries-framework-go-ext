# Orb VDR
Orb vdr used to manage DID operation.


## New VDR
```
import (
	"crypto"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
)

type keyRetrieverImpl struct {
	nextRecoveryPublicKey crypto.PublicKey
	nextUpdatePublicKey   crypto.PublicKey
	updateKey             crypto.PrivateKey
	recoverKey            crypto.PrivateKey
}

func (k *keyRetrieverImpl) GetNextRecoveryPublicKey(didID string) (crypto.PublicKey, error) {
	return k.nextRecoveryPublicKey, nil
}

func (k *keyRetrieverImpl) GetNextUpdatePublicKey(didID string) (crypto.PublicKey, error) {
	return k.nextUpdatePublicKey, nil
}

func (k *keyRetrieverImpl) GetSigningKey(didID string, ot orb.OperationType) (crypto.PrivateKey, error) {
	if ot == orb.Update {
		return k.updateKey, nil
	}

	return k.recoverKey, nil
}


keyRetrieverImpl := &keyRetrieverImpl{}

vdr, err := orb.New(keyRetrieverImpl, orb.WithDomain("https://testnet.devel.trustbloc.dev"))
	if err != nil {
		return err
}
```

## Create DID
For creating DID use vdr create and pass DID document. To discover orb instance there are two ways explicitly or
through domain.

```
import (
"crypto"
"crypto/ed25519"
"crypto/rand"
"fmt"

ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"

"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
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
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		// No need to use this option because we already use domain
		// vdrapi.WithOption(orb.OperationEndpointsOpt, []string{"https://orb-1.devel.trustbloc.dev/sidetree/v1/operations"}),
		vdrapi.WithOption(orb.AnchorOriginOpt, "https://orb-2.devel.trustbloc.dev/services/orb"))
if err != nil {
	return err
}

fmt.Println(createdDocResolution.DIDDocument.ID)

// recovery private key be will used to sign next recovery request
keyRetrieverImpl.recoverKey = recoveryKeyPrivateKey
// update private key will be used to sign next update request
keyRetrieverImpl.updateKey = updateKeyPrivateKey


discoverableDID := createdDocResolution.DIDDocument.ID
```

## Resolve DID
For resolving DID use vdr read and pass DID URI. To discover orb instance there are two ways explicitly or
through did URI.

```
docResolution, err := vdr.Read(discoverableDID)
if err != nil {
	return err
}

fmt.Println(docResolution.DIDDocument.ID)
```

## Update DID
For updating DID use vdr update and pass DID document. To discover orb instance there are two ways explicitly or
through domain.

```	
updateKey, updateKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
	return err
}

// this key will used for next update request
keyRetrieverImpl.nextUpdatePublicKey = updateKey

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


didDoc := &ariesdid.Doc{ID: discoverableDID}

didDoc.Authentication = append(didDoc.Authentication, *ariesdid.NewReferencedVerification(vm,
		ariesdid.Authentication))

didDoc.CapabilityInvocation = append(didDoc.CapabilityInvocation, *ariesdid.NewReferencedVerification(vm,
		ariesdid.CapabilityInvocation))

didDoc.Service = []ariesdid.Service{
		{
			ID:              "svc1",
			Type:            "typeUpdated",
			ServiceEndpoint: "http://www.example.com/",
		},
		{
			ID:              "svc2",
			Type:            "type",
			ServiceEndpoint: "http://www.example.com/",
		},
}

if err := vdr.Update(didDoc); err != nil {
	return err
}

// update private key will be used to sign next update request
keyRetrieverImpl.updateKey = updateKeyPrivateKey
```

## Recover DID
For recovering DID use vdr recover and pass DID document. To discover orb instance there are two ways explicitly or
through domain.

```	
recoveryKey, recoveryKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
	return err
}

// this key will used for next recover request
keyRetriever.nextRecoveryPublicKey = recoveryKey

didDoc := &ariesdid.Doc{ID: discoverableDID}

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


didDoc.CapabilityInvocation = append(didDoc.CapabilityInvocation, *ariesdid.NewReferencedVerification(vm,
	ariesdid.CapabilityDelegation))

didDoc.Service = []ariesdid.Service{{ID: "svc1", Type: "type", ServiceEndpoint: "http://www.example.com/"}}

if err := e.vdr.Update(didDoc,
	vdrapi.WithOption(orb.RecoverOpt, true), 
	vdrapi.WithOption(orb.AnchorOriginOpt, "https://orb-2.devel.trustbloc.dev/services/orb")); err != nil {
	return err
}

// recover private key will be used to sign next recover request
keyRetrieverImpl.recoverKey = recoveryKeyPrivateKey
```

## Deactivate DID
For deactivating DID use vdr recover and pass DID URI. To discover orb instance there are two ways explicitly or
through domain.

```	
if err:=vdr.Deactivate(discoverableDID);err!=nil{
 return err
}
```
