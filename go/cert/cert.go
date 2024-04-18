package cert

import (
	"fmt"
	"math"

	c "github.com/christoffercarlsson/autograph/go/constants"
	"github.com/christoffercarlsson/autograph/go/external"
	t "github.com/christoffercarlsson/autograph/go/types"
)

func CreateSubject(data *[]byte) []byte {
	maxSize := math.MaxUint32 - int(c.PUBLIC_KEY_SIZE)
	var dataSize int
	if len(*data) > maxSize {
		dataSize = maxSize
	} else {
		dataSize = len(*data)
	}
	return make([]byte, dataSize+int(c.PUBLIC_KEY_SIZE))
}

func CalculateSubject(publicKey *t.PublicKey, data *[]byte) []byte {
	subject := CreateSubject(data)
	keyOffset := len(subject) - int(c.PUBLIC_KEY_SIZE)

	copy(subject[:keyOffset], (*data)[:keyOffset])
	copy(subject[keyOffset:], (*publicKey)[:])

	return subject
}

func Certify(
	ourIdentityKeyPair *t.KeyPair,
	theirIdentityKey *t.PublicKey,
	data *[]byte,
) (t.Signature, error) {
	signature := t.Signature{}
	subject := CalculateSubject(theirIdentityKey, data)
	success := external.Sign(&signature, (*[64]byte)(ourIdentityKeyPair), &subject)
	if !success {
		return signature, fmt.Errorf("sign failure")
	}
	return signature, nil
}

func Verify(
	ownerIdentityKey *t.PublicKey,
	certifierIdentityKey *t.PublicKey,
	signature *t.Signature,
	data *[]byte,
) bool {
	subject := CalculateSubject(ownerIdentityKey, data)
	return external.Verify(certifierIdentityKey, signature, &subject)
}
