package cert

import (
	"math"

	c "github.com/christoffercarlsson/autograph/go/constants"
	"github.com/christoffercarlsson/autograph/go/external"
	s "github.com/christoffercarlsson/autograph/go/state"
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

func SignSubject(signature *t.Signature, state *t.State, subject *[]byte) bool {
	return external.Sign(signature, s.GetIdentityKeyPair(state), subject)
}

func CertifyDataOwnership(
	signature *t.Signature,
	state *t.State,
	ownerPublicKey *t.PublicKey,
	data *[]byte,
) bool {
	subject := CalculateSubject(ownerPublicKey, data)
	return SignSubject(signature, state, &subject)
}

func CertifyIdentityOwnership(
	signature *t.Signature,
	state *t.State,
	ownerPublicKey *t.PublicKey,
) bool {
	ownerPublicKeySlice := ownerPublicKey[:]
	return SignSubject(signature, state, &ownerPublicKeySlice)
}

func VerifyDataOwnership(
	ownerPublicKey *t.PublicKey,
	data *[]byte,
	certifierPublicKey *t.PublicKey,
	signature *t.Signature,
) bool {
	subject := CalculateSubject(ownerPublicKey, data)
	return external.Verify(certifierPublicKey, signature, &subject)
}

func VerifyIdentityOwnership(
	ownerPublicKey *t.PublicKey,
	certifierPublicKey *t.PublicKey,
	signature *t.Signature,
) bool {
	ownerPublicKeySlice := ownerPublicKey[:]
	return external.Verify(certifierPublicKey, signature, &ownerPublicKeySlice)
}
