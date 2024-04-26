package auth

import (
	"bytes"
	"fmt"

	c "github.com/christoffercarlsson/autograph/go/constants"
	"github.com/christoffercarlsson/autograph/go/external"
	"github.com/christoffercarlsson/autograph/go/keypair"
	t "github.com/christoffercarlsson/autograph/go/types"
)

func EncodeFingerprint(digest *t.Digest) t.Fingerprint {
	fingerprint := t.Fingerprint{}
	for i := uint16(0); i < c.FINGERPRINT_SIZE; i += 4 {
		dig := digest[:]
		n := external.GetUint32(&dig, int(i))
		finger := fingerprint[:]
		external.SetUint32(&finger, int(i), n%c.FINGERPRINT_DIVISOR)
	}
	return fingerprint
}

func CalculateFingerprint(publicKey *t.PublicKey) (t.Fingerprint, error) {
	a := [c.DIGEST_SIZE]byte{}
	b := [c.DIGEST_SIZE]byte{}
	success := external.Hash(&a, publicKey[:])
	if !success {
		return t.Fingerprint{}, fmt.Errorf("fingerprint hash failure")
	}
	for i := 1; i < int(c.FINGERPRINT_ITERATIONS); i += 1 {
		success := external.Hash(&b, a[:])
		if !success {
			return t.Fingerprint{}, fmt.Errorf("fingerprint hash failure")
		}
		copy(a[:], b[:])
	}
	return EncodeFingerprint(&a), nil
}

func CalculateSafetyNumber(ourFingerprint *t.Fingerprint, theirFingerprint *t.Fingerprint) t.SafetyNumber {
	safetyNumber := t.SafetyNumber{}

	if bytes.Compare(ourFingerprint[:], theirFingerprint[:]) < 0 {
		copy((safetyNumber)[:c.FINGERPRINT_SIZE], theirFingerprint[:])
		copy((safetyNumber)[c.FINGERPRINT_SIZE:], ourFingerprint[:])
	} else {
		copy((safetyNumber)[:c.FINGERPRINT_SIZE], ourFingerprint[:])
		copy((safetyNumber)[c.FINGERPRINT_SIZE:], theirFingerprint[:])
	}
	return safetyNumber
}

func Authenticate(identityKeyPair *t.KeyPair, theirIdentityKey *t.PublicKey) (t.SafetyNumber, error) {
	ourIdentityKey := keypair.GetPublicKey(identityKeyPair)
	ourFingerprint, err := CalculateFingerprint(&ourIdentityKey)
	if err != nil {
		return t.SafetyNumber{}, err
	}
	theirFingerprint, err := CalculateFingerprint(theirIdentityKey)
	if err != nil {
		return t.SafetyNumber{}, err
	}
	return CalculateSafetyNumber(&ourFingerprint, &theirFingerprint), nil
}
