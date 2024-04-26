package keypair

import (
	"fmt"

	c "github.com/christoffercarlsson/autograph/go/constants"
	e "github.com/christoffercarlsson/autograph/go/external"
	t "github.com/christoffercarlsson/autograph/go/types"
)

func SessionKeyPair(keyPair *t.KeyPair) bool {
	if !e.Init() {
		return false
	}
	return e.KeyPairSession(keyPair)
}

func IdentityKeyPair(keyPair *t.KeyPair) bool {
	if !e.Init() {
		return false
	}
	return e.KeyPairIdentity(keyPair)
}

func GenerateSessionKeyPair() (t.KeyPair, error) {
	var keyPair t.KeyPair = [c.KEY_PAIR_SIZE]byte{}
	success := SessionKeyPair(&keyPair)
	if !success {
		return [c.KEY_PAIR_SIZE]byte{}, fmt.Errorf("failed to generate KeyPair")
	}
	return keyPair, nil
}

func GenerateIdentityKeyPair() (t.KeyPair, error) {
	var keyPair t.KeyPair = [c.KEY_PAIR_SIZE]byte{}
	success := IdentityKeyPair(&keyPair)
	if !success {
		return [c.KEY_PAIR_SIZE]byte{}, fmt.Errorf("failed to generate identity KeyPair")
	}
	return keyPair, nil
}

func GetPublicKey(keyPair *t.KeyPair) t.PublicKey {
	return [c.PUBLIC_KEY_SIZE]byte(keyPair[c.PRIVATE_KEY_SIZE:])
}
