package keypair

import (
	"testing"
)

func isZeroized(s []byte) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestKeyPairSession(t *testing.T) {
	keyPair, err := GenerateSessionKeyPair()
	if err != nil {
		t.Errorf("TEST:KEYPAIR:FAIL GenerateKeyPair Session returned err")
	}
	if isZeroized(keyPair[:]) {
		t.Errorf("TEST:KEYPAIR:FAIL Generated Session KeyPair is zeroized")
	}
}

func TestKeyPairIdentity(t *testing.T) {
	keyPair, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Errorf("TEST:KEYPAIR:FAIL GenerateKeyPair Identity returned err")
	}
	if isZeroized(keyPair[:]) {
		t.Errorf("TEST:KEYPAIR:FAIL Generated Identity KeyPair is zeroized")
	}
}
