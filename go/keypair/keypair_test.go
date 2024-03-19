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

func TestKeyPairEphemral(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Errorf("TEST:KEYPAIR:FAIL GenerateKeyPair Ephemral returned err")
	}
	if isZeroized(keyPair[:]) {
		t.Errorf("TEST:KEYPAIR:FAIL Generated Ephemral KeyPair is zeroized")
	}
}

func TestKeyPairIdentity(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Errorf("TEST:KEYPAIR:FAIL GenerateKeyPair Identity returned err")
	}
	if isZeroized(keyPair[:]) {
		t.Errorf("TEST:KEYPAIR:FAIL Generated Identity KeyPair is zeroized")
	}
}
