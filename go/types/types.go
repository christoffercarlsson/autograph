package types

import (
	c "github.com/christoffercarlsson/autograph/go/constants"
)

type Bytes = []byte
type Digest = [c.DIGEST_SIZE]byte
type Fingerprint = [c.FINGERPRINT_SIZE]byte
type Hello = [c.HELLO_SIZE]byte
type Ikm = [c.IKM_SIZE]byte
type Index = [c.INDEX_SIZE]byte
type KeyPair = [c.KEY_PAIR_SIZE]byte
type Nonce = [c.NONCE_SIZE]byte
type Okm = [c.OKM_SIZE]byte
type PrivateKey = [c.PRIVATE_KEY_SIZE]byte
type PublicKey = [c.PUBLIC_KEY_SIZE]byte
type SafetyNumber = [c.SAFETY_NUMBER_SIZE]byte
type Salt = [c.SALT_SIZE]byte
type SecretKey = [c.SECRET_KEY_SIZE]byte
type SharedSecret = [c.SHARED_SECRET_SIZE]byte
type Signature = [c.SIGNATURE_SIZE]byte
type Size = [c.SIZE_SIZE]byte
type State = [c.STATE_SIZE]byte
type Transcript = [c.TRANSCRIPT_SIZE]byte
