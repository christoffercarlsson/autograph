package channel

import (
	"fmt"

	"github.com/christoffercarlsson/autograph/go/auth"
	"github.com/christoffercarlsson/autograph/go/cert"
	c "github.com/christoffercarlsson/autograph/go/constants"
	e "github.com/christoffercarlsson/autograph/go/external"
	"github.com/christoffercarlsson/autograph/go/keyexchange"
	"github.com/christoffercarlsson/autograph/go/keypair"
	m "github.com/christoffercarlsson/autograph/go/message"
	t "github.com/christoffercarlsson/autograph/go/types"
)

type Channel struct {
	ourIdentityKeyPair t.KeyPair
	ourSessionKeyPair  t.KeyPair
	theirIdentityKey   t.PublicKey
	theirSessionKey    t.PublicKey
	transcript         t.Transcript
	sendingKey         t.SecretKey
	receivingKey       t.SecretKey
	sendingNonce       t.Nonce
	receivingNonce     t.Nonce
	skippedIndexes     []uint32
	established        bool
}

func New(skippedIndexesCount uint16) Channel {
	return Channel{
		ourIdentityKeyPair: [c.KEY_PAIR_SIZE]byte{},
		ourSessionKeyPair:  [c.KEY_PAIR_SIZE]byte{},
		theirIdentityKey:   [c.PUBLIC_KEY_SIZE]byte{},
		theirSessionKey:    [c.PUBLIC_KEY_SIZE]byte{},
		transcript:         [c.TRANSCRIPT_SIZE]byte{},
		sendingKey:         [c.SECRET_KEY_SIZE]byte{},
		receivingKey:       [c.SECRET_KEY_SIZE]byte{},
		sendingNonce:       [c.NONCE_SIZE]byte{},
		receivingNonce:     [c.NONCE_SIZE]byte{},
		skippedIndexes:     createSkippedIndexes(&skippedIndexesCount),
		established:        false,
	}
}

func createSkippedIndexes(count *uint16) []uint32 {
	size := c.DEFAULT_SKIPPED_INDEXES_COUNT
	if count != nil {
		size = *count
	}
	skippedIndexes := make([]uint32, size)
	return skippedIndexes
}

func (ch *Channel) IsEstablished() bool {
	return ch.established
}

func (ch *Channel) UseKeyPairs(
	ourIdentityKeyPair *t.KeyPair,
	ourSessionKeyPair *t.KeyPair,
) (t.PublicKey, t.PublicKey) {
	ch.established = false
	identityKey := keypair.GetPublicKey(ourIdentityKeyPair)
	sessionKey := keypair.GetPublicKey(ourSessionKeyPair)
	copy(ch.ourIdentityKeyPair[:], ourIdentityKeyPair[:])
	copy(ch.ourSessionKeyPair[:], ourSessionKeyPair[:])
	e.Zeroize64(ourSessionKeyPair)
	return identityKey, sessionKey
}

func (ch *Channel) UsePublicKeys(
	theirIdentityKey *t.PublicKey,
	theirSessionKey *t.PublicKey,
) {
	ch.established = false
	copy(ch.theirIdentityKey[:], theirIdentityKey[:])
	copy(ch.theirSessionKey[:], theirSessionKey[:])
}

func (ch *Channel) Authenticate() (t.SafetyNumber, error) {
	return auth.Authenticate(&ch.ourIdentityKeyPair, &ch.theirIdentityKey)
}

func (ch *Channel) Certify(data *[]byte) (t.Signature, error) {
	return cert.Certify(&ch.ourIdentityKeyPair, &ch.theirIdentityKey, data)
}

func (ch *Channel) Verify(certifierIdentityKey *t.PublicKey, signature *t.Signature, data *[]byte) bool {
	return cert.Verify(&ch.theirIdentityKey, certifierIdentityKey, signature, data)
}

func (ch *Channel) KeyExchange(isInitiator bool) (t.Signature, error) {
	ch.established = false
	transcript, signature, sendingKey, receivingKey, err := keyexchange.KeyExchange(isInitiator, &ch.ourIdentityKeyPair, &ch.ourSessionKeyPair, &ch.theirIdentityKey, &ch.theirSessionKey)
	if err != nil {
		return signature, fmt.Errorf("FAIL: KeyExchange")
	}
	copy(ch.transcript[:], transcript[:])
	copy(ch.sendingKey[:], sendingKey[:])
	copy(ch.receivingKey[:], receivingKey[:])
	return signature, nil
}

func (ch *Channel) VerifyKeyExchange(theirSignature *t.Signature) error {
	err := keyexchange.VerifyKeyExchange(&ch.transcript, &ch.ourIdentityKeyPair, &ch.theirIdentityKey, theirSignature)
	e.Zeroize12(&ch.sendingNonce)
	e.Zeroize12(&ch.receivingNonce)
	for i := range ch.skippedIndexes {
		ch.skippedIndexes[i] = 0
	}
	ch.established = err == nil
	return err
}

func (ch *Channel) Encrypt(plainText *[]byte) (uint32, t.Bytes, error) {
	if ch.established {
		return m.Encrypt(&ch.sendingKey, &ch.sendingNonce, plainText)
	} else {
		return 0, []byte{}, fmt.Errorf("encryption failed")
	}
}

func (ch *Channel) Decrypt(cipherText *[]byte) (uint32, t.Bytes, error) {
	if ch.established {
		return m.Decrypt(&ch.receivingKey, &ch.receivingNonce, &ch.skippedIndexes, cipherText)
	} else {
		return 0, []byte{}, fmt.Errorf("decryption failed")
	}
}

func (ch *Channel) Close() {
	ch.established = false
	e.Zeroize64(&ch.ourIdentityKeyPair)
	e.Zeroize64(&ch.ourSessionKeyPair)
	e.Zeroize32(&ch.sendingKey)
	e.Zeroize32(&ch.receivingKey)
	e.Zeroize12(&ch.sendingNonce)
	e.Zeroize12(&ch.receivingNonce)
	for i := range ch.skippedIndexes {
		ch.skippedIndexes[i] = 0
	}
}
