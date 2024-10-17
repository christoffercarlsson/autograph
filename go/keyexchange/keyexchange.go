package keyexchange

import (
	"fmt"

	"github.com/christoffercarlsson/autograph/go/cert"
	c "github.com/christoffercarlsson/autograph/go/constants"
	e "github.com/christoffercarlsson/autograph/go/external"
	"github.com/christoffercarlsson/autograph/go/keypair"
	t "github.com/christoffercarlsson/autograph/go/types"
)

func CalculateSecretKeys(isInitiator bool, okm *t.Okm) (t.SecretKey, t.SecretKey) {
	sendingKey := t.SecretKey{}
	receivingKey := t.SecretKey{}
	if isInitiator {
		copy(sendingKey[:], okm[:c.SECRET_KEY_SIZE])
		copy(receivingKey[:], okm[c.SECRET_KEY_SIZE:])
	} else {
		copy(sendingKey[:], okm[c.SECRET_KEY_SIZE:])
		copy(receivingKey[:], okm[:c.SECRET_KEY_SIZE])
	}
	return sendingKey, receivingKey
}

func DeriveSecretKeys(isInitiator bool, ourSessionKeypair *t.KeyPair, theirSessionKey *t.PublicKey) (t.SecretKey, t.SecretKey, error) {
	var sharedSecret t.SharedSecret = [c.SHARED_SECRET_SIZE]byte{}
	var okm t.Okm = [c.OKM_SIZE]byte{}
	dhSuccess := e.DiffieHellman(
		&sharedSecret,
		ourSessionKeypair,
		theirSessionKey,
	)
	// kdfSuccess := kdf.Kdf(&okm, &sharedSecret)
	salt := [c.SALT_SIZE]byte{}
	e.Zeroize64(&salt)
	saltSlice := salt[:]
	okmSlice := okm[:]
	sharedSecretSlice := sharedSecret[:]
	kdfSuccess := e.Hkdf(&okmSlice, &sharedSecretSlice, &saltSlice, &c.INFO)
	sendingKey, receivingKey := CalculateSecretKeys(isInitiator, &okm)

	e.Zeroize64(&okm)
	e.Zeroize32(&sharedSecret)
	e.Zeroize64(ourSessionKeypair)
	if !dhSuccess || !kdfSuccess {
		return t.SecretKey{}, t.SecretKey{}, fmt.Errorf("diffie or kdf failure")
	}
	return sendingKey, receivingKey, nil
}

func CalculateTranscript(
	isInitiator bool,
	ourSessionKeyPair *t.KeyPair,
	theirSessionKey *t.PublicKey,
) t.Transcript {
	transcript := [c.TRANSCRIPT_SIZE]byte{}
	ourSessionKey := keypair.GetPublicKey(ourSessionKeyPair)
	if isInitiator {
		copy(transcript[:c.PUBLIC_KEY_SIZE], ourSessionKey[:])
		copy(transcript[c.PUBLIC_KEY_SIZE:], theirSessionKey[:])
	} else {
		copy(transcript[:c.PUBLIC_KEY_SIZE], theirSessionKey[:])
		copy(transcript[c.PUBLIC_KEY_SIZE:], ourSessionKey[:])
	}
	return transcript
}

func KeyExchange(isInitiator bool, ourIdentityKeyPair *t.KeyPair, ourSessionKeyPair *t.KeyPair, theirIdentityKey *t.PublicKey, theirSessionKey *t.PublicKey) (t.Transcript, t.Signature, t.SecretKey, t.SecretKey, error) {
	transcript := CalculateTranscript(isInitiator, ourSessionKeyPair, theirSessionKey)
	sendingKey, receivingKey, err := DeriveSecretKeys(isInitiator, ourSessionKeyPair, theirSessionKey)
	if err != nil {
		return t.Transcript{}, t.Signature{}, t.SecretKey{}, t.SecretKey{}, err
	}
	transcriptSlice := transcript[:]
	signature, err := cert.Certify(
		ourIdentityKeyPair,
		theirIdentityKey,
		&transcriptSlice,
	)
	if err != nil {
		return t.Transcript{}, t.Signature{}, t.SecretKey{}, t.SecretKey{}, err
	}
	return transcript, signature, sendingKey, receivingKey, nil
}

func VerifyKeyExchange(transcript *t.Transcript, ourIdentityKeyPair *t.KeyPair, theirIdentityKey *t.PublicKey, theirSignature *t.Signature) error {
	ourIdentityKey := keypair.GetPublicKey(ourIdentityKeyPair)
	transcriptSlice := transcript[:]
	verifySuccess := cert.Verify(&ourIdentityKey, theirIdentityKey, theirSignature, &transcriptSlice)
	if !verifySuccess {
		return fmt.Errorf("verify failure")
	}
	return nil
}
