package external

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"io"

	c "github.com/christoffercarlsson/autograph/go/constants"
	t "github.com/christoffercarlsson/autograph/go/types"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func Init() bool {
	return true
}

func Encrypt(cipherText *[]byte, key *t.SecretKey, nonce *t.Nonce, plaintext *[]byte) bool {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return false
	}
	result := aead.Seal([]byte{}, nonce[:], *plaintext, nil)
	copy(*cipherText, result)
	return true
}

func Decrypt(plainText *[]byte, key *t.SecretKey, nonce *t.Nonce, cipherText *[]byte) bool {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return false
	}
	result, err := aead.Open([]byte{}, nonce[:], *cipherText, nil)
	if err != nil {
		return false
	}
	copy(*plainText, result)

	*plainText = (*plainText)[:len(result)]
	return true
}

func DiffieHellman(
	sharedSecretRef *t.SharedSecret,
	ourPrivateKey *t.PrivateKey,
	theirPublicKey *t.PublicKey,
) bool {
	sharedSecret, err := curve25519.X25519(ourPrivateKey[:], theirPublicKey[:])
	if err != nil {
		return false
	}
	copy((*sharedSecretRef)[:], sharedSecret)
	Zeroize(&sharedSecret)
	return true
}

func CreateKeyPair(keyPair *t.KeyPair, privateKey *t.PrivateKey, publicKey *t.PublicKey) {
	copy((*keyPair)[:], (*privateKey)[:])
	copy((*keyPair)[c.PRIVATE_KEY_SIZE:], (*publicKey)[:])
	Zeroize32(privateKey)
	Zeroize32(publicKey)
}

func KeyPairEphemeral(keyPair *t.KeyPair) bool {
	var private, public [32]byte

	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		return false
	}

	curve25519.ScalarBaseMult(&public, &private)
	copy((*keyPair)[:], private[:])
	copy((*keyPair)[c.PRIVATE_KEY_SIZE:], private[:])
	Zeroize32(&private)
	Zeroize32(&public)
	return true
}

func KeyPairIdentity(keyPair *t.KeyPair) bool {
	pub, privSeed64, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false
	}
	var privSeed32 = [32]byte(privSeed64)
	var privateKey = [32]byte(ed25519.NewKeyFromSeed(privSeed32[:]))
	var publicKey = [32]byte(pub)
	CreateKeyPair(keyPair, &privateKey, &publicKey)
	Zeroize((*[]byte)(&privSeed64))
	Zeroize((*[]byte)(&pub))
	Zeroize32(&privSeed32)
	Zeroize32(&privateKey)
	Zeroize32(&publicKey)
	return true
}

func Sign(signature *t.Signature, keyPair *t.KeyPair, message *[]byte) bool {
	key := ed25519.NewKeyFromSeed(keyPair[:32])
	signed := ed25519.Sign(key, *message)
	copy((*signature)[:], signed)
	return true
}

func Verify(publicKey *t.PublicKey, signature *t.Signature, message *[]byte) bool {
	return ed25519.Verify(publicKey[:], *message, signature[:])
}

func Hash(digest *t.Digest, message []byte) bool {
	result := sha512.Sum512(message)
	copy((*digest)[:], result[:])
	return true
}

func Hkdf(okm *[]byte, ikm *[]byte, salt *[]byte, info *[]byte) bool {
	hkdf := hkdf.New(sha512.New, *ikm, *salt, *info)
	_, err := io.ReadFull(hkdf, (*okm))
	return err == nil
}

func Zeroize(data *[]byte) {
	for i := range *data {
		(*data)[i] = 0
	}
}

func Zeroize64(arr *[64]byte) {
	slice := arr[:]
	Zeroize(&slice)
}

func Zeroize32(arr *[32]byte) {
	slice := arr[:]
	Zeroize(&slice)
}
