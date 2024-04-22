package external

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
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
	ourKeypair *t.KeyPair,
	theirPublicKey *t.PublicKey,
) bool {
	ourPrivateKey := ourKeypair[:c.PRIVATE_KEY_SIZE]
	sharedSecret, err := curve25519.X25519(ourPrivateKey[:], theirPublicKey[:])
	if err != nil {
		Zeroize(&ourPrivateKey)
		Zeroize(&sharedSecret)
		return false
	}
	copy((*sharedSecretRef)[:], sharedSecret)
	Zeroize(&ourPrivateKey)
	Zeroize(&sharedSecret)
	return true
}

func CreateKeyPair(keyPair *t.KeyPair, privateKey *t.PrivateKey, publicKey *t.PublicKey) {
	copy((*keyPair)[:], (*privateKey)[:])
	copy((*keyPair)[c.PRIVATE_KEY_SIZE:], (*publicKey)[:])
	Zeroize32(privateKey)
	Zeroize32(publicKey)
}

func KeyPairSession(keyPair *t.KeyPair) bool {
	var private, public [32]byte

	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		return false
	}

	curve25519.ScalarBaseMult(&public, &private)
	copy((*keyPair)[:], private[:])
	copy((*keyPair)[c.PRIVATE_KEY_SIZE:], public[:])
	Zeroize32(&private)
	Zeroize32(&public)
	return true
}

func KeyPairIdentity(keyPair *t.KeyPair) bool {
	_, privSeed64, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false
	}
	keyPairSlice := keyPair[:]
	copy(keyPairSlice, ed25519.NewKeyFromSeed(privSeed64[:c.PRIVATE_KEY_SIZE])[:])
	Zeroize((*[]byte)(&privSeed64))
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

func Zeroize12(arr *[12]byte) {
	slice := arr[:]
	Zeroize(&slice)
}

func GetUint32(bytes *[]byte, offset int) uint32 {
	return binary.BigEndian.Uint32((*bytes)[offset : offset+4])
}

func SetUint32(bytes *[]byte, offset int, number uint32) {
	newBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(newBytes, number)
	for i := 0; i < 4; i += 1 {
		(*bytes)[i+int(offset)] = newBytes[i]
	}
}
