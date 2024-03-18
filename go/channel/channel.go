package channel

import (
	"fmt"

	"github.com/christoffercarlsson/autograph/go/auth"
	"github.com/christoffercarlsson/autograph/go/cert"
	c "github.com/christoffercarlsson/autograph/go/constants"
	e "github.com/christoffercarlsson/autograph/go/external"
	"github.com/christoffercarlsson/autograph/go/kdf"
	"github.com/christoffercarlsson/autograph/go/keyexchange"
	"github.com/christoffercarlsson/autograph/go/numbers"
	s "github.com/christoffercarlsson/autograph/go/state"
	t "github.com/christoffercarlsson/autograph/go/types"
)

func UseKeyPairs(
	publicKeys *t.Hello,
	state *t.State,
	identityKeyPair t.KeyPair,
	ephemeralKeyPair t.KeyPair,
) bool {

	s.ZeroizeState(state)
	if !e.Init() {
		return false
	}
	s.SetIdentityKeyPair(state, &identityKeyPair)
	s.SetEphemeralKeyPair(state, &ephemeralKeyPair)
	copy((*publicKeys)[:], identityKeyPair[c.PRIVATE_KEY_SIZE:])
	copy((*publicKeys)[c.PUBLIC_KEY_SIZE:], ephemeralKeyPair[c.PRIVATE_KEY_SIZE:])
	e.Zeroize64(&identityKeyPair)
	e.Zeroize64(&ephemeralKeyPair)
	return true
}

func UsePublicKeys(state *t.State, publicKeys *t.Hello) {
	id_pub := [c.PUBLIC_KEY_SIZE]byte(publicKeys[:c.PUBLIC_KEY_SIZE])
	eph_pub := [c.PUBLIC_KEY_SIZE]byte(publicKeys[c.PUBLIC_KEY_SIZE:])
	s.SetTheirIdentityKey(
		state,
		&id_pub,
	)
	s.SetTheirEphemeralKey(
		state,
		&eph_pub,
	)
}

func CalculatePaddedSize(plainText *[]byte) int {
	size := len(*plainText)
	return size + int(c.PADDING_BLOCK_SIZE) - (size % int(c.PADDING_BLOCK_SIZE))
}

func Pad(plainText *[]byte) t.Bytes {
	bytes := (*plainText)[:]
	paddedSize := CalculatePaddedSize(plainText)
	for range paddedSize - len(bytes) {
		bytes = append(bytes, 0)
	}
	bytes[len(*plainText)] = c.PADDING_BYTE
	return bytes
}

func EncryptPlainText(
	cipherText *[]byte,
	key *t.SecretKey,
	nonce *t.Nonce,
	plainText *[]byte,
) bool {
	padded := Pad(plainText)
	return e.Encrypt(cipherText, key, nonce, &padded)
}

func EncryptMessage(
	cipherText *[]byte,
	index *t.Index,
	state *t.State,
	plainText *[]byte,
) bool {
	if !s.IncrementSendingIndex(state) {
		s.ZeroizeState(state)
		return false
	}
	if !EncryptPlainText(
		cipherText,
		s.GetSendingKey(state),
		s.GetSendingNonce(state),
		plainText,
	) {
		s.ZeroizeState(state)
		return false
	}
	idx := s.GetSendingIndex(state)
	copy((*index)[:], idx[:])
	return true
}

func CalculateUnpaddedSize(padded *[]byte) int {
	size := len(*padded)
	if size == 0 || (size%int(c.PADDING_BLOCK_SIZE)) > 0 {
		return 0
	}
	for i := size - 1; i > (size - int(c.PADDING_BLOCK_SIZE)); i -= 1 {
		byte := (*padded)[i]
		if byte == c.PADDING_BYTE {
			return i
		}
		if byte != 0 {
			return 0
		}
	}
	return 0
}

func UnPad(unpaddedSize *t.Size, padded *[]byte) bool {
	size := CalculateUnpaddedSize(padded)
	if size == 0 {
		return false
	}
	numbers.SetSize(unpaddedSize, size)
	return true
}

func DecryptCipherText(
	plainText *[]byte,
	plainTextSize *t.Size,
	key *t.SecretKey,
	nonce *t.Nonce,
	cipherText *[]byte,
) bool {

	if e.Decrypt(plainText, key, nonce, cipherText) {
		return UnPad(plainTextSize, plainText)
	}
	return false
}

func DecryptCurrent(
	plainText *[]byte,
	plainTextSize *t.Size,
	state *t.State,
	cipherText *[]byte,
) bool {
	return DecryptCipherText(
		plainText,
		plainTextSize,
		s.GetReceivingKey(state),
		s.GetReceivingNonce(state),
		cipherText,
	)
}

func DecryptSkipped(
	plainText *[]byte,
	plainTextSize *t.Size,
	index *t.Index,
	state *t.State,
	cipherText *[]byte,
) bool {
	key := s.GetReceivingKey(state)
	var nonce t.Nonce = [c.NONCE_SIZE]byte{}
	offset := s.GetSkippedIndex(index, &nonce, state, 0)
	session_size := s.CalculateStateSize(state)
	for {
		if DecryptCipherText(plainText, plainTextSize, key, &nonce, cipherText) {
			s.DeleteSkippedIndex(state, offset)
			return true
		}
		offset = s.GetSkippedIndex(index, &nonce, state, offset)
		if offset > session_size {
			break
		}
	}
	return false
}

func DecryptMessage(
	plainText *[]byte,
	plainTextSize *t.Size,
	index *t.Index,
	state *t.State,
	cipherText *[]byte,
) bool {
	if DecryptSkipped(plainText, plainTextSize, index, state, cipherText) {
		return true
	}
	for {
		if !s.IncrementReceivingIndex(state) {
			s.ZeroizeState(state)
			return false
		}
		if DecryptCurrent(plainText, plainTextSize, state, cipherText) {
			receivingIndex := s.GetReceivingIndex(state)
			copy((*index)[:], receivingIndex[:])
			return true
		} else if !s.SkipIndex(state) {
			s.ZeroizeState(state)
			return false
		}
	}
}

func CertifyData(signature *t.Signature, state *t.State, data *[]byte) bool {
	return cert.CertifyDataOwnership(signature, state, s.GetTheirIdentityKey(state), data)
}

func CertifyIdentity(signature *t.Signature, state *t.State) bool {
	return cert.CertifyIdentityOwnership(signature, state, s.GetTheirIdentityKey(state))
}

func VerifyData(
	state *t.State,
	data *[]byte,
	publicKey *t.PublicKey,
	signature *t.Signature,
) bool {
	return cert.VerifyDataOwnership(s.GetTheirIdentityKey(state), data, publicKey, signature)
}

func VerifyIdentity(state *t.State, publicKey *t.PublicKey, signature *t.Signature) bool {
	return cert.VerifyIdentityOwnership(s.GetTheirIdentityKey(state), publicKey, signature)
}

func CreateCiphertext(plainText *[]byte) t.Bytes {
	return make([]byte, CalculatePaddedSize(plainText)+int(c.TAG_SIZE))
}

func CreatePlaintext(cipherText *[]byte) t.Bytes {
	return make([]byte, len(*cipherText)+int(c.TAG_SIZE))
}

func DeriveSessionKey(key *t.SecretKey, state *t.State) bool {
	okm := [c.OKM_SIZE]byte{}
	success := kdf.Kdf(&okm, s.GetSendingKey(state))
	if success {
		copy(key[:], okm[:c.SECRET_KEY_SIZE])
	}
	e.Zeroize64(&okm)
	return success
}

func CloseChannel(key *t.SecretKey, cipherText *[]byte, state *t.State) bool {
	if !DeriveSessionKey(key, state) {
		s.ZeroizeState(state)
		return false
	}
	plainText := s.GetState(state)
	var nonce t.Nonce = [c.NONCE_SIZE]byte{}
	success := EncryptPlainText(cipherText, key, &nonce, plainText)
	s.ZeroizeState(state)
	e.Zeroize(plainText)
	return success
}

func OpenChannel(state *t.State, key *t.SecretKey, cipherText *[]byte) bool {
	plainText := CreatePlaintext(cipherText)
	var plainTextSize t.Size = [c.SIZE_SIZE]byte{}
	var nonce t.Nonce = [c.NONCE_SIZE]byte{}
	success := DecryptCipherText(&plainText, &plainTextSize, key, &nonce, cipherText)
	e.Zeroize32(key)
	if success {
		size := numbers.ReadSize(plainTextSize)
		copy((*state)[:size], plainText)
	}
	return success
}

func ResizePlaintext(plainText t.Bytes, plainTextSize t.Size) t.Bytes {
	size := numbers.ReadSize(plainTextSize)
	if size == len(plainText) {
		return plainText
	}
	if size < len(plainText) {
		return plainText[:size]
	}
	for range size - len(plainText) {
		plainText = append(plainText, 0)
	}
	return plainText
}

type Channel struct {
	state t.State
}

func New() Channel {
	return Channel{[c.STATE_SIZE]byte{}}
}

func (ch *Channel) UseKeyPairs(
	identityKeyPair t.KeyPair,
	ephemeralKeyPair t.KeyPair,
) (t.Hello, error) {
	publicKeys := [c.HELLO_SIZE]byte{}
	success := UseKeyPairs(&publicKeys, &ch.state, identityKeyPair, ephemeralKeyPair)
	if !success {
		return publicKeys, fmt.Errorf("FAIL: UseKeyPairs")
	}
	return publicKeys, nil
}

func (ch *Channel) UsePublicKeys(publicKeys *t.Hello) {
	UsePublicKeys(&ch.state, publicKeys)
}

func (ch *Channel) Authenticate() (t.SafetyNumber, error) {
	var safetyNumber t.SafetyNumber = [c.SAFETY_NUMBER_SIZE]byte{}
	success := auth.Authenticate(&safetyNumber, &ch.state)
	if !success {
		return safetyNumber, fmt.Errorf("FAIL: Authenticate")
	}
	return safetyNumber, nil
}

func (ch *Channel) KeyExchange(isInitiator bool) (t.Signature, error) {
	var signature t.Signature = [c.SIGNATURE_SIZE]byte{}
	success := keyexchange.KeyExchange(&signature, &ch.state, isInitiator)
	if !success {
		return signature, fmt.Errorf("FAIL: KeyExchange")
	}
	return signature, nil
}

func (ch *Channel) VerifyKeyExchange(signature t.Signature) error {
	verified := keyexchange.VerifyKeyExchange(&ch.state, signature)
	if !verified {
		return fmt.Errorf("FAIL: VerifyKeyExchange")
	}
	return nil
}

func (ch *Channel) Encrypt(plainText *[]byte) (uint32, t.Bytes, error) {
	cipherText := CreateCiphertext(plainText)
	var index t.Index = [c.INDEX_SIZE]byte{}
	success := EncryptMessage(&cipherText, &index, &ch.state, plainText)
	if !success {
		return 0, nil, fmt.Errorf("FAIL: Encrypt")
	}
	return numbers.ReadIndex(index), cipherText, nil
}

func (ch *Channel) Decrypt(cipherText *[]byte) (uint32, t.Bytes, error) {
	plainText := CreatePlaintext(cipherText)
	var size t.Size = [c.SIZE_SIZE]byte{}
	var index t.Index = [c.INDEX_SIZE]byte{}
	success := DecryptMessage(
		&plainText,
		&size,
		&index,
		&ch.state,
		cipherText,
	)
	if !success {
		return 0, nil, fmt.Errorf("FAIL: Decrypt")
	}
	return numbers.ReadIndex(index), ResizePlaintext(plainText, size), nil
}

func (ch *Channel) CertifyIdentity() (t.Signature, error) {
	signature := [c.SIGNATURE_SIZE]byte{}
	success := CertifyIdentity(&signature, &ch.state)
	if !success {
		return signature, fmt.Errorf("FAIL: Certify Identity")
	}
	return signature, nil
}

func (ch *Channel) CertifyData(data *[]byte) (t.Signature, error) {
	var signature t.Signature = [c.SIGNATURE_SIZE]byte{}
	success := CertifyData(&signature, &ch.state, data)
	if !success {
		return signature, fmt.Errorf("FAIL: CertifyData")
	}
	return signature, nil
}

func (ch *Channel) VerifyData(data *[]byte, publicKey *t.PublicKey, signature *t.Signature) bool {
	return VerifyData(&ch.state, data, publicKey, signature)
}

func (ch *Channel) VerifyIdentity(publicKey *t.PublicKey, signature *t.Signature) bool {
	return VerifyIdentity(&ch.state, publicKey, signature)
}

func (ch *Channel) Close() (t.SecretKey, t.Bytes, error) {
	var key t.SecretKey = [c.SECRET_KEY_SIZE]byte{}
	cipherText := CreateCiphertext(s.GetState(&ch.state))
	success := CloseChannel(&key, &cipherText, &ch.state)
	if !success {
		return key, nil, fmt.Errorf("FAIL: Close channel")
	}
	return key, cipherText, nil
}

func (ch *Channel) Open(key *t.SecretKey, cipherText *[]byte) error {
	success := OpenChannel(&ch.state, key, cipherText)
	if !success {
		return fmt.Errorf("FAIL: Open channel")
	}
	return nil
}
