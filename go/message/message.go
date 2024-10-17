package message

import (
	"fmt"
	"math"

	c "github.com/christoffercarlsson/autograph/go/constants"
	e "github.com/christoffercarlsson/autograph/go/external"
	t "github.com/christoffercarlsson/autograph/go/types"
)

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

func CalculateUnpaddedSize(padded *[]byte) int {
	size := len(*padded)
	if size == 0 || (size%int(c.PADDING_BLOCK_SIZE)) > 0 {
		return 0
	}
	for i := size - 1; i >= (size - int(c.PADDING_BLOCK_SIZE)); i -= 1 {
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

func UnPad(plainText *[]byte) error {
	size := CalculateUnpaddedSize(plainText)
	if size == 0 {
		return fmt.Errorf("unpad calculate unpadded size error")
	}
	// TODO is this an error?
	*plainText = (*plainText)[:size]
	return nil
}

func getIndex(nonce *t.Nonce) uint32 {
	nonceSlice := nonce[:]
	return e.GetUint32(&nonceSlice, int(c.NONCE_SIZE-4))
}

func setIndex(nonce *t.Nonce, index uint32) {
	nonceSlice := nonce[:]
	e.SetUint32(&nonceSlice, int(c.NONCE_SIZE-4), index)
}

func IncrementNonce(nonce *t.Nonce, err error) error {
	index := getIndex(nonce)
	if index == math.MaxUint32 {
		return fmt.Errorf("nonce index out of bounds error")
	}
	setIndex(nonce, index+1)
	return nil
}

func CreateCiphertext(plainText *[]byte) t.Bytes {
	return make([]byte, CalculatePaddedSize(plainText)+int(c.TAG_SIZE))
}

func Encrypt(
	key *t.SecretKey,
	nonce *t.Nonce,
	plainText *[]byte,
) (uint32, []byte, error) {
	incrementNonceError := fmt.Errorf("increment nonce error")
	err := IncrementNonce(nonce, incrementNonceError)
	if err != nil {
		return 0, []byte{}, err
	}
	cipherText := CreateCiphertext(plainText)
	padded := Pad(plainText)
	success := e.Encrypt(&cipherText, key, nonce, &padded)
	if !success {
		return 0, []byte{}, fmt.Errorf("encrypt error")
	}
	return getIndex(nonce), cipherText, nil
}

func CreatePlaintext(cipherText *[]byte) t.Bytes {
	return make([]byte, len(*cipherText)+int(c.TAG_SIZE))
}

func DecryptCipherText(
	key *t.SecretKey,
	nonce *t.Nonce,
	cipherText *[]byte,
) (uint32, []byte, error) {
	plainText := CreatePlaintext(cipherText)
	success := e.Decrypt(&plainText, key, nonce, cipherText)
	if !success {
		return 0, []byte{}, fmt.Errorf("decrypt error")
	}
	err := UnPad(&plainText)
	if err != nil {
		return 0, []byte{}, err
	}
	return getIndex(nonce), plainText, nil
}

func DecryptSkipped(
	key *t.SecretKey,
	skippedIndexes *[]uint32,
	cipherText *[]byte,
) (uint32, []byte, error) {
	nonce := [c.NONCE_SIZE]byte{}
	for i, skippedIndex := range *skippedIndexes {
		if skippedIndex == 0 {
			continue
		}
		setIndex(&nonce, skippedIndex)
		index, plainText, err := DecryptCipherText(key, &nonce, cipherText)
		if err != nil {
			continue
		}
		(*skippedIndexes)[i] = 0
		return index, plainText, nil
	}
	return 0, []byte{}, fmt.Errorf("decrypt skipped fail")
}

func skipIndex(skippedIndexes *[]uint32, nonce *t.Nonce) error {
	index := getIndex(nonce)
	for i, skippedIndex := range *skippedIndexes {
		if skippedIndex == 0 {
			(*skippedIndexes)[i] = index
			return nil
		}
	}
	return fmt.Errorf("skip index failure")
}

func Decrypt(
	key *t.SecretKey,
	nonce *t.Nonce,
	skippedIndexes *[]uint32,
	cipherText *[]byte,
) (uint32, []byte, error) {
	i, plainText, err := DecryptSkipped(key, skippedIndexes, cipherText)
	if err == nil {
		return i, plainText, nil
	}
	for {
		err := IncrementNonce(nonce, fmt.Errorf("increment nonce error"))
		if err != nil {
			return 0, []byte{}, err
		}
		i, plainText, err = DecryptCipherText(key, nonce, cipherText)
		if err != nil {
			err := skipIndex(skippedIndexes, nonce)
			if err != nil {
				return 0, []byte{}, err
			}
		} else {
			return i, plainText, nil
		}
	}
}
