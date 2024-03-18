package state

import (
	"math"

	c "github.com/christoffercarlsson/autograph/go/constants"
	e "github.com/christoffercarlsson/autograph/go/external"
	"github.com/christoffercarlsson/autograph/go/numbers"
	t "github.com/christoffercarlsson/autograph/go/types"
)

func SetIdentityKeyPair(state *t.State, keyPair *t.KeyPair) {
	for i := uint16(0); i < c.KEY_PAIR_SIZE; i += 1 {
		state[i+c.IDENTITY_KEY_PAIR_OFFSET] = (*keyPair)[i]
	}
}

func GetIdentityKeyPair(state *t.State) *t.KeyPair {
	return (*[c.KEY_PAIR_SIZE]byte)(state[c.IDENTITY_KEY_PAIR_OFFSET:])
}

func GetIdentityPublicKey(state *t.State) *t.PublicKey {
	return (*[c.PUBLIC_KEY_SIZE]byte)(state[c.IDENTITY_PUBLIC_KEY_OFFSET:])
}

func GetTheirIdentityKey(state *t.State) *t.PublicKey {
	return (*[c.PUBLIC_KEY_SIZE]byte)(state[c.THEIR_IDENTITY_KEY_OFFSET:])
}

func SetTheirIdentityKey(state *t.State, publicKey *t.PublicKey) {
	for i := uint16(0); i < c.PUBLIC_KEY_SIZE; i += 1 {
		state[i+c.THEIR_IDENTITY_KEY_OFFSET] = (*publicKey)[i]
	}
}

func GetSendingNonce(state *t.State) *t.Nonce {
	return (*[c.NONCE_SIZE]byte)(state[c.SENDING_NONCE_OFFSET:])
}

func GetSendingIndex(state *t.State) *t.Index {
	return (*[c.INDEX_SIZE]byte)(state[c.SENDING_INDEX_OFFSET:])
}

func GetSendingKey(state *t.State) *t.SecretKey {
	return (*[c.SECRET_KEY_SIZE]byte)(state[c.SENDING_KEY_OFFSET:])
}

func GetReceivingNonce(state *t.State) *t.Nonce {
	return (*[c.NONCE_SIZE]byte)(state[c.RECEIVING_NONCE_OFFSET:])
}

func GetReceivingIndex(state *t.State) *t.Index {
	return (*[c.INDEX_SIZE]byte)(state[c.RECEIVING_INDEX_OFFSET:])
}

func GetReceivingKey(state *t.State) *t.SecretKey {
	return (*[c.SECRET_KEY_SIZE]byte)(state[c.RECEIVING_KEY_OFFSET:])
}

func GetEphemeralPrivateKey(state *t.State) *t.PrivateKey {
	return (*[c.PRIVATE_KEY_SIZE]byte)(state[c.EPHEMERAL_KEY_PAIR_OFFSET:])
}

func DeleteEphemeralPrivateKey(state *t.State) {
	ephPrivKeySlice := state[c.EPHEMERAL_KEY_PAIR_OFFSET : c.EPHEMERAL_KEY_PAIR_OFFSET+c.PRIVATE_KEY_SIZE]
	e.Zeroize(&ephPrivKeySlice)
}

func GetTheirEphemeralKey(state *t.State) *t.PublicKey {
	return (*[c.PUBLIC_KEY_SIZE]byte)(state[c.THEIR_EPHEMERAL_KEY_OFFSET:])
}

func SetSecretKeys(state *t.State, isInitiator bool, okm *t.Okm) {
	if isInitiator {
		for i := uint16(0); i < c.SECRET_KEY_SIZE; i += 1 {
			state[i+c.SENDING_KEY_OFFSET] = okm[i]
			state[i+c.RECEIVING_KEY_OFFSET] = okm[i+c.SECRET_KEY_SIZE]
		}
	} else {
		for i := uint16(0); i < c.SECRET_KEY_SIZE; i += 1 {
			state[i+c.SENDING_KEY_OFFSET] = okm[i+c.SECRET_KEY_SIZE]
			state[i+c.RECEIVING_KEY_OFFSET] = okm[i]
		}
	}
}

func IncrementIndex(state *t.State, offset uint16) bool {
	stateSlice := state[:]
	index := numbers.GetUint32(&stateSlice, int(offset))
	if index == math.MaxUint32 {
		return false
	}
	numbers.SetUint32(&stateSlice, int(offset), index+1)
	return true
}

func IncrementSendingIndex(state *t.State) bool {
	return IncrementIndex(state, c.SENDING_INDEX_OFFSET)
}

func IncrementReceivingIndex(state *t.State) bool {
	return IncrementIndex(state, c.RECEIVING_INDEX_OFFSET)
}

func SetEphemeralKeyPair(state *t.State, keyPair *t.KeyPair) {
	for i := uint16(0); i < c.KEY_PAIR_SIZE; i += 1 {
		state[i+c.EPHEMERAL_KEY_PAIR_OFFSET] = (*keyPair)[i]
	}
}

func SetTheirEphemeralKey(state *t.State, publicKey *t.PublicKey) {
	for i := uint16(0); i < c.PUBLIC_KEY_SIZE; i += 1 {
		state[i+c.THEIR_EPHEMERAL_KEY_OFFSET] = publicKey[i]
	}
}

func SetTranscript(state *t.State, isInitiator bool) {
	if isInitiator {
		copy(
			state[c.TRANSCRIPT_OFFSET:c.TRANSCRIPT_OFFSET+c.PUBLIC_KEY_SIZE],
			state[c.EPHEMERAL_PUBLIC_KEY_OFFSET:c.EPHEMERAL_PUBLIC_KEY_OFFSET+c.PUBLIC_KEY_SIZE],
		)
		copy(
			state[c.TRANSCRIPT_OFFSET+c.PUBLIC_KEY_SIZE:c.TRANSCRIPT_OFFSET+c.PUBLIC_KEY_SIZE+c.PUBLIC_KEY_SIZE],
			state[c.THEIR_EPHEMERAL_KEY_OFFSET:c.THEIR_EPHEMERAL_KEY_OFFSET+c.PUBLIC_KEY_SIZE],
		)
	} else {
		copy(
			state[c.TRANSCRIPT_OFFSET:c.TRANSCRIPT_OFFSET+c.PUBLIC_KEY_SIZE],
			state[c.THEIR_EPHEMERAL_KEY_OFFSET:c.THEIR_EPHEMERAL_KEY_OFFSET+c.PUBLIC_KEY_SIZE],
		)
		copy(
			state[c.TRANSCRIPT_OFFSET+c.PUBLIC_KEY_SIZE:c.TRANSCRIPT_OFFSET+c.PUBLIC_KEY_SIZE+c.PUBLIC_KEY_SIZE],
			state[c.EPHEMERAL_PUBLIC_KEY_OFFSET:c.EPHEMERAL_PUBLIC_KEY_OFFSET+c.PUBLIC_KEY_SIZE],
		)
	}
}

func GetTranscript(state *t.State) *t.Transcript {
	return (*[c.TRANSCRIPT_SIZE]byte)(state[c.TRANSCRIPT_OFFSET:])
}

func ZeroizeSkippedIndexes(state *t.State) {
	skippedIndexesSlice := state[c.SKIPPED_INDEXES_MIN_OFFSET:]
	e.Zeroize(&skippedIndexesSlice)
}

func CalculateStateSize(state *t.State) int {
	stateSlice := state[:]
	if numbers.GetUint32(&stateSlice, int(c.SKIPPED_INDEXES_MAX_OFFSET)) > 0 {
		return int(c.STATE_SIZE)
	}
	offset := c.SKIPPED_INDEXES_MIN_OFFSET
	for {
		if offset >= c.SKIPPED_INDEXES_MAX_OFFSET {
			break
		}
		if numbers.GetUint32(&stateSlice, int(offset)) == 0 {
			return int(offset)
		}
		offset += c.INDEX_SIZE
	}
	return int(c.STATE_SIZE)
}

func SkipIndex(state *t.State) bool {

	offset := CalculateStateSize(state)
	if offset > int(c.SKIPPED_INDEXES_MAX_OFFSET) {
		return false
	}
	copy(state[offset:offset+int(c.INDEX_SIZE)], state[c.RECEIVING_INDEX_OFFSET:c.RECEIVING_INDEX_OFFSET+c.INDEX_SIZE])
	return true
}

func GetSkippedIndex(
	index *t.Index,
	nonce *t.Nonce,
	state *t.State,
	offset int,
) int {
	var o int
	if offset == 0 {
		o = int(c.SKIPPED_INDEXES_MIN_OFFSET)
	} else {
		o = offset
	}
	if o > int(c.SKIPPED_INDEXES_MAX_OFFSET) {
		return 0
	}
	nextOffset := o + int(c.INDEX_SIZE)
	slice := state[o:nextOffset]

	copy((*index)[:], slice)
	copy((*nonce)[c.NONCE_SIZE-c.INDEX_SIZE:], slice)

	return nextOffset
}

func DeleteSkippedIndex(state *t.State, nextOffset int) {
	sessionSize := CalculateStateSize(state)
	offset := nextOffset - int(c.INDEX_SIZE)
	lastOffset := sessionSize - int(c.INDEX_SIZE)
	if offset != lastOffset {
		copy(state[offset:offset+int(sessionSize)], state[lastOffset:lastOffset+sessionSize])
	}
	skippedIndexSlice := state[lastOffset:]
	e.Zeroize(&skippedIndexSlice)
}

func GetState(state *t.State) *[]byte {
	stateSlice := state[:CalculateStateSize(state)]
	return &stateSlice
}

func ZeroizeState(state *[c.STATE_SIZE]byte) {
	stateSlice := state[:]
	e.Zeroize(&stateSlice)
}
