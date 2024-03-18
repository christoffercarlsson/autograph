package keyexchange

import (
	"github.com/christoffercarlsson/autograph/go/cert"
	c "github.com/christoffercarlsson/autograph/go/constants"
	e "github.com/christoffercarlsson/autograph/go/external"
	"github.com/christoffercarlsson/autograph/go/kdf"
	s "github.com/christoffercarlsson/autograph/go/state"
	t "github.com/christoffercarlsson/autograph/go/types"
)

func DeriveSecretKeys(state *t.State, isInitiator bool) bool {
	var sharedSecret t.SharedSecret = [c.SHARED_SECRET_SIZE]byte{}
	var okm t.Okm = [c.OKM_SIZE]byte{}
	dhSuccess := e.DiffieHellman(
		&sharedSecret,
		s.GetEphemeralPrivateKey(state),
		s.GetTheirEphemeralKey(state),
	)
	kdfSuccess := kdf.Kdf(&okm, &sharedSecret)
	s.SetSecretKeys(state, isInitiator, &okm)

	e.Zeroize64(&okm)
	e.Zeroize32(&sharedSecret)
	return dhSuccess && kdfSuccess
}

func KeyExchange(ourSignature *t.Signature, state *t.State, isInitiator bool) bool {
	s.SetTranscript(state, isInitiator)
	keySuccess := DeriveSecretKeys(state, isInitiator)
	s.DeleteEphemeralPrivateKey(state)
	transcript := s.GetTranscript(state)[:]
	certifySuccess := cert.CertifyDataOwnership(
		ourSignature,
		state,
		s.GetTheirIdentityKey(state),
		&transcript,
	)
	if !certifySuccess || !keySuccess {
		s.ZeroizeState(state)
		return false
	}
	return true
}

func VerifyKeyExchange(state *t.State, theirSignature t.Signature) bool {
	transcript := s.GetTranscript(state)[:]
	if !cert.VerifyDataOwnership(
		s.GetIdentityPublicKey(state),
		&transcript,
		s.GetTheirIdentityKey(state),
		&theirSignature,
	) {
		s.ZeroizeState(state)
		return false
	}
	s.ZeroizeSkippedIndexes(state)
	return true
}
