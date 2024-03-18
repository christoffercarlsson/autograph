package kdf

import (
	c "github.com/christoffercarlsson/autograph/go/constants"
	e "github.com/christoffercarlsson/autograph/go/external"
	t "github.com/christoffercarlsson/autograph/go/types"
)

func Kdf(okm *t.Okm, ikm *t.Ikm) bool {
	salt := []byte{}
	okmSlice := okm[:]
	ikmSlice := ikm[:]
	return e.Hkdf(&okmSlice, &ikmSlice, &salt, &c.INFO)
}
