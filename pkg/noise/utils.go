package noise

import (
	"math/big"
)

// RecoverSecret returns the ECDSA secret from a leaked nonce.
//
// Reference - https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
func (h *HandshakeState) RecoverSecret(r, s *big.Int, k string, hash []byte) *big.Int {

	// Convert string to *big.Int
	kInt := new(big.Int)
	kInt.SetBytes([]byte(k))

	// k*s
	kInt.Mul(kInt, s)

	// k*s - H(m)
	kInt.Sub(kInt, hashToInt(hash, h.sign.PublicKey.Curve))

	// Finding inverse of r (r^-1)
	var rInv *big.Int
	if in, ok := h.sign.PublicKey.Curve.(invertible); ok {
		rInv = in.Inverse(r)
	}

	// (r^-1)*(k*s - H(m))
	kInt.Mul(kInt, rInv)

	// ((r^-1)*(k*s - H(m))) mod N
	N := h.sign.PublicKey.Curve.Params().N
	kInt.Mod(kInt, N)

	return kInt
}
