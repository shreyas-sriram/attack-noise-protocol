package noise

import (
	"math/big"
)

// RecoverSecret returns the ECDSA secret from a leaked nonce.
//
// Reference - https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
func (h *HandshakeState) RecoverSecret(r, s *big.Int, k string, hash []byte) *big.Int {
	N := h.sign.PublicKey.Curve.Params().N

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
	kInt.Mod(kInt, N)

	return kInt
}

// ExtractNonce returns the re-used nonce from a set of messages.
//
// Reference - https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
func (h *HandshakeState) ExtractNonce(s []*big.Int, hashes [][]byte) string {
	N := h.sign.PublicKey.Curve.Params().N

	// s1 - s2
	s[0].Sub(s[0], s[1])
	s[0].Mod(s[0], N)

	// Finding inverse (s1 - s2)^-1
	sInv := new(big.Int)
	if in, ok := h.sign.PublicKey.Curve.(invertible); ok {
		sInv = in.Inverse(s[0])
	}

	// h(m1) - h(m2)
	h0 := hashToInt(hashes[0], h.sign.PublicKey.Curve)
	h1 := hashToInt(hashes[1], h.sign.PublicKey.Curve)

	h0.Sub(h0, h1)
	h0.Mod(h0, N)

	// ((s1 - s2)^-1) * h(m1) - h(m2)
	k := sInv.Mul(sInv, h0)

	// (((s1 - s2)^-1) * h(m1) - h(m2)) mod N
	k.Mod(k, N)

	return string(k.Bytes())
}
