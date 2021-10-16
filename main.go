package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
)

var (
	defaultPathToBinary string = "/home/shreyas/go/src/github.com/alichator/wg-lite/wg-lite"
)

func GenBadPriv() (k *big.Int) {
	k = new(big.Int).SetInt64(32) // exact value of k can be changed
	return
}

// GenerateKey returns a ecdsa keypair
func GenerateKey(c elliptic.Curve) *ecdsa.PrivateKey {
	k := GenBadPriv() // problem
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k // problem
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv
}

// RandomInc is a simple random number generator that uses the power of
// incrementing to produce "secure" random numbers
type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

func main() {
	if len(os.Args) == 2 {
		defaultPathToBinary = os.Args[1]
	}

	// cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	// ecdsakey := GenerateKey(elliptic.P256())
	// rngR := new(RandomInc)
	// *rngR = RandomInc(1)
	// var privbytes [32]byte
	// staticRbad, _ := noise.GenerateBadKeypair(ecdsakey.D.FillBytes(privbytes[:])) // problem

	// // var cs1, cs2 *noise.CipherState
	// hsR, _ := noise.NewHandshakeState(noise.Config{
	// 	CipherSuite:   cs,
	// 	Random:        rngR,
	// 	Pattern:       noise.HandshakeIKSign,
	// 	Prologue:      []byte("ABC"),
	// 	StaticKeypair: staticRbad,
	// 	SigningKey:    ecdsakey,
	// 	VerifyingKey:  ecdsakey.Public().(*ecdsa.PublicKey),
	// })

	// hsR.ReadMessage(nil, msg)
	// fmt.Printf("%+v", hsR)

	var (
		hashes = make([][]byte, 2)
		r      = make([]*big.Int, 2)
		s      = make([]*big.Int, 2)
	)

	for i := 0; i < 2; i++ {
		runWGLite(i, 1)
		runWGLite(i, 2)

		_hash, _r, _s := readMessage(WGLiteArgs[2][3])
		hashes[i] = _hash
		r[i] = _r
		s[i] = _s
	}

	fmt.Println("r:", r)
	fmt.Println("s:", s)
	fmt.Println("hash:", hashes)

	// secret := hsR.RecoverSecret(r, s, k, hash)
	// fmt.Println(secret)
}
