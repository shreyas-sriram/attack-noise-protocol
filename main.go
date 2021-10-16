package main

import (
	"compromiser/pkg/noise"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
)

var (
	defaultPathToBinary string = "/home/shreyas/go/src/github.com/alichator/wg-lite/wg-lite"
)

func main() {
	if len(os.Args) == 2 {
		defaultPathToBinary = os.Args[1]
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	ecdsakey := generateKey(elliptic.P256())
	rngR := new(RandomInc)
	*rngR = RandomInc(1)
	var privbytes [32]byte
	staticRbad, _ := noise.GenerateBadKeypair(ecdsakey.D.FillBytes(privbytes[:])) // problem

	// var cs1, cs2 *noise.CipherState
	hsR, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       noise.HandshakeIKSign,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticRbad,
		SigningKey:    ecdsakey,
		VerifyingKey:  ecdsakey.Public().(*ecdsa.PublicKey),
	})

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

	nonce := hsR.ExtractNonce(s, hashes)
	fmt.Println("nonce: ", nonce)

	secret := hsR.RecoverSecret(r[1], s[1], nonce, hashes[1])
	fmt.Println("secret: ", secret)
}
