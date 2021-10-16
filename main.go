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

	var (
		hashes = make([][]byte, 2)
		r      = make([]*big.Int, 2)
		s      = make([]*big.Int, 2)
	)

	// run wg-lite twice with different `seed` values
	for i := 0; i < 2; i++ {
		runWGLite(i, 1)
		runWGLite(i, 2)

		hashes[i], r[i], s[i] = readMessage(WGLiteArgs[2][3])
	}

	fmt.Println("r:", r)
	fmt.Println("s:", s)
	fmt.Println("hash:", hashes)

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	ecdsakey := generateKey(elliptic.P256())

	hsM, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:  cs,
		VerifyingKey: ecdsakey.Public().(*ecdsa.PublicKey),
	})

	nonce := hsM.RecoverNonce(s, hashes)
	fmt.Println("nonce: ", nonce)

	secret := hsM.RecoverSecret(r[1], s[1], nonce, hashes[1])
	fmt.Println("secret: ", secret)
}
