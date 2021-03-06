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

// attackHandshake recovers the weakly implemented server's `nonce` and `secret`
// from intercepted messages
func attackHandshake() (string, *big.Int) {
	var (
		hash = make([][]byte, 2)
		r    = make([]*big.Int, 2)
		s    = make([]*big.Int, 2)
	)

	// run wg-lite twice with different `seed` values
	for i := 0; i < 2; i++ {
		runWGLite(i, 1)
		runWGLite(i, 2)

		hash[i], r[i], s[i] = readMessage(WGLiteArgs[2][3])
	}

	// fmt.Println("r:", r)
	// fmt.Println("s:", s)
	// fmt.Println("hash:", hash)

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	ecdsakey := generateKey(elliptic.P256())

	hsM, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:  cs,
		VerifyingKey: ecdsakey.Public().(*ecdsa.PublicKey),
	})

	nonce := hsM.RecoverNonce(s, hash)
	secret := hsM.RecoverSecret(r[1], s[1], nonce, hash[1])

	return nonce, secret
}

// spoofClient imitates the supposed client and retrieves the `secret` from the server
func spoofClient() string {
	hsM := createNoiseHandshakeState()

	var cs1, cs2 *noise.CipherState

	// step 1
	// client handshake message
	msg, _, _, _ := hsM.WriteMessage(nil, nil)
	err := os.WriteFile(WGLiteArgs[1][3], msg, 0666)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	// server handshake message
	runWGLite(2, 2)

	// step 2
	// client request `secret` message
	msg, _ = os.ReadFile(WGLiteArgs[3][4])
	var res []byte
	res, cs1, cs2, err = hsM.ReadMessage(nil, msg)
	if err != nil {
		fmt.Println(err)
	}
	res, _ = cs1.Encrypt(nil, nil, []byte("secret"))

	if err = os.WriteFile(WGLiteArgs[3][3], res, 0666); err != nil {
		fmt.Println(err)
	}

	// server responds with `secret` message
	runWGLite(2, 4)

	// step 3
	// client reads `secret` message
	ct, _ := os.ReadFile(WGLiteArgs[5][5])
	msg, _ = cs2.Decrypt(nil, nil, ct)

	return string(msg)
}

func main() {
	if len(os.Args) == 2 {
		defaultPathToBinary = os.Args[1]
	}

	noise.Nonce, secret = attackHandshake()
	// fmt.Println("nonce: ", noise.Nonce)
	// fmt.Println("secret: ", secret)

	msg := spoofClient()
	fmt.Printf(msg)
}
