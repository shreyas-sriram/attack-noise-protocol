package main

import (
	"compromiser/pkg/noise"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// Arguments for wg-lite
var WGLiteArgs = map[int][]string{
	1: {"client", "1", "1", "client-message-1", "server-message-1", "server-message-2"},
	2: {"server", "1", "1", "server-message-1", "client-message-1", "client-message-2"},
	3: {"client", "1", "2", "client-message-2", "server-message-1", "server-message-2"},
	4: {"server", "1", "2", "server-message-2", "client-message-1", "client-message-2"},
	5: {"client", "1", "3", "client-message-3", "server-message-1", "server-message-2"},
}

var (
	secret *big.Int = new(big.Int)
)

// Re-used from wg-lite
func genBadPriv() (k *big.Int) {
	k = new(big.Int).SetInt64(secret.Int64()) // exact value of k can be changed
	return
}

// generateKey returns a ecdsa keypair
// Re-used from wg-lite
func generateKey(c elliptic.Curve) *ecdsa.PrivateKey {
	k := genBadPriv() // problem
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k // problem
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv
}

// RandomInc is a simple random number generator that uses the power of
// incrementing to produce "secure" random numbers
// Re-used from wg-lite
type RandomInc byte

// Re-used from wg-lite
func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

// runWGLite runs the `wg-lite` binary with arguments based on the
// given step.
func runWGLite(seed, step int) {
	args := WGLiteArgs[step]
	args[1] = strconv.FormatInt(int64(seed), 10)

	_, err := exec.Command(defaultPathToBinary, args...).Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	// fmt.Println(string(output))
}

// readMessage reads the intermediate messages and returns the hash,
// (r, s) from the signature.
func readMessage(filename string) ([]byte, *big.Int, *big.Int) {
	msg, err := os.ReadFile(WGLiteArgs[2][3])
	if err != nil {
		fmt.Println("Error reading file")
		os.Exit(0)
	}

	sigatureLength := msg[len(msg)-1]
	hash := msg[:len(msg)-int(sigatureLength)-1]
	signature := msg[len(msg)-int(sigatureLength)-1 : len(msg)-1]

	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)

	input := cryptobyte.String(signature)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		fmt.Println("Error")
	}

	return hash, r, s
}

func createNoiseHandshakeState() *noise.HandshakeState {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	ecdsakey := generateKey(elliptic.P256())

	rngI := new(RandomInc)
	staticI, _ := cs.GenerateKeypair(rngI)

	var privbytes [32]byte
	staticRbad, _ := noise.GenerateBadKeypair(ecdsakey.D.FillBytes(privbytes[:])) // problem

	hsI, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       noise.HandshakeIKSign,
		Initiator:     true,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticI,
		PeerStatic:    staticRbad.Public,
		VerifyingKey:  ecdsakey.Public().(*ecdsa.PublicKey),
	})

	return hsI
}
