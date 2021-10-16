package main

import (
	"compromiser/pkg/noise"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"os/exec"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// type WGLiteArgs struct {
// 	pathToBinary            string
// 	seed                    int
// 	step                    int
// 	outgoingMessageFile     string
// 	incomingMessageFile     string
// 	tempIncomingMessageFile string
// }

var WGLiteArgs = map[int][]string{
	1: {"client", "1", "1", "client-message-1", "server-message-1", "server-message-2"},
	2: {"server", "1", "1", "server-message-1", "client-message-1", "client-message-2"},
	3: {"client", "1", "2", "client-message-2", "server-message-1", "server-message-2"},
	4: {"server", "1", "2", "server-message-2", "client-message-1", "client-message-2"},
	5: {"client", "1", "3", "client-message-3", "server-message-1", "server-message-2"},
}

var (
	defaultPathToBinary string = "/home/shreyas/go/src/github.com/alichator/wg-lite/wg-lite"
)

func runWGLite(step int) {
	output, err := exec.Command(defaultPathToBinary, WGLiteArgs[step]...).Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(output))
}

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

	runWGLite(1)
	runWGLite(2)

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	ecdsakey := GenerateKey(elliptic.P256())
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

	msg, _ := os.ReadFile(WGLiteArgs[2][3])
	fmt.Println(msg)

	hsR.ReadMessage(nil, msg)
	// fmt.Printf("%+v", hsR)

	sigatureLength := msg[len(msg)-1]
	hash := msg[:len(msg)-int(sigatureLength)-1]
	signature := msg[len(msg)-int(sigatureLength)-1 : len(msg)-1]

	fmt.Println(hash)
	fmt.Println(signature)
	fmt.Println(sigatureLength)

	var (
		r, s  = &big.Int{}, &big.Int{}
		k     = "secure nonce"
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

	fmt.Println("r:", r)
	fmt.Println("s:", s)
	fmt.Println("k:", k)
	fmt.Println("hash:", hash)

	secret := hsR.RecoverSecret(r, s, k, hash)
	fmt.Println(secret)
}
