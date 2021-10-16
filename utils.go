package main

import (
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var WGLiteArgs = map[int][]string{
	1: {"client", "1", "1", "client-message-1", "server-message-1", "server-message-2"},
	2: {"server", "1", "1", "server-message-1", "client-message-1", "client-message-2"},
	3: {"client", "1", "2", "client-message-2", "server-message-1", "server-message-2"},
	4: {"server", "1", "2", "server-message-2", "client-message-1", "client-message-2"},
	5: {"client", "1", "3", "client-message-3", "server-message-1", "server-message-2"},
}

func runWGLite(seed, step int) {
	args := WGLiteArgs[step]
	args[1] = strconv.FormatInt(int64(seed), 10)

	output, err := exec.Command(defaultPathToBinary, args...).Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(output))
}

func readMessage(filename string) ([]byte, *big.Int, *big.Int) {
	msg, err := os.ReadFile(WGLiteArgs[2][3])
	if err != nil {
		fmt.Println("Error reading file")
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
