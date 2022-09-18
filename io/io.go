package io

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func StorePrivateKey(privateKey *rsa.PrivateKey) {

	pemPrivateFile, _ := os.Create("privateKey.pem")

	pemPrivateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	pem.Encode(pemPrivateFile, pemPrivateBlock)
	pemPrivateFile.Close()
}

func ReadPrivateKey(filePath string) *rsa.PrivateKey {
	privateKeyFile, _ := os.Open(filePath)

	pemFileInfo, _ := privateKeyFile.Stat()
	size := pemFileInfo.Size()

	pemBytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	buffer.Read(pemBytes)
	data, _ := pem.Decode([]byte(pemBytes))
	privateKeyFile.Close()

	privateKey, _ := x509.ParsePKCS1PrivateKey(data.Bytes)

	return privateKey
}

func StorePublicKey(publicKey *rsa.PublicKey) {

	pemPublicFile, _ := os.Create("publicKey.pem")

	pemPublicBlock := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(publicKey)}

	pem.Encode(pemPublicFile, pemPublicBlock)
	pemPublicFile.Close()
}

func ReadPublicKey(filePath string) *rsa.PublicKey {
	publicKeyFile, _ := os.Open(filePath)

	pemFileInfo, _ := publicKeyFile.Stat()
	size := pemFileInfo.Size()

	pemBytes := make([]byte, size)
	buffer := bufio.NewReader(publicKeyFile)
	buffer.Read(pemBytes)
	data, _ := pem.Decode([]byte(pemBytes))
	publicKeyFile.Close()

	publicKey, _ := x509.ParsePKCS1PublicKey(data.Bytes)

	return publicKey
}

func DecodePublicKey(pubKeyBytes []byte) *rsa.PublicKey {

	// buffer := bufio.NewReader()
	// buffer.Read(pubKeyBytes)
	data, remainder := pem.Decode([]byte(pubKeyBytes))
	if remainder != nil {
		fmt.Println(string(remainder))
	}

	publicKey, _ := x509.ParsePKCS1PublicKey(data.Bytes)

	return publicKey
}

func GetDrives() []string {
	bufferLength, _ := windows.GetLogicalDriveStrings(0, nil)

	buffer := make([]uint16, bufferLength)
	windows.GetLogicalDriveStrings(bufferLength, &buffer[0])

	s := string(utf16.Decode(buffer))

	return strings.Split(strings.TrimRight(s, "\x00"), "\x00")
}