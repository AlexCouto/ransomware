package rsaLib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func EncryptRSA(msg []byte, publikKey *rsa.PublicKey) ([]byte, error) {

	encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publikKey, msg, nil)
	if err != nil {
		return nil, err
	}

	return encryptedMessage, nil
}

func DecryptRSA(msg []byte, privateKey *rsa.PrivateKey) []byte {

	decryptedMessage, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, msg, nil)

	return decryptedMessage
}
