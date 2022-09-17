package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Encrypts message with AES using Galois/Counter Mode
// Returns (cipherText appended to nonce , key)
func EncryptAES(msg []byte, key []byte) []byte {

	// Creates cipher block and wraps it into galois counter mode
	cipherBlock, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(cipherBlock)

	//Generates random nonce
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	//Encrypts the message and appends it to the nonce
	output := gcm.Seal(nonce, nonce, msg, nil)

	return output
}

// Decrypts messages encrypted with EncryptAES()
func DecryptAES(msg []byte, key []byte) []byte {

	// Creates cipher block and wraps it into galois counter mode
	cipherBlock, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(cipherBlock)

	// Separates nonce from message
	nonceSize := gcm.NonceSize()
	nonce, msg := msg[:nonceSize], msg[nonceSize:]

	decriptedMessage, err := gcm.Open(nil, nonce, msg, nil)
	if err != nil {
		fmt.Println(err)
	}

	return decriptedMessage
}

func EncryptRSA(msg []byte, publikKey *rsa.PublicKey) []byte {

	encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publikKey, msg, nil)
	if err != nil {
		fmt.Println(err)
	}

	return encryptedMessage
}

func DecryptRSA(msg []byte, privateKey *rsa.PrivateKey) []byte {

	decryptedMessage, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, msg, nil)

	return decryptedMessage
}

func storePrivateKey(privateKey *rsa.PrivateKey) {

	pemPrivateFile, _ := os.Create("privateKey.pem")

	pemPrivateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	pem.Encode(pemPrivateFile, pemPrivateBlock)
	pemPrivateFile.Close()
}

func readPrivateKey(filePath string) *rsa.PrivateKey {
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

func storePublicKey(publicKey *rsa.PublicKey) {

	pemPublicFile, _ := os.Create("publicKey.pem")

	pemPublicBlock := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(publicKey)}

	pem.Encode(pemPublicFile, pemPublicBlock)
	pemPublicFile.Close()
}

func readPublicKey(filePath string) *rsa.PublicKey {
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

// Generates random 16 byte AES key and encrypts message with it, encrypts the AES key
// with RSA and then returns the encrypted AES key concatenated with the encrypted message
func Encrypt(msg []byte, publicKey *rsa.PublicKey) []byte {

	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	encrypted := EncryptAES(msg, aesKey)
	aesKeyEncrypted := EncryptRSA(aesKey, publicKey)

	encrypted = append(aesKeyEncrypted, encrypted...)

	return encrypted
}

// Decrypts messages encrypted with Encrypt()
func Decrypt(msg []byte, privateKey *rsa.PrivateKey) []byte {

	aesKeyEncrypted, encryptedMessage := msg[:256], msg[256:]

	aesKey := DecryptRSA(aesKeyEncrypted, privateKey)

	decrypted := DecryptAES(encryptedMessage, aesKey)

	return decrypted
}

func main() {

	var msg []byte

	// privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// storePrivateKey(privateKey)
	// storePublicKey(&privateKey.PublicKey)

	privateKey := readPrivateKey("privateKey.pem")
	publicKey := readPublicKey("publicKey.pem")

	msg, _ = os.ReadFile("source")

	encrypted := Encrypt(msg, publicKey)

	os.WriteFile("encrypted", encrypted, 0644)

	encryptedFromFile, _ := os.ReadFile("encrypted")

	decripted := Decrypt(encryptedFromFile, privateKey)

	os.WriteFile("decripted", decripted, 0644)

}
