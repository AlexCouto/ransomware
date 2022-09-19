package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Encrypts message with AES using Galois/Counter Mode
// Returns (cipherText appended to nonce , key)
func EncryptAES(msg []byte, key []byte) ([]byte, error) {

	// Creates cipher block and wraps it into galois counter mode
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}

	//Generates random nonce
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	//Encrypts the message and appends it to the nonce
	output := gcm.Seal(nonce, nonce, msg, nil)

	return output, nil
}

// Decrypts messages encrypted with EncryptAES()
func DecryptAES(msg []byte, key []byte) ([]byte, error) {

	// Creates cipher block and wraps it into galois counter mode
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, err
	}

	// Separates nonce from message
	nonceSize := gcm.NonceSize()
	nonce, msg := msg[:nonceSize], msg[nonceSize:]

	decriptedMessage, err := gcm.Open(nil, nonce, msg, nil)
	if err != nil {
		return nil, err
	}

	return decriptedMessage, nil
}

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

// Generates random 16 byte AES key and encrypts message with it, encrypts the AES key
// with RSA and then returns the encrypted AES key concatenated with the encrypted message
func Encrypt(msg []byte, publicKey *rsa.PublicKey) ([]byte, error) {

	aesKey := make([]byte, 16)
	rand.Read(aesKey)

	encrypted, err := EncryptAES(msg, aesKey)
	if err != nil {
		return nil, err
	}
	aesKeyEncrypted, err := EncryptRSA(aesKey, publicKey)
	if err != nil {
		return nil, err
	}

	encrypted = append(aesKeyEncrypted, encrypted...)

	return encrypted, nil
}

// Decrypts messages encrypted with Encrypt()
func Decrypt(msg []byte, privateKey *rsa.PrivateKey) []byte {

	aesKeyEncrypted, encryptedMessage := msg[:256], msg[256:]

	aesKey := DecryptRSA(aesKeyEncrypted, privateKey)

	decrypted, err := DecryptAES(encryptedMessage, aesKey)
	if err != nil {
		return msg
	}

	return decrypted
}
