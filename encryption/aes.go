package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Encrypts message with AES using Galois/Counter Mode
// Returns cipherText appended to nonce
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
