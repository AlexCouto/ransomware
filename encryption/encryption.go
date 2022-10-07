package enc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// Generates random 16 byte AES key and encrypts message with it, encrypts the AES key
// with RSA and then returns the encrypted AES key concatenated with the encrypted message
func RSAAESEncrypt(msg []byte, publicKey *rsa.PublicKey) ([]byte, error) {

	aesKey := make([]byte, 32)
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
func RSAAESDecrypt(msg []byte, privateKey *rsa.PrivateKey) []byte {

	aesKeyEncrypted, encryptedMessage := msg[:256], msg[256:]

	aesKey := DecryptRSA(aesKeyEncrypted, privateKey)

	decrypted, err := DecryptAES(encryptedMessage, aesKey)
	if err != nil {
		return msg
	}

	return decrypted
}

func ECDHAESEncrypt(msg []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {

	aesKey, cipherPublicKey, err := ECDHGenerateEncryptionKey(publicKey)
	if err != nil {
		return nil, err
	}

	cipherPublicMarshal := elliptic.MarshalCompressed(Curve, cipherPublicKey.X, cipherPublicKey.Y)

	encrypted, err := EncryptAES(msg, aesKey)
	if err != nil {
		return nil, err
	}

	encrypted = append(cipherPublicMarshal, encrypted...)

	return encrypted, nil
}

func ECDHAESDecrypt(msg []byte, privateKey *ecdsa.PrivateKey) []byte {

	cipherPublicMarshal, encryptedMessage := msg[:33], msg[33:]

	x, y := elliptic.UnmarshalCompressed(Curve, cipherPublicMarshal)

	cipherPublicKey := &ecdsa.PublicKey{Curve: Curve, X: x, Y: y}

	aesKey := ECDHGenerateDecryptionKey(privateKey, cipherPublicKey)

	decrypted, err := DecryptAES(encryptedMessage, aesKey)
	if err != nil {
		return msg
	}

	return decrypted
}
