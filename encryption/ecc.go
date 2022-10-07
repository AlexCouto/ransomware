package enc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
)

var (
	Curve = elliptic.P256()
	N     = Curve.Params().N
)

func ECDHGenerateEncryptionKey(pubKey *ecdsa.PublicKey) ([]byte, *ecdsa.PublicKey, error) {
	cipherTextPrivKey, err := ecdsa.GenerateKey(Curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ciperTextPubKey := cipherTextPrivKey.PublicKey

	x, _ := Curve.ScalarMult(pubKey.X, pubKey.Y, cipherTextPrivKey.D.Bytes())

	sharedECCKey := sha256.Sum256(x.Bytes())

	return sharedECCKey[:], &ciperTextPubKey, nil
}

func ECDHGenerateDecryptionKey(privKey *ecdsa.PrivateKey, cipherTextPubKey *ecdsa.PublicKey) []byte {

	x, _ := Curve.ScalarMult(cipherTextPubKey.X, cipherTextPubKey.Y, privKey.D.Bytes())

	sharedECCKey := sha256.Sum256(x.Bytes())

	return sharedECCKey[:]
}
