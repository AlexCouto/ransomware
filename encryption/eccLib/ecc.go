package eccLib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

var (
	Curve      = elliptic.P256()
	CurveOrder = Curve.Params().N
)

type ExtendedPrivateKey struct {
	ChainCode  []byte
	PrivateKey ecdsa.PrivateKey
	Index      uint16
}

type ExtendedPublicKey struct {
	ChainCode []byte
	PublicKey ecdsa.PublicKey
	Index     uint16
}

func ECDHGenerateEncryptionKey(pubKey *ecdsa.PublicKey) ([]byte, *ecdsa.PublicKey, error) {
	cipherTextPrivKey, err := ecdsa.GenerateKey(Curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ciperTextPubKey := cipherTextPrivKey.PublicKey

	x, _ := Curve.ScalarMult(pubKey.X, pubKey.Y, cipherTextPrivKey.D.Bytes())

	hash := sha256.New()
	hash.Write(x.Bytes())
	sharedECCKey := hash.Sum(nil)

	return sharedECCKey[:], &ciperTextPubKey, nil
}

func ECDHGenerateDecryptionKey(privKey *ecdsa.PrivateKey, cipherTextPubKey *ecdsa.PublicKey) []byte {

	x, _ := Curve.ScalarMult(cipherTextPubKey.X, cipherTextPubKey.Y, privKey.D.Bytes())

	hash := sha256.New()
	hash.Write(x.Bytes())
	sharedECCKey := hash.Sum(nil)

	return sharedECCKey[:]
}

func Point(p []byte) (*big.Int, *big.Int) {
	x, y := Curve.ScalarBaseMult(p)
	return x, y
}

func SerializeCoords(x *big.Int, y *big.Int) []byte {
	return elliptic.MarshalCompressed(Curve, x, y)
}

func NewPrivateKey(D *big.Int) *ecdsa.PrivateKey {

	pubKey := *NewPublicKey(Point(D.Bytes()))
	privKey := &ecdsa.PrivateKey{PublicKey: pubKey, D: D}
	return privKey

}

func NewPublicKey(X *big.Int, Y *big.Int) *ecdsa.PublicKey {
	pubKey := &ecdsa.PublicKey{Curve: Curve, X: X, Y: Y}
	return pubKey
}
