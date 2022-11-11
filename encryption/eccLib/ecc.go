package eccLib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
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

// Generates random cipher ecc key pair and then calculates shared secret = pubKey * cipherPrivKey. Returns SHA256
// of the x coordinate of the result and the cipher public key.
func ECDHGenerateEncryptionKey(pubKey *ecdsa.PublicKey) ([]byte, *ecdsa.PublicKey, error) {

	cipherTextPrivKey, err := ecdsa.GenerateKey(Curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ciperTextPubKey := cipherTextPrivKey.PublicKey

	x, _ := Curve.ScalarMult(pubKey.X, pubKey.Y, cipherTextPrivKey.D.Bytes())

	reader := hkdf.New(sha256.New, x.Bytes(), []byte("AES Key"), nil)
	sharedECCKey := make([]byte, 32)

	if _, err := io.ReadFull(reader, sharedECCKey); err != nil {
		return nil, nil, err
	}

	return sharedECCKey[:], &ciperTextPubKey, nil
}

// Calculates shared secret = cipherTextPubKey * privKey and returns SHA256 of the result
func ECDHGenerateDecryptionKey(privKey *ecdsa.PrivateKey, cipherTextPubKey *ecdsa.PublicKey) ([]byte, error) {

	x, _ := Curve.ScalarMult(cipherTextPubKey.X, cipherTextPubKey.Y, privKey.D.Bytes())

	reader := hkdf.New(sha256.New, x.Bytes(), []byte("AES Key"), nil)
	sharedECCKey := make([]byte, 32)

	if _, err := io.ReadFull(reader, sharedECCKey); err != nil {
		return nil, err
	}

	return sharedECCKey[:], nil
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
