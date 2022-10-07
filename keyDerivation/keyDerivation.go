package main

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	enc "ransomware/encryption"
	"ransomware/utils"
)

type ExtendedPrivateKey struct {
	ChainCode  [32]byte
	PrivateKey ecdsa.PrivateKey
}

type ExtendedPublicKey struct {
	ChainCode [32]byte
	PublicKey ecdsa.PublicKey
}

func PrivChildDeriv(extPrivParentKey ExtendedPrivateKey, i uint32) ExtendedPrivateKey {

	var I [64]byte
	var Il, Ir [32]byte

	var childKey *big.Int
	var modulus *big.Int

	chainCode, privKey := extPrivParentKey.ChainCode, extPrivParentKey.PrivateKey

	// if it is a hardened key
	// if i >= 2^31 {
	hashData := append([]byte{byte(0)}, privKey.D.Bytes()...)
	hashData = append(hashData, utils.Serialize32Int(i)...)

	I = utils.ComputeHmac512(hashData, chainCode[:])
	// } else {
	// 	hashData := append(
	// 		utils.SerializeCoords(privKey.PublicKey.X, privKey.PublicKey.Y),
	// 		utils.Serialize32Int(i)...,
	// 	)

	// 	I = utils.ComputeHmac512(hashData, chainCode[:])
	// }

	//Ll, Lr := l[:32], l[32:]
	copy(Il[:], I[:32])
	copy(Ir[:], I[32:])

	//ki is parse256(IL) + kpar (mod n).
	modulus.Mod(privKey.D, enc.N)
	childKey.Add(utils.Parse256(Il[:]), modulus)

	extChildPrivKey := ExtendedPrivateKey{ChainCode: Ir, PrivateKey: utils.NewPrivateKey(childKey)}

	return extChildPrivKey
}

func PubChildDeriv(extPrivParentKey ExtendedPrivateKey, i uint32) ExtendedPublicKey {

	extChildPrivKey := PrivChildDeriv(extPrivParentKey, i)

	chainCode, childPubKey := extChildPrivKey.ChainCode, extChildPrivKey.PrivateKey.PublicKey

	extChildPubKey := ExtendedPublicKey{ChainCode: chainCode, PublicKey: childPubKey}

	return extChildPubKey
}

func main() {

	key := []byte("test")
	msg := []byte("aaaaaaaa")

	l := hmac.New(sha512.New, key)

	// sha512.New()

	l.Write(msg)
	out := l.Sum((nil))

	// fmt.Println(hex.DecodeString(string(out)))

	fmt.Println(hex.EncodeToString(out))

}
