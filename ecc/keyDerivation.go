package ecc

import (
	"errors"
	"math/big"
	"ransomware/utils"
)

func PrivChildDeriv(extPrivParentKey ExtendedPrivateKey, i uint16) (*ExtendedPrivateKey, error) {

	var I [64]byte
	var childKey big.Int

	chainCode, privKey := extPrivParentKey.ChainCode, extPrivParentKey.PrivateKey

	hashData := append([]byte{byte(0)}, privKey.D.Bytes()...)
	hashData = append(hashData, utils.Serialize16Int(i)...)

	I = utils.ComputeHmac512(hashData, chainCode[:])
	Il, Ir := I[:32], I[32:]

	if CurveOrder.Cmp(utils.Parse256(Il)) < 1 {

		return nil, errors.New("Invalid child Key : parse256(IL) ≥ n")
	}

	//ki is parse256(IL) + kpar (mod n).
	childKey.Add(privKey.D, utils.Parse256(Il))
	childKey.Mod(&childKey, CurveOrder)

	extChildPrivKey := &ExtendedPrivateKey{ChainCode: Ir, PrivateKey: *NewPrivateKey(&childKey), Index: i}

	return extChildPrivKey, nil
}

func PubChildDeriv(extPrivParentKey ExtendedPrivateKey, i uint16) (*ExtendedPublicKey, error) {

	extChildPrivKey, err := PrivChildDeriv(extPrivParentKey, i)
	if err != nil {
		return nil, err
	}

	chainCode, childPubKey := extChildPrivKey.ChainCode, extChildPrivKey.PrivateKey.PublicKey

	extChildPubKey := &ExtendedPublicKey{ChainCode: chainCode, PublicKey: childPubKey, Index: i}

	return extChildPubKey, nil
}
