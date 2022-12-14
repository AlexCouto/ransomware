package io

import (
	"os"
)

type File struct {
	Info      os.FileInfo
	Path      string
	Extension string
}

func EncryptFile[Key any](
	file *File,
	encrypt func([]byte, Key) ([]byte, error),
	pubKey Key) error {

	osFile, err := os.Open(file.Path)
	if err != nil {
		return err
	}

	buffer := make([]byte, file.Info.Size())
	osFile.Read(buffer)
	osFile.Close()

	encrypted, err := encrypt(buffer, pubKey)
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

func DecryptFile[Key any](
	file *File,
	decrypt func([]byte, Key) ([]byte, error),
	privKey Key) error {

	osFile, err := os.Open(file.Path)
	if err != nil {
		return err
	}

	buffer := make([]byte, file.Info.Size())

	osFile.Read(buffer)

	osFile.Close()

	decrypted, err := decrypt(buffer, privKey)
	if err != nil {
		return err
	}

	osFile, err = os.Create(file.Path)
	if err != nil {
		return err
	}
	_, err = osFile.Write(decrypted)
	if err != nil {
		return err
	}

	osFile.Close()
	os.Rename(file.Path, file.Path[:len(file.Path)-4])

	return nil
}
