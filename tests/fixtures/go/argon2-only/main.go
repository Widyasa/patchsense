// The project imports argon2 only. openpgp appears in files the scan skips.

package app

import (
	argon2 "golang.org/x/crypto/argon2"
	"fmt"
)

func Hash(password, salt []byte) []byte {
	fmt.Println("hash")
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}
