//go:build linux

package app

import . "golang.org/x/crypto/openpgp/packet"

func Dot() {
	_ = PublicKeyAlgorithmRSA
}
