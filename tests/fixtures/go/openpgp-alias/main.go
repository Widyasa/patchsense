package app

import pgp "golang.org/x/crypto/openpgp"

func Use() {
	_ = pgp.PublicKeyType
}
