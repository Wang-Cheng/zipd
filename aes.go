package main

import (
	"crypto/sha1"
	"crypto/subtle"
	"golang.org/x/crypto/pbkdf2"
)

func aesKeyLen(aesStrength byte) int {
	switch aesStrength {
	case 1:
		return 16
	case 2:
		return 24
	case 3:
		return 32
	default:
		return 0
	}
}

func generateKeys(password, salt []byte, keySize int) (encKey, authKey, pwv []byte) {
	totalSize := (keySize * 2) + 2 // enc + auth + pv sizes
	key := pbkdf2.Key(password, salt, 1000, totalSize, sha1.New)
	encKey = key[:keySize]
	authKey = key[keySize : keySize*2]
	pwv = key[keySize*2:]
	return
}

func checkPasswordVerification(pwvv, pwv []byte) bool {
	b := subtle.ConstantTimeCompare(pwvv, pwv) > 0
	return b
}

func checkAesPassword(salt, pwvv []byte, keyLen int, password []byte) bool {
	_, _, pwv := generateKeys(password, salt, keyLen)
	return checkPasswordVerification(pwv, pwvv)
}
