package jasypt

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"fmt"
)

var (
	// ErrEmptyPassword denotes that a password is missing or empty. This is a
	// soft error.
	ErrEmptyPassword = fmt.Errorf("the password used was empty")
	// ErrExceededLength indicates that for a given hash function, the maximum
	// pbkdf1 length has been exceeded.
	ErrExceededLength = fmt.Errorf("derived key too long for md5")
)

// Constants for maximum PBKDF1 key lengths
const (
	MaxLenMD5 = 20
)

// PBKDF1MD5 takes a password and salt, as well as an iteration count and key
// length in bytes, and a hash function, and returns the derived key and an
// error in the case that the key was too short.
func PBKDF1MD5(pass, salt []byte, count, l int) ([]byte, error) {
	if l > MaxLenMD5 {
		return nil, ErrExceededLength
	}

	derived := make([]byte, len(pass)+len(salt))
	copy(derived, pass)
	copy(derived[len(pass):], salt)

	for i := 0; i < count; i++ {
		dr := md5.Sum(derived)
		derived = dr[:]
	}

	return derived[:l], nil
}

// DecryptJasypt takes bytes encrypted by the default jasypt PBE md5 DES
// implementation, as well as a password, and decrypts the byte slice in place.
// Any errors encountered will be returned.
func DecryptJasypt(encrypted []byte, password string) error {
	if len(encrypted) < des.BlockSize {
		return fmt.Errorf("Invalid encrypted text")
	}

	salt := encrypted[:des.BlockSize]
	encrypted = encrypted[des.BlockSize:]

	key, err := PBKDF1MD5([]byte(password), salt, 1000, des.BlockSize*2)
	if err != nil {
		return err
	}

	iv := key[des.BlockSize:]
	key = key[:des.BlockSize]

	b, err := des.NewCipher(key)
	if err != nil {
		return err
	}

	bm := cipher.NewCBCDecrypter(b, iv)
	bm.CryptBlocks(encrypted, encrypted)

	// Remove any padding
	last := len(encrypted) - 1
	pad := int(encrypted[last])

	encrypted = encrypted[:len(encrypted)-pad]

	return nil
}

type Decryptor struct {
	Password, Algorithm string
}

func (d *Decryptor) Decrypt(bs []byte) error {
	err := DecryptJasypt(bs, d.Password)

	// If the password is empty, notify the end user
	if err != nil && d.Password == "" {
		err = ErrEmptyPassword
	}

	return err
}
