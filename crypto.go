// Package jasypt was created to assist in the decryption of jasypt-encrypted
// values. Many of the algorithms in this package are for legacy use only.
// Please use strong cryptographic algorithms and keys when encrypting your
// sensitive plaintext.
//
// Note that many times base64 encoding has been applied to jasypt output, and
// thus you will likely need to base64 decode any strings before attempting to
// decrypt them.
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

// Common implemented decryption algorithms
const (
	AlgoPBEWithMD5AndDES = "PBEWithMD5AndDES"
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

// DecryptJasypt takes bytes encrypted by the default Jasypt PBEWithMD5AndDES
// implementation, as well as a password, decrypts the byte slice, and returns
// a slice of the decrypted bytes.  Any errors encountered will be returned.
func DecryptJasypt(encrypted []byte, password string) ([]byte, error) {
	if len(encrypted) < des.BlockSize {
		return nil, fmt.Errorf("Invalid encrypted text. Text length than block size.")
	}

	salt := encrypted[:des.BlockSize]
	ct := encrypted[des.BlockSize:]

	key, err := PBKDF1MD5([]byte(password), salt, 1000, des.BlockSize*2)
	if err != nil {
		return nil, err
	}

	iv := key[des.BlockSize:]
	key = key[:des.BlockSize]

	b, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, len(ct))
	bm := cipher.NewCBCDecrypter(b, iv)
	bm.CryptBlocks(dst, ct)

	// Remove any padding
	pad := int(dst[len(dst)-1])
	dst = dst[:len(dst)-pad]

	return dst, nil
}

// A Decryptor encapsulates a password and Algorithm for more easily using
// common decryption across multiple ciphertexts.
type Decryptor struct {
	Password, Algorithm string
}

// Decrypt takes a slice of bytes and decrypts based on the password and
// algorithm specified, returning the slice of decrypted byts and any errors
// encountered.
func (d Decryptor) Decrypt(bs []byte) ([]byte, error) {
	switch d.Algorithm {
	case "", AlgoPBEWithMD5AndDES:
		if d.Password == "" {
			return nil, ErrEmptyPassword
		}
		return DecryptJasypt(bs, d.Password)
	}
	return nil, fmt.Errorf("unknown jasypt algorithm")
}
