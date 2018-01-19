# jasypt
--
    import "astuart.co/go-jasypt"

Package jasypt was created to assist in the decryption of jasypt-encrypted
values. Many of the algorithms in this package are for legacy use only. Please
use strong cryptographic algorithms and keys when encrypting your sensitive
plaintext.

Note that many times base64 encoding has been applied to jasypt output, and thus
you will likely need to base64 decode any strings before attempting to decrypt
them.

## Usage

```go
const (
	AlgoPBEWithMD5AndDES = "PBEWithMD5AndDES"
)
```
Common implemented decryption algorithms

```go
const (
	MaxLenMD5 = 20
)
```
Constants for maximum PBKDF1 key lengths

```go
var (
	// ErrEmptyPassword denotes that a password is missing or empty. This is a
	// soft error.
	ErrEmptyPassword = fmt.Errorf("the password used was empty")
	// ErrExceededLength indicates that for a given hash function, the maximum
	// pbkdf1 length has been exceeded.
	ErrExceededLength = fmt.Errorf("derived key too long for md5")
)
```

#### func  DecryptJasypt

```go
func DecryptJasypt(encrypted []byte, password string) ([]byte, error)
```
DecryptJasypt takes bytes encrypted by the default Jasypt PBEWithMD5AndDES
implementation, as well as a password, decrypts the byte slice, and returns a
slice of the decrypted bytes. Any errors encountered will be returned.

#### func  PBKDF1MD5

```go
func PBKDF1MD5(pass, salt []byte, count, l int) ([]byte, error)
```
PBKDF1MD5 takes a password and salt, as well as an iteration count and key
length in bytes, and a hash function, and returns the derived key and an error
in the case that the key was too short.

#### type Decryptor

```go
type Decryptor struct {
	Password, Algorithm string
}
```

A Decryptor encapsulates a password and Algorithm for more easily using common
decryption across multiple ciphertexts.

#### func (Decryptor) Decrypt

```go
func (d Decryptor) Decrypt(bs []byte) ([]byte, error)
```
Decrypt takes a slice of bytes and decrypts based on the password and algorithm
specified, returning the slice of decrypted byts and any errors encountered.
