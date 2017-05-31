# jasypt
--
    import "astuart.co/go-jasypt"


## Usage

```go
const (
	AlgoPBEWithMD5AndDES = "PBEWitMD5AndDES"
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
func DecryptJasypt(encrypted []byte, password string) error
```
DecryptJasypt takes bytes encrypted by the default Jasypt PBEWithMD5AndDES
implementation, as well as a password, and decrypts the byte slice in place. Any
errors encountered will be returned.

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
func (d Decryptor) Decrypt(bs []byte) (err error)
```
Decrypt takes a slice of bytes and decrypts based on the password and algorithm
specified.
