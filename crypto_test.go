package jasypt

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCrypto(t *testing.T) {
	asrt := assert.New(t)

	bs, err := base64.StdEncoding.DecodeString("jfNpQI9nKsUkBMkIxX0qz5Ft9T5ACtKnUgUeJBCFuxK3ofh24PbuNlnxIOr0P7Jeay81gCY3hIUTLvF5xlgVp9sAktdAjOaL")
	asrt.NoError(err)

	d := Decryptor{
		Algorithm: AlgoPBEWithMD5AndDES,
		Password:  "FOO_BAR",
	}

	out, err := d.Decrypt(bs)
	asrt.NoError(err)
	asrt.Equal("asdfasdfasdasdasuesrfqweafasdnlv,sdklfjasdklfsjadfklsajfksdw", string(out))
}
