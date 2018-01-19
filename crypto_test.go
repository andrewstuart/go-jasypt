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

	pw := "FOO_BAR"

	out, err := DecryptJasypt(bs, pw)
	asrt.NoError(err)
	asrt.Equal("asdfasdfasdasdasuesrfqweafasdnlv,sdklfjasdklfsjadfklsajfksdw", string(out))
}
