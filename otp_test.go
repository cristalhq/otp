package otp

import (
	"encoding/base32"
	"reflect"
	"testing"
)

var (
	secretSha1   = b32("12345678901234567890")
	secretSha256 = b32("12345678901234567890123456789012")
	secretSha512 = b32("1234567890123456789012345678901234567890123456789012345678901234")
)

func TestKey(t *testing.T) {
	testCases := []struct {
		url     string
		typ     string
		issuer  string
		account string
		secret  string
		period  int
	}{
		{
			url:     "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			typ:     "totp",
			issuer:  "Example",
			account: "alice@bob.com",
			secret:  "JBSWY3DPEHPK3PXP",
			period:  30,
		},
		{
			url:     "otpauth://hotp/alice@bob.com?secret=JBSWY3DPEHPK3PXP",
			typ:     "hotp",
			issuer:  "",
			account: "alice@bob.com",
			secret:  "JBSWY3DPEHPK3PXP",
			period:  30,
		},
		{
			url:     "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&period=42",
			typ:     "totp",
			issuer:  "Example",
			account: "alice@bob.com",
			secret:  "JBSWY3DPEHPK3PXP",
			period:  42,
		},
	}

	for _, tc := range testCases {
		key, err := ParseKeyFromURL(tc.url)
		mustOk(t, err)
		mustEqual(t, key.String(), tc.url)
		mustEqual(t, key.Type(), tc.typ)
		mustEqual(t, key.Issuer(), tc.issuer)
		mustEqual(t, key.Account(), tc.account)
		mustEqual(t, key.Secret(), tc.secret)
		mustEqual(t, key.Period(), uint64(tc.period))
	}
}

func b32(s string) string {
	return base32.StdEncoding.EncodeToString([]byte(s))
}

func mustOk(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}

func mustEqual(tb testing.TB, have, want interface{}) {
	tb.Helper()
	if !reflect.DeepEqual(have, want) {
		tb.Fatalf("\nhave: %+v\nwant: %+v\n", have, want)
	}
}
