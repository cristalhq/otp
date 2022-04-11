package otp

import (
	"reflect"
	"testing"
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
		failIfErr(t, err)
		mustEqual(t, key.String(), tc.url)
		mustEqual(t, key.Type(), tc.typ)
		mustEqual(t, key.Issuer(), tc.issuer)
		mustEqual(t, key.Account(), tc.account)
		mustEqual(t, key.Secret(), tc.secret)
		mustEqual(t, key.Period(), uint64(tc.period))
	}
}

func failIfErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustEqual(t testing.TB, got, want interface{}) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
