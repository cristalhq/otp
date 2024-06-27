package otp

import (
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
		url       string
		typ       string
		issuer    string
		account   string
		secret    string
		period    int
		digits    uint
		counter   uint64
		algorithm Algorithm
	}{
		{
			url:       "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			typ:       "totp",
			issuer:    "Example",
			account:   "alice@bob.com",
			secret:    "JBSWY3DPEHPK3PXP",
			period:    30,
			digits:    0,
			counter:   0,
			algorithm: AlgorithmUnknown,
		},
		{
			url:       "otpauth://hotp/alice@bob.com?secret=JBSWY3DPEHPK3PXP",
			typ:       "hotp",
			issuer:    "",
			account:   "alice@bob.com",
			secret:    "JBSWY3DPEHPK3PXP",
			period:    30,
			digits:    0,
			counter:   0,
			algorithm: AlgorithmUnknown,
		},
		{
			url:       "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&period=42",
			typ:       "totp",
			issuer:    "Example",
			account:   "alice@bob.com",
			secret:    "JBSWY3DPEHPK3PXP",
			period:    42,
			digits:    0,
			counter:   0,
			algorithm: AlgorithmUnknown,
		},
		{
			url:       "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&period=42&digits=8",
			typ:       "totp",
			issuer:    "Example",
			account:   "alice@bob.com",
			secret:    "JBSWY3DPEHPK3PXP",
			period:    42,
			digits:    8,
			counter:   0,
			algorithm: AlgorithmUnknown,
		},
		{
			url:       "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&period=42&counter=42",
			typ:       "totp",
			issuer:    "Example",
			account:   "alice@bob.com",
			secret:    "JBSWY3DPEHPK3PXP",
			period:    42,
			digits:    0,
			counter:   42,
			algorithm: AlgorithmUnknown,
		},
		{
			url:       "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&period=42&algorithm=SHA1",
			typ:       "totp",
			issuer:    "Example",
			account:   "alice@bob.com",
			secret:    "JBSWY3DPEHPK3PXP",
			period:    42,
			digits:    0,
			counter:   0,
			algorithm: AlgorithmSHA1,
		},
		{
			url:       "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&period=42&algorithm=SHA256",
			typ:       "totp",
			issuer:    "Example",
			account:   "alice@bob.com",
			secret:    "JBSWY3DPEHPK3PXP",
			period:    42,
			digits:    0,
			counter:   0,
			algorithm: AlgorithmSHA256,
		},
		{
			url:       "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&period=42&algorithm=SHA512",
			typ:       "totp",
			issuer:    "Example",
			account:   "alice@bob.com",
			secret:    "JBSWY3DPEHPK3PXP",
			period:    42,
			digits:    0,
			counter:   0,
			algorithm: AlgorithmSHA512,
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
		mustEqual(t, key.Digits(), tc.digits)
		mustEqual(t, key.Counter(), tc.counter)
		mustEqual(t, key.Algorithm(), tc.algorithm)
	}
}

func b32(s string) string {
	return b32Enc([]byte(s))
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
