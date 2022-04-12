package otp

import (
	"testing"
)

type tcHOTP struct {
	counter uint64
	code    string
	algo    Algorithm
	secret  string
}

// See: https://datatracker.ietf.org/doc/html/rfc4226#appendix-D
var hotpRFCTestCases = []tcHOTP{
	{0, "755224", AlgorithmSHA1, secretSha1},
	{1, "287082", AlgorithmSHA1, secretSha1},
	{2, "359152", AlgorithmSHA1, secretSha1},
	{3, "969429", AlgorithmSHA1, secretSha1},
	{4, "338314", AlgorithmSHA1, secretSha1},
	{5, "254676", AlgorithmSHA1, secretSha1},
	{6, "287922", AlgorithmSHA1, secretSha1},
	{7, "162583", AlgorithmSHA1, secretSha1},
	{8, "399871", AlgorithmSHA1, secretSha1},
	{9, "520489", AlgorithmSHA1, secretSha1},
}

func TestHOTP(t *testing.T) {
	for _, tc := range hotpRFCTestCases {
		totp, err := NewHOTP(tc.algo, DigitsSix, "cristalhq")
		failIfErr(t, err)

		code, err := totp.GenerateCode(tc.counter, tc.secret)
		failIfErr(t, err)
		mustEqual(t, code, tc.code)

		err = totp.Validate(tc.code, tc.counter, tc.secret)
		failIfErr(t, err)
	}
}

func TestNewHOTP(t *testing.T) {
	var err error
	_, err = NewHOTP(-1, DigitsEight, "cristalhq")
	mustEqual(t, err, ErrUnsupportedAlgorithm)

	_, err = NewHOTP(1, DigitsEight, "")
	mustEqual(t, err, ErrEmptyIssuer)
}

func TestHOTPGenerateURL(t *testing.T) {
	hotp, err := NewHOTP(AlgorithmSHA1, DigitsEight, "cristalhq")
	failIfErr(t, err)

	var url string
	url = hotp.GenerateURL("alice@bob.com", []byte("SECRET_STRING"))
	mustEqual(t, url, "otpauth://hotp/cristalhq:alice@bob.com?algorithm=SHA1&digits=8&issuer=cristalhq&secret=KNCUGUSFKRPVGVCSJFHEO")

	url = hotp.GenerateURL("bob@alice.com", []byte("SECRET_STRING"))
	mustEqual(t, url, "otpauth://hotp/cristalhq:bob@alice.com?algorithm=SHA1&digits=8&issuer=cristalhq&secret=KNCUGUSFKRPVGVCSJFHEO")
}
