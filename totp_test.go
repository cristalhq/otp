package otp

import (
	"encoding/base32"
	"testing"
	"time"
)

type tcTOTP struct {
	ts     int64
	code   string
	algo   Algorithm
	secret string
}

var (
	secretSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secretSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secretSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))
)

// See: https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
var totpRFCTestCases = []tcTOTP{
	{59, "94287082", AlgorithmSHA1, secretSha1},
	{59, "46119246", AlgorithmSHA256, secretSha256},
	{59, "90693936", AlgorithmSHA512, secretSha512},
	{1111111109, "07081804", AlgorithmSHA1, secretSha1},
	{1111111109, "68084774", AlgorithmSHA256, secretSha256},
	{1111111109, "25091201", AlgorithmSHA512, secretSha512},
	{1111111111, "14050471", AlgorithmSHA1, secretSha1},
	{1111111111, "67062674", AlgorithmSHA256, secretSha256},
	{1111111111, "99943326", AlgorithmSHA512, secretSha512},
	{1234567890, "89005924", AlgorithmSHA1, secretSha1},
	{1234567890, "91819424", AlgorithmSHA256, secretSha256},
	{1234567890, "93441116", AlgorithmSHA512, secretSha512},
	{2000000000, "69279037", AlgorithmSHA1, secretSha1},
	{2000000000, "90698825", AlgorithmSHA256, secretSha256},
	{2000000000, "38618901", AlgorithmSHA512, secretSha512},
	{20000000000, "65353130", AlgorithmSHA1, secretSha1},
	{20000000000, "77737706", AlgorithmSHA256, secretSha256},
	{20000000000, "47863826", AlgorithmSHA512, secretSha512},
}

func TestTOTP(t *testing.T) {
	for _, tc := range totpRFCTestCases {
		totp, err := NewTOTP(tc.algo, DigitsEight, "cristalhq", 30, 1)
		failIfErr(t, err)

		at := time.Unix(tc.ts, 0).UTC()
		code, err := totp.GenerateCode(tc.secret, at)
		failIfErr(t, err)
		mustEqual(t, code, tc.code)

		err = totp.Validate(tc.code, at, tc.secret)
		failIfErr(t, err)
	}
}

func TestNewTOTP(t *testing.T) {
	var err error
	_, err = NewTOTP(-1, DigitsEight, "cristalhq", 30, 1)
	mustEqual(t, err, ErrUnsupportedAlgorithm)

	_, err = NewTOTP(1, DigitsEight, "", 30, 1)
	mustEqual(t, err, ErrEmptyIssuer)

	_, err = NewTOTP(1, DigitsEight, "cristalhq", -30, 1)
	mustEqual(t, err, ErrPeriodNotValid)

	_, err = NewTOTP(1, DigitsEight, "cristalhq", 30, -1)
	mustEqual(t, err, ErrSkewNotValid)
}

func TestTOTPGenerateURL(t *testing.T) {
	totp, err := NewTOTP(AlgorithmSHA1, DigitsEight, "cristalhq", 30, 1)
	failIfErr(t, err)

	var url string
	url = totp.GenerateURL("alice@bob.com", []byte("SECRET_STRING"))
	mustEqual(t, url, "otpauth://totp/cristalhq:alice@bob.com?algorithm=SHA1&digits=8&issuer=cristalhq&period=30&secret=KNCUGUSFKRPVGVCSJFHEO")

	url = totp.GenerateURL("bob@alice.com", []byte("SECRET_STRING"))
	mustEqual(t, url, "otpauth://totp/cristalhq:bob@alice.com?algorithm=SHA1&digits=8&issuer=cristalhq&period=30&secret=KNCUGUSFKRPVGVCSJFHEO")
}

func BenchmarkTOTP_GenerateURL(b *testing.B) {
	totp, err := NewTOTP(AlgorithmSHA1, DigitsEight, "cristalhq", 30, 1)
	failIfErr(b, err)

	account := "otp@cristalhq.dev"
	secret := []byte(secretSha1)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		url := totp.GenerateURL(account, secret)
		failIfErr(b, err)

		if url == "" {
			b.Fail()
		}
	}
}

func BenchmarkTOTP_GenerateCode(b *testing.B) {
	totp, err := NewTOTP(AlgorithmSHA1, DigitsEight, "cristalhq", 30, 1)
	failIfErr(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		passcode, err := totp.GenerateCode(secretSha1, time.Now())
		failIfErr(b, err)

		if passcode == "" {
			b.Fail()
		}
	}
}

func BenchmarkTOTP_Validate(b *testing.B) {
	totp, err := NewTOTP(AlgorithmSHA1, DigitsEight, "cristalhq", 30, 1)
	failIfErr(b, err)

	secret := secretSha1
	at := time.Now()
	passcode, err := totp.GenerateCode(secret, at)
	failIfErr(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := totp.Validate(passcode, at, secret)
		failIfErr(b, err)
	}
}
