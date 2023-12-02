package otp

import (
	"testing"
	"time"
)

func TestTOTP(t *testing.T) {
	// See: https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
	totpRFCTestCases := []struct {
		ts     int64
		code   string
		algo   Algorithm
		secret string
	}{
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

	for _, tc := range totpRFCTestCases {
		totp, err := NewTOTP(TOTPConfig{
			Algo:   tc.algo,
			Digits: 8,
			Issuer: "cristalhq",
			Period: 30,
			Skew:   1,
		})
		mustOk(t, err)

		at := time.Unix(tc.ts, 0).UTC()
		code, err := totp.GenerateCode(tc.secret, at)
		mustOk(t, err)
		mustEqual(t, code, tc.code)

		err = totp.Validate(tc.code, at, tc.secret)
		mustOk(t, err)
	}
}

func TestNewTOTP(t *testing.T) {
	_, err := NewTOTP(TOTPConfig{
		Algo:   0,
		Digits: 8,
		Issuer: "cristalhq",
		Period: 30,
		Skew:   1,
	})
	mustEqual(t, err, ErrUnsupportedAlgorithm)

	_, err = NewTOTP(TOTPConfig{
		Algo:   100,
		Digits: 8,
		Issuer: "cristalhq",
		Period: 30,
		Skew:   1,
	})
	mustEqual(t, err, ErrUnsupportedAlgorithm)

	_, err = NewTOTP(TOTPConfig{
		Algo:   1,
		Digits: 0,
		Issuer: "cristalhq",
		Period: 30,
		Skew:   1,
	})
	mustEqual(t, err, ErrNoDigits)

	_, err = NewTOTP(TOTPConfig{
		Algo:   1,
		Digits: 8,
		Issuer: "",
		Period: 30,
		Skew:   1,
	})
	mustEqual(t, err, ErrEmptyIssuer)

	_, err = NewTOTP(TOTPConfig{
		Algo:   1,
		Digits: 8,
		Issuer: "cristalhq",
		Period: 0,
		Skew:   1,
	})
	mustEqual(t, err, ErrPeriodNotValid)

	_, err = NewTOTP(TOTPConfig{
		Algo:   1,
		Digits: 8,
		Issuer: "cristalhq",
		Period: 30,
		Skew:   0,
	})
	mustEqual(t, err, ErrSkewNotValid)
}

func TestTOTPGenerateURL(t *testing.T) {
	totp, err := NewTOTP(TOTPConfig{
		Algo:   AlgorithmSHA1,
		Digits: 8,
		Issuer: "cristalhq",
		Period: 30,
		Skew:   1,
	})
	mustOk(t, err)

	url := totp.GenerateURL("alice@bob.com", []byte("SECRET_STRING"))
	mustEqual(t, url, "otpauth://totp/cristalhq:alice@bob.com?algorithm=SHA1&digits=8&issuer=cristalhq&period=30&secret=KNCUGUSFKRPVGVCSJFHEO")

	url = totp.GenerateURL("bob@alice.com", []byte("SECRET_STRING"))
	mustEqual(t, url, "otpauth://totp/cristalhq:bob@alice.com?algorithm=SHA1&digits=8&issuer=cristalhq&period=30&secret=KNCUGUSFKRPVGVCSJFHEO")
}

func BenchmarkTOTP_GenerateURL(b *testing.B) {
	totp, err := NewTOTP(TOTPConfig{
		Algo:   AlgorithmSHA1,
		Digits: 8,
		Issuer: "cristalhq",
		Period: 30,
		Skew:   1,
	})
	mustOk(b, err)

	account := "otp@cristalhq.dev"
	secret := []byte(secretSha1)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		url := totp.GenerateURL(account, secret)
		mustOk(b, err)

		if url == "" {
			b.Fail()
		}
	}
}

func BenchmarkTOTP_GenerateCode(b *testing.B) {
	totp, err := NewTOTP(TOTPConfig{
		Algo:   AlgorithmSHA1,
		Digits: 8,
		Issuer: "cristalhq",
		Period: 30,
		Skew:   1,
	})
	mustOk(b, err)

	secret := secretSha1
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		passcode, err := totp.GenerateCode(secret, time.Now())
		mustOk(b, err)

		if passcode == "" {
			b.Fail()
		}
	}
}

func BenchmarkTOTP_Validate(b *testing.B) {
	totp, err := NewTOTP(TOTPConfig{
		Algo:   AlgorithmSHA1,
		Digits: 8,
		Issuer: "cristalhq",
		Period: 30,
		Skew:   1,
	})
	mustOk(b, err)

	secret := secretSha1
	at := time.Now()
	passcode, err := totp.GenerateCode(secret, at)
	mustOk(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := totp.Validate(passcode, at, secret)
		mustOk(b, err)
	}
}
