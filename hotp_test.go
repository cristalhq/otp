package otp

import (
	"testing"
)

func TestHOTP(t *testing.T) {
	// See: https://datatracker.ietf.org/doc/html/rfc4226#appendix-D
	hotpRFCTestCases := []struct {
		counter uint64
		code    string
		algo    Algorithm
		secret  string
	}{
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

	for _, tc := range hotpRFCTestCases {
		hotp, err := NewHOTP(HOTPConfig{
			Algo:   tc.algo,
			Digits: 6,
			Issuer: "cristalhq",
		})
		mustOk(t, err)

		code, err := hotp.GenerateCode(tc.counter, tc.secret)
		mustOk(t, err)
		mustEqual(t, code, tc.code)

		err = hotp.Validate(tc.code, tc.counter, tc.secret)
		mustOk(t, err)
	}
}

func TestNewHOTP(t *testing.T) {
	_, err := NewHOTP(HOTPConfig{
		Algo:   0,
		Digits: 8,
		Issuer: "cristalhq",
	})
	mustEqual(t, err, ErrUnsupportedAlgorithm)

	_, err = NewHOTP(HOTPConfig{
		Algo:   100,
		Digits: 8,
		Issuer: "cristalhq",
	})
	mustEqual(t, err, ErrUnsupportedAlgorithm)

	_, err = NewHOTP(HOTPConfig{
		Algo:   1,
		Digits: 0,
		Issuer: "cristalhq",
	})
	mustEqual(t, err, ErrNoDigits)

	_, err = NewHOTP(HOTPConfig{
		Algo:   1,
		Digits: 8,
		Issuer: "",
	})
	mustEqual(t, err, ErrEmptyIssuer)
}

func TestHOTPGenerateURL(t *testing.T) {
	hotp, err := NewHOTP(HOTPConfig{
		Algo:   AlgorithmSHA1,
		Digits: 8,
		Issuer: "cristalhq",
	})
	mustOk(t, err)

	url := hotp.GenerateURL("alice@bob.com", []byte("SECRET_STRING"))
	mustEqual(t, url, "otpauth://hotp/cristalhq:alice@bob.com?algorithm=SHA1&digits=8&issuer=cristalhq&secret=KNCUGUSFKRPVGVCSJFHEO")

	url = hotp.GenerateURL("bob@alice.com", []byte("SECRET_STRING"))
	mustEqual(t, url, "otpauth://hotp/cristalhq:bob@alice.com?algorithm=SHA1&digits=8&issuer=cristalhq&secret=KNCUGUSFKRPVGVCSJFHEO")
}

func BenchmarkHOTP_GenerateURL(b *testing.B) {
	hotp, err := NewHOTP(HOTPConfig{
		Algo:   AlgorithmSHA1,
		Digits: 8,
		Issuer: "cristalhq",
	})
	mustOk(b, err)

	account := "otp@cristalhq.dev"
	secret := []byte(secretSha1)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		url := hotp.GenerateURL(account, secret)
		mustOk(b, err)

		if url == "" {
			b.Fail()
		}
	}
}

func BenchmarkHOTP_GenerateCode(b *testing.B) {
	hotp, err := NewHOTP(HOTPConfig{
		Algo:   AlgorithmSHA1,
		Digits: 8,
		Issuer: "cristalhq",
	})
	mustOk(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		passcode, err := hotp.GenerateCode(uint64(i), secretSha1)
		mustOk(b, err)

		if passcode == "" {
			b.Fail()
		}
	}
}

func BenchmarkHOTP_Validate(b *testing.B) {
	hotp, err := NewHOTP(HOTPConfig{
		Algo:   AlgorithmSHA1,
		Digits: 8,
		Issuer: "cristalhq",
	})
	mustOk(b, err)

	secret := secretSha1
	passcode, err := hotp.GenerateCode(uint64(1), secretSha1)
	mustOk(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := hotp.Validate(passcode, 1, secret)
		mustOk(b, err)
	}
}
