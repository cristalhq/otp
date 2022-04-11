package otp

import (
	"math"
	"net/url"
	"strconv"
	"time"
)

// TOTP represents TOTP codes generator and validator.
type TOTP struct {
	*HOTP
	issuer string
	period int
	skew   int
}

// NewTOTP creates new TOTP.
func NewTOTP(algo Algorithm, digits Digits, issuer string, period, skew int) (*TOTP, error) {
	if algo < 0 || algo >= algorithmMax {
		return nil, ErrUnsupportedAlgorithm
	}
	if issuer == "" {
		return nil, ErrEmptyIssuer
	}
	if period < 1 {
		return nil, ErrPeriodNotValid
	}
	if skew < 1 {
		return nil, ErrPeriodNotValid
	}
	hotp, err := NewHOTP(algo, digits, issuer)
	if err != nil {
		return nil, err
	}
	return &TOTP{
		HOTP:   hotp,
		period: period,
		skew:   skew,
	}, nil
}

// GenerateURL for the account for a given secret.
func (t *TOTP) GenerateURL(account string, secret []byte) string {
	v := url.Values{}
	v.Set("algorithm", t.algo.String())
	v.Set("digits", t.digits.String())
	v.Set("issuer", t.issuer)
	v.Set("secret", b32NoPadding(secret))
	v.Set("period", strconv.FormatUint(uint64(t.period), 10))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + t.issuer + ":" + account,
		RawQuery: v.Encode(),
	}
	return u.String()
}

// GenerateCode for the given counter and secret.
func (t *TOTP) GenerateCode(secret string, at time.Time) (string, error) {
	counter := uint64(math.Floor(float64(at.Unix()) / float64(t.period)))
	code, err := t.HOTP.GenerateCode(counter, secret)
	if err != nil {
		return "", err
	}
	return code, nil
}

// Validate the given passcode, time and secret.
func (t *TOTP) Validate(passcode string, at time.Time, secret string) error {
	if len(passcode) != t.digits.Length() {
		return ErrCodeLengthMismatch
	}

	counters := make([]uint64, 0, 2*t.skew+1)
	counter := int64(math.Floor(float64(at.Unix()) / float64(t.period)))
	counters = append(counters, uint64(counter))

	for i := 1; i <= t.skew; i++ {
		counters = append(counters, uint64(counter+int64(i)), uint64(counter-int64(i)))
	}

	for _, counter := range counters {
		err := t.HOTP.Validate(passcode, counter, secret)
		if err == nil {
			return nil
		}
	}
	return ErrCodeIsNotValid
}
