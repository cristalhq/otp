package otp

import (
	"math"
	"net/url"
	"time"
)

// TOTP represents TOTP codes generator and validator.
type TOTP struct {
	hotp HOTP
	cfg  TOTPConfig
}

type TOTPConfig struct {
	Algo   Algorithm
	Digits uint
	Issuer string
	Period uint64
	Skew   uint
}

func (cfg TOTPConfig) Validate() error {
	switch {
	case cfg.Algo == 0 || cfg.Algo >= algorithmMax:
		return ErrUnsupportedAlgorithm
	case cfg.Digits == 0:
		return ErrNoDigits
	case cfg.Issuer == "":
		return ErrEmptyIssuer
	case cfg.Period == 0:
		return ErrPeriodNotValid
	case cfg.Skew == 0:
		return ErrSkewNotValid
	default:
		return nil
	}
}

// NewTOTP creates new TOTP.
func NewTOTP(cfg TOTPConfig) (*TOTP, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	hotp, err := NewHOTP(HOTPConfig{
		Algo:   cfg.Algo,
		Digits: cfg.Digits,
		Issuer: cfg.Issuer,
	})
	if err != nil {
		return nil, err
	}
	return &TOTP{
		hotp: *hotp,
		cfg:  cfg,
	}, nil
}

// GenerateURL for the account for a given secret.
func (t *TOTP) GenerateURL(account string, secret []byte) string {
	v := url.Values{}
	v.Set("algorithm", t.cfg.Algo.String())
	v.Set("digits", atoi(uint64(t.cfg.Digits)))
	v.Set("issuer", t.cfg.Issuer)
	v.Set("secret", b32Enc(secret))
	v.Set("period", atoi(t.cfg.Period))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + t.cfg.Issuer + ":" + account,
		RawQuery: v.Encode(),
	}
	return u.String()
}

// GenerateCode for the given counter and secret.
func (t *TOTP) GenerateCode(secret string, at time.Time) (string, error) {
	counter := uint64(math.Floor(float64(at.Unix()) / float64(t.cfg.Period)))
	code, err := t.hotp.GenerateCode(counter, secret)
	if err != nil {
		return "", err
	}
	return code, nil
}

// Validate the given passcode, time and secret.
func (t *TOTP) Validate(passcode string, at time.Time, secret string) error {
	if len(passcode) != int(t.cfg.Digits) {
		return ErrCodeLengthMismatch
	}

	counter := int64(math.Floor(float64(at.Unix()) / float64(t.cfg.Period)))

	if err := t.hotp.Validate(passcode, uint64(counter), secret); err == nil {
		return nil
	}

	for i := uint(1); i <= t.cfg.Skew; i++ {
		if err := t.hotp.Validate(passcode, uint64(counter+int64(i)), secret); err == nil {
			return nil
		}

		if err := t.hotp.Validate(passcode, uint64(counter-int64(i)), secret); err == nil {
			return nil
		}
	}

	return ErrCodeIsNotValid
}
