package otp

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"math"
	"net/url"
)

// HOTP represents HOTP codes generator and validator.
type HOTP struct {
	cfg HOTPConfig
}

type HOTPConfig struct {
	Algo   Algorithm
	Digits Digits
	Issuer string
}

func (cfg HOTPConfig) Validate() error {
	switch {
	case cfg.Algo < 0 || cfg.Algo >= algorithmMax:
		return ErrUnsupportedAlgorithm
	case cfg.Issuer == "":
		return ErrEmptyIssuer
	default:
		return nil
	}
}

// NewHOTP creates new HOTP.
func NewHOTP(cfg HOTPConfig) (*HOTP, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &HOTP{cfg: cfg}, nil
}

// GenerateURL for the account for a given secret.
func (h *HOTP) GenerateURL(account string, secret []byte) string {
	v := url.Values{}
	v.Set("algorithm", h.cfg.Algo.String())
	v.Set("digits", h.cfg.Digits.String())
	v.Set("issuer", h.cfg.Issuer)
	v.Set("secret", b32EncNoPadding(secret))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "hotp",
		Path:     "/" + h.cfg.Issuer + ":" + account,
		RawQuery: v.Encode(),
	}
	return u.String()
}

// GenerateCode for the given counter and secret.
func (h *HOTP) GenerateCode(counter uint64, secret string) (string, error) {
	secretBytes, err := b32Dec(secret)
	if err != nil {
		return "", ErrEncodingNotValid
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(h.cfg.Algo.Hash, secretBytes)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// See: http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	var value int64
	value |= int64(sum[offset]&0x7f) << 24
	value |= int64(sum[offset+1]&0xff) << 16
	value |= int64(sum[offset+2]&0xff) << 8
	value |= int64(sum[offset+3] & 0xff)

	length := int64(math.Pow10(h.cfg.Digits.Length()))
	return h.cfg.Digits.Format(int(value % length)), nil
}

// Validate the given passcode, counter and secret.
func (h *HOTP) Validate(passcode string, counter uint64, secret string) error {
	if len(passcode) != h.cfg.Digits.Length() {
		return ErrCodeLengthMismatch
	}

	code, err := h.GenerateCode(counter, secret)
	if err != nil {
		return err
	}

	ok := subtle.ConstantTimeCompare([]byte(code), []byte(passcode))
	if ok != 1 {
		return ErrCodeIsNotValid
	}
	return nil
}
