package otp

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"math"
	"net/url"
	"strings"
)

// HOTP represents HOTP codes generator and validator.
type HOTP struct {
	algo   Algorithm
	digits Digits
	issuer string
}

// NewHOTP creates new HOTP.
func NewHOTP(algo Algorithm, digits Digits, issuer string) (*HOTP, error) {
	if algo < 0 || algo >= algorithmMax {
		return nil, ErrUnsupportedAlgorithm
	}
	if issuer == "" {
		return nil, ErrEmptyIssuer
	}
	return &HOTP{
		algo:   algo,
		digits: digits,
		issuer: issuer,
	}, nil
}

// GenerateURL for the account for a given secret.
func (h *HOTP) GenerateURL(account string, secret []byte) string {
	v := url.Values{}
	v.Set("algorithm", h.algo.String())
	v.Set("digits", h.digits.String())
	v.Set("issuer", h.issuer)
	v.Set("secret", b32NoPadding(secret))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "hotp",
		Path:     "/" + h.issuer + ":" + account,
		RawQuery: v.Encode(),
	}
	return u.String()
}

// GenerateCode for the given counter and secret.
func (h *HOTP) GenerateCode(counter uint64, secret string) (string, error) {
	// add padding if missing
	if n := len(secret) % 8; n != 0 {
		secret += strings.Repeat("=", 8-n)
	}

	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", ErrEncodingNotValid
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(h.algo.Hash, secretBytes)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// See: http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	var value int64
	value |= int64(sum[offset]&0x7f) << 24
	value |= int64(sum[offset+1]&0xff) << 16
	value |= int64(sum[offset+2]&0xff) << 8
	value |= int64(sum[offset+3] & 0xff)

	length := int64(math.Pow10(h.digits.Length()))
	return h.digits.Format(int(value % length)), nil
}

// Validate the given passcode, counter and secret.
func (h *HOTP) Validate(passcode string, counter uint64, secret string) error {
	if len(passcode) != h.digits.Length() {
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
