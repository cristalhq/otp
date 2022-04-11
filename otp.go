package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrEmptyIssuer          = errors.New("empty issuer")
	ErrPeriodNotValid       = errors.New("period is not valid")
	ErrCodeLengthMismatch   = errors.New("code length mismatch")
	ErrCodeIsNotValid       = errors.New("code is not valid")
	ErrEncodingNotValid     = errors.New("encoding is not valid")
)

// Algorithm represents the hashing function to use for OTP.
type Algorithm int

const (
	AlgorithmUnknown Algorithm = 0
	AlgorithmSHA1    Algorithm = 1
	AlgorithmSHA256  Algorithm = 2
	AlgorithmSHA512  Algorithm = 3
	algorithmMax     Algorithm = 4
)

func (a Algorithm) String() string {
	switch a {
	case AlgorithmUnknown:
		return ""
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	default:
		panic(fmt.Sprintf("otp: unsupported algorithm: %d", int(a)))
	}
}

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmUnknown:
		return nil
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	default:
		panic(fmt.Sprintf("otp: unsupported algorithm: %d", int(a)))
	}
}

// Digits is the number of digits in the OTP passcode.
type Digits uint

// Six and Eight are the most common values.
const (
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

func (d Digits) String() string { return fmt.Sprintf("%d", d) }

// Length of the passcode.
func (d Digits) Length() int { return int(d) }

// Format the number to a digit format (zero-filled upto digits size).
func (d Digits) Format(n int) string {
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", d), n)
}

// Key represents an HTOP or TOTP key.
type Key struct {
	url    *url.URL
	values url.Values
}

// ParseKeyFromURL creates a new Key from the HOTP or TOTP URL.
// See: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func ParseKeyFromURL(s string) (*Key, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	key := &Key{
		url:    u,
		values: u.Query(),
	}
	return key, nil
}

func (k *Key) String() string { return k.url.String() }

// Type returns "hotp" or "totp".
func (k *Key) Type() string { return k.url.Host }

// Secret returns the opaque secret for this Key.
func (k *Key) Secret() string { return k.values.Get("secret") }

// Issuer returns the name of the issuing organization.
func (k *Key) Issuer() string {
	issuer := k.values.Get("issuer")
	if issuer != "" {
		return issuer
	}

	p := strings.TrimPrefix(k.url.Path, "/")
	if i := strings.Index(p, ":"); i != -1 {
		return p[:i]
	}
	return ""
}

// Account returns the name of the user's account.
func (k *Key) Account() string {
	p := strings.TrimPrefix(k.url.Path, "/")
	if i := strings.Index(p, ":"); i != -1 {
		return p[i+1:]
	}
	return p
}

// Period returns a tiny int representing the rotation time in seconds.
func (k *Key) Period() uint64 {
	period := k.values.Get("period")

	u, err := strconv.ParseUint(period, 10, 64)
	if err == nil {
		return u
	}
	return 30 // If no period is defined 30 seconds is the default per (RFC 6238)
}

func b32NoPadding(src []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(src)
}
