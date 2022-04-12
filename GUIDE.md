# Guide for otp

## How to generate QR code

```go
hotp, err := NewHOTP(...)
checkErr(err)

url := hotp.GenerateURL("alice@bob.com", "SECRET_STRING")

// url will look like: "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"

// we will use github.com/boombuler/barcode package
// but you can use any other
img, err := qr.Encode(url, qr.M, qr.Auto)
checkErr(err)

// how big image should be
width, height := 512, 512
img, err = barcode.Scale(img, width, height)
checkErr(err)
```
