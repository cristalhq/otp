# Guide for otp

## How to generate QR code

```go
hotp, err := otp.NewHOTP(otp.AlgorithmSHA1, otp.DigitsEight, "cristalhq")
checkErr(err)

url := hotp.GenerateURL("alice@bob.com", []byte("SECRET_STRING"))

// url will look like: "otpauth://totp/Example:alice@bob.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"

// we will use github.com/cristalhq/qrcode package
// but you can use any other
img, err := qrcode.Encode(url, qrcode.M)
checkErr(err)

_ = img.Image()     // returns stdlib image.Image
imgPNG := img.PNG() // returns []byte representing PNG

err = os.WriteFile("cristalhq-qr.png", imgPNG, os.ModePerm)
checkErr(err)
```
