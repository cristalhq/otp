package otp_test

import (
	"fmt"
	"time"

	"github.com/cristalhq/otp"
)

func ExampleHOTP() {
	hotp, err := otp.NewHOTP(otp.HOTPConfig{
		Algo:   otp.AlgorithmSHA1,
		Digits: 10,
		Issuer: "cristalhq",
	})
	checkErr(err)

	secretInBase32 := "JBSWY3DPEHPK3PXP"
	code, err := hotp.GenerateCode(42, secretInBase32)
	checkErr(err)

	fmt.Println(code)

	err = hotp.Validate(code, 42, secretInBase32)
	checkErr(err)

	// Output:
	// 0979090604
}

func ExampleTOTP() {
	totp, err := otp.NewTOTP(otp.TOTPConfig{
		Algo:   otp.AlgorithmSHA1,
		Digits: 10,
		Issuer: "cristalhq",
		Period: 30,
		Skew:   2,
	})
	checkErr(err)

	secretInBase32 := "JBSWY3DPEHPK3PXP"
	at := time.Date(2023, 11, 26, 12, 15, 18, 0, time.UTC)

	code, err := totp.GenerateCode(secretInBase32, at)
	checkErr(err)

	fmt.Println(code)

	err = totp.Validate(code, at, secretInBase32)
	checkErr(err)

	// Output:
	// 0462778229
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
