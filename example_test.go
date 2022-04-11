package otp_test

import (
	"fmt"

	"github.com/cristalhq/otp"
)

func Example() {
	secretInBase32 := "JBSWY3DPEHPK3PXP"

	algo := otp.AlgorithmSHA1
	digits := otp.Digits(10)
	issuer := "cristalhq"

	hotp, err := otp.NewHOTP(algo, digits, issuer)
	checkErr(err)

	code, err := hotp.GenerateCode(42, secretInBase32)
	checkErr(err)

	fmt.Println(code)

	err = hotp.Validate(code, 42, secretInBase32)
	checkErr(err)

	// Output:
	// 0979090604
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
