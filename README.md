# otp

[![build-img]][build-url]
[![pkg-img]][pkg-url]
[![reportcard-img]][reportcard-url]
[![coverage-img]][coverage-url]
[![version-img]][version-url]

One time password for Go.

## Features

* Simple API.
* Dependency-free.
* Clean and tested code.
* HOTP [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226).
* TOTP [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).

See [GUIDE.md](https://github.com/cristalhq/otp/blob/main/GUIDE.md) for more details.

## Install

Go version 1.17+

```
go get github.com/cristalhq/otp
```

## Example

```go
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
```

Also see examples: [examples_test.go](https://github.com/cristalhq/otp/blob/main/example_test.go).

## Documentation

See [these docs][pkg-url].

## License

[MIT License](LICENSE).

[build-img]: https://github.com/cristalhq/otp/workflows/build/badge.svg
[build-url]: https://github.com/cristalhq/otp/actions
[pkg-img]: https://pkg.go.dev/badge/cristalhq/otp
[pkg-url]: https://pkg.go.dev/github.com/cristalhq/otp
[reportcard-img]: https://goreportcard.com/badge/cristalhq/otp
[reportcard-url]: https://goreportcard.com/report/cristalhq/otp
[coverage-img]: https://codecov.io/gh/cristalhq/otp/branch/main/graph/badge.svg
[coverage-url]: https://codecov.io/gh/cristalhq/otp
[version-img]: https://img.shields.io/github/v/release/cristalhq/otp
[version-url]: https://github.com/cristalhq/otp/releases
