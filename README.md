# Scrypt Password Authentication

In lieu of Golang's [official scrypt implementation](https://godoc.org/golang.org/x/crypto/scrypt)
coming with functions for authentication functionality, this library does exactly that.

**Table of Contents**

1. [Why do we need a wrapper library?](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#why-doesnt-go-supply-its-own)
2. [Why not use a third-party library?](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#why-not-use-an-existing-wrapper-library)
3. [Library index](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#index)
4. [Example usage](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#example-usage)
5. [How parameters are encoded](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#encoding)
6. [Implementation Requirements](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#implementation-requirements)

## Why doesn't Go supply its own?

Scrypt is a [Key Derivation Function (KDF)](https://en.wikipedia.org/wiki/Key_derivation_function)
which means it is designed to create keys that are safe to use in encryption algorithms.  KDFs,
including scrypt, feature two essential properties.

1. They include an element of randomness to prevent keys from being derived by brute-force password guesses
2. They perform a cryptographic hashing operation to prevent key material from being determined from keys themselves

Modern KDFs, again including scrypt, are designed to be configurable to allow for more computational resources,
such as processing time and memory usage, to be consumed when computing a key so that the algorithm's security
scales as computers become more powerful.

Password hashing functions are typically only expected to meet the second of the two requirements above,
which means they are not suitable as KDFs but that KDFs are suitable password hashing algorithms. However,
because scrypt is not designed specifically as a password hash function, supporting that usage requires
making decisions about how parameters to the KDF are encoded (documented below) that could make usage confusing.

## Why not use an existing wrapper library?

There are some existing scrypt wrapper libraries that provide similar or even equivalent functionality
to that which this library provides.  However, due to the critical nature of securing user passwords,
StratumSecurity has opted to create its own library for internal use so that stronger requirements may be
placed on its implementation and so that guarantees can be made internally about its development.

For example, this library will fully document the decisions made regarding how parameters are encoded into
and decoded from hashed values. 

## Index

1. [Constants](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#constants)
2. [Variables](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#variables)
3. [Functions](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#functions)
  * [DefaultHashConfiguration](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#defaulthashconfiguration)
  * [NewHashConfiguration](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#newhashconfiguration)
  * [GenerateFromPassword](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#generatefrompassword)
  * [CompareHashAndPassword](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#comparehashandpassword)
4. [Types](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#types)

### Constants

```go
const (
	MinN           HashParameter = 4          // 2^2,  the minimum allowable N value
	MaxN           HashParameter = 2147483648 // 2^31, the maximum N value we can contain in an int
	MinR           HashParameter = 1          // 2^0,  the minimum r value possible, corresponding to 1 <= p <= MaxP
	MaxR           HashParameter = 1073741823 // 2^30 - 1, the maximum r value possible, requiring p = 1
	MinP           HashParameter = 1          // 2^0,  the minimum p value possible, corresponding to 1 <= r <= MaxR
	MaxP           HashParameter = 1073741823 // 2^30 - 1, the maximum p value possible, requiring r = 1
	MinKeyLen      HashParameter = 32         // the minimum number of bytes a key should contain, corresponds to 256 bits
	MinSaltLen     HashParameter = 8          // the minimum length of a salt, 8 bytes
	DefaultSaltLen HashParameter = 8          // the default length of a salt, 8 bytes
	DefaultKeyLen  HashParameter = 32         // the default number of bytes a key will contain
	DefaultN       HashParameter = 32768      // 2^15, a default N value. 2^14 was the recommended value in 2009
	DefaultR       HashParameter = 8          // the default r value recommended in 2009 (pertains to parallelization)
	DefaultP       HashParameter = 1          // the default p value recommended in 2009 (pertains to parallelization)
)
```

### Variables

```go
var (
	ErrInvalidNValue             = errors.New("scrypt/auth: N parameter must be between 2^2 and 2^31 inclusive, and be a power of 2")
	ErrInvalidRValue             = errors.New("scrypt/auth: r parameter must be between 2^0 and 2^30 inclusive")
	ErrInvalidPValue             = errors.New("scrypt/auth: p parameter must be between 2^0 and 2^30 inclusive")
	ErrInvalidRPValues           = errors.New("scrypt/auth: The r and p parameters must be such that r * p < 2^30")
	ErrKeyTooShort               = errors.New("scrypt/auth: The minimum allowed key length is 32 bytes, or 256 bits")
	ErrSaltTooShort              = errors.New("scrypt/auth: The minimum allowed salt length is 8 bytes or 64 bits")
	ErrInvalidHashFormat         = errors.New("scrypt/auth: The expected hashed value format is $4s$salt$N$r$p$hashedPassword")
	ErrMismatchedHashAndPassword = errors.New("scrypt/auth: The supplied password does not match the hashed secret")
	ErrMissingPrefix             = errors.New("scrypt/auth: Hashed password is not prefixed with the expected $4s$ sequence")
	ErrInsufficientRandomData    = errors.New("scrypt/auth: Not enough random data is available to securely hash passwords")
)
```

### Functions

#### DefaultHashConfiguration

[View source](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/auth.go#L157)

```go
func DefaultHashConfiguration() HashConfiguration
```

Produces a set of parameters that are safe to use to configure scrypt with.

#### NewHashConfiguration

[View source](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/auth.go#L172)

```go
func NewHashConfiguration(n, r, p, saltLen, keyLen int) (HashConfiguration, error)
```

Produces a new set of parameters with the values provided. It will check that the
parameter values provided satisfy scrypt (and this library)'s requirements, and
return an error if they do not.

#### GenerateFromPassword

[View source](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/auth.go#L186)

```go
func GenerateFromPassword(password []byte, parameters HashConfiguration) ([]byte, error)
```

Creates a slice of bytes containing the encoded scrypt parameters including a
cryptographically secure random salt of the specified length. An error may be
returned if the parameters are invalid, the function is unable to read enough
random bytes, or scrypt encouners an error.

#### CompareHashAndPassword

[View source](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/auth.go#L220)

```go
func CompareHashAndPassword(hashedPassword, password []byte) error
```

Hashes the input password with the same salt and parameters used to encode the already
hashed password and carries out a constant-time comparison to check if the results
are equal. The function returns `nil` if no error occurs and the password matched.
Errors will be returned if the hashed password is not encoded as expected, scrypt
encounters a problem, or the password does not match the hashed password.

### Types

```go
type HashParameter int
```

```go
type HashConfiguration struct {
	N       HashParameter
	R       HashParameter
	P       HashParameter
	SaltLen HashParameter
	KeyLen  HashParameter
}
```

## Example usage

Below is a complete demonstration of how to use this library.
In the comments, you'll find notes about how you may wish to handle different
errors in the context of a web application.

You can run this program by saving it as `example.go` and then running

    go get github.com/StratumSecurity/scryptauth
    go run example.go

```go
package main

import (
	"fmt"
	auth "github.com/StratumSecurity/scryptauth"
)

func main() {
	// Get the user's password from some source of input,
	// probably the body of an HTTP request.
	password := "Pr3tt!3_D3c3nT"

	// Set some relatively high parameters for scrypt.
	N := 1 << 16 // 2^16
	r := 10
	p := 2
	saltLen := 12
	keyLen := 64

	parameters, err := auth.NewHashConfiguration(N, r, p, saltLen, keyLen)
	if err != nil {
		// An error may be returned if we didn't satisfy some requirement
		// for the scrypt parameters
		panic(err)
	}

	hashed, err := auth.GenerateFromPassword([]byte(password), parameters)
	if err != nil {
		// An error may be returned if scrypt encounters an error or
		// if there are not enough random bytes available to fill the salt.
		// We could either try to wait for more random bytes or ask the user
		// to try again in a moment if we need more random bytes.
		panic(err)
	}

	// Later, we get a request to log in and another password becomes input.
	inputPassword := "Pr3tt!3_D3c3nT"
	compareErr := auth.CompareHashAndPassword(hashed, []byte(inputPassword))
	if compareErr == auth.ErrMismatchedHashAndPassword {
		// The passwords didn't match. Don't authenticate the user.
		panic(compareErr)
	} else if compareErr != nil {
		// Decoding parameters failed. We should rehash the password
		// with a proper, secure configuration.
		panic(compareErr)
	} else {
		// Nothing went wrong. The passwords match.
		fmt.Println("Passwords matched!")
	}
}
```

## Encoding

### Parameters

The scrypt algorithm accepts three parameters that are used to configure its complexity, and can be changed
to hash new passwords more strongly as computational resources improve. It also accepts data obtained from a random source and a key length to stretch (if necessary) the output length to).

1. `salt`: A cryptographically-secure random salt (random bytes) is appended to add randomness. At least 8 truly random bytes are suggested.
2. `N`: This is a CPU/memory cost parameter. It must be a power of 2 greater than 1. 16384 is commonly used.
3. `r` and `p`: These parameters configure scrypt's parallelized efficiency. They must satisfy `r * p < 2^30`. r = 8 and p = 1 were commonly used in 2009.
4. `keyLen`: The number of bytes the output key should be stretched to (if at all). This value is often 32, corresponding to an AES key length.

### Output

In order to be able to compare a password to a hashed value, we must be able to hash the input password using
the same parameters that were used to hash the already hashed value.  To do so, we will borrow the idea of
prepending parameters for the hash function to the front of the output, similar to [bcrypt's approach](https://en.wikipedia.org/wiki/Bcrypt).

The format is as follows:

    $4s$salt$N$r$p$h(password)

Here, `$4s$` is a special prefix that will identify this library, and the salt, `N`, `r`, and `p` are prepended
directly to the output in that order as decimals. Each value is separated by the `$` character and none of N, r, or p
are encoded (e.g. to hex/base64). The salt is encoded to base64. Finally, the output of the scrypt KDF, `h(password)`
is appended to the output following the final `$` separator. `h(password)` *will be encoded to base64*.

### Parsing

Below are a list of guidelines for implementing functions to parse the output format above.

* No assumptions should be made about any fields except for the `$4s$` prefix
* Use your language's standard library's string splitting function to split pieces on the `$` character
* Use a standard library function to check that `N` is a power of 2. More on this in the `Parameter Restrictions` section
* Check that `r * p > 0` to prevent incorrect behavior resulting from multiplying large `r` and `p`
* Check that `r * p < 1073741824` (`1073741824` = `2^30`)
* Derive the `keyLen` parameter from the length of the decoded `h(password)`, i.e. `keyLen = len(b64_decode(b64(h(password))))`
* Implement a *constant time comparison* between the hash of the input password and the previously hashed value

## Implementation Requirements 

### Scrypt parameter values

* `N` *must* satisfy `N >= 4` and must be a power of 2
* `r` *must* satisfy `r > 0` and `r * p < 1073741824` (where 1073741823 = 2^30)
* `p` *must* satisfy `p > 0` and `r * p < 1073741824` (where 1073741823 = 2^30)
* Salts *must* be at least 8 bytes long
* Key lengths *must* be at least 32 bytes long

### General rules

* Padding bytes (`=`) at the end of base64-encoded values should *not* be removed
* `N`, `r`, and `p` *must* be encoded as decimals. Do not use another base.
* A constant-time comparison should be used to check if a hashed input password equals a previously hashed password

### Testing N

When testing the `N` parameter for scrypt, your implementation must guarantee that
`N` satisfies `N >= 4` and that `N` is a power of two (2). There are two recommended ways to do this.

The first way is to cast `N` to an unsigned integer 
(if you are using a signed integer, as Go's scrypt interface requires)
and use the following expression

    N > 1 && ((N & (N-1)) > 0)

Which will be true _if and only if_ N is a power of 2.

The second approach is to use a math library's logarithm function, such as
[Go's math.Log2](https://golang.org/pkg/math/#Log2) to compute the exponent that
satisfies `2^x = N`.  You then have to check that the computed value `x` is a positive integer.
Beware of cases where confusion arises due to the handling of floating point numbers
(i.e. where something like 3.00000001 != 3.0).

You should carefully consider your language's handling of types, library efficiency,
and handling of floating-point values before making your decision.

### Implementing constant-time comparisons

[Constant time comparisons](http://rdist.root.org/2010/01/07/timing-independent-array-comparison/)
are used to prevent timing attacks that can be used to determine parts of passwords
that could ultimately lead to completely reversing a hash.

The example below is an implementation of a constant-time comparison function in Python.

```py
def constant_time_compare(expected, input):
  if len(input) != len(expected):
    return False

  # XOR the two strings and accumulate any differing bits with OR
  mismatched = 0
  for x, y in zip(input, expected):
    mismatched |= ord(x) ^ ord(y)
  return mismatched == 0
```

Your language may include an implementation of such a function for strings/byte arrays,
like the
[ConstantTimeCompare function in crypto/subtle](https://golang.org/pkg/crypto/subtle/#ConstantTimeCompare)
used by the implementation included in this library.
