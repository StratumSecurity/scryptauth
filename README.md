# Scrypt Password Authentication

In lieu of Golang's [official scrypt implementation](https://godoc.org/golang.org/x/crypto/scrypt)
coming with functions for authentication functionality, this library does exactly that.

**Table of Contents**

1. [Why do we need a wrapper library?](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#why-doesnt-go-supply-its-own)
2. [Why not use a third-party library?](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#why-not-use-an-existing-wrapper-library)
3. [Library Index](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#index)
4. [How parameters are encoded](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#encoding)

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
4. [Types](https://github.com/StratumSecurity/scrypt_auth_go/blob/master/README.md#types)

### Constants


### Variables


### Functions


### Types


## Encoding

### Parameters

The scrypt algorithm accepts three parameters that are used to configure its complexity, and can be changed
to hash new passwords more strongly as computational resources improve. It also accepts data obtained from a random source and a key length to stretch (if necessary) the output length to).

1. `salt`: A cryptographically-secure random salt (random bytes) is appended to add randomness. At least 4 truly random bytes are suggested.
2. `N`: This is a CPU/memory cost parameter. It must be a power of 2 greater than 1. 16384 is commonly used.
3. `r` and `p`: These parameters configure scrypt's parallelized efficiency. They must satisfy `r * p < 2^30`. r = 8 and p = 1 were commonly used in 2009.
4. `keyLen`: The number of bytes the output key should be stretched to (if at all). This value is often 32, corresponding to an AES key length.

### Output

In order to be able to compare a password to a hashed value, we must be able to hash the input password using
the same parameters that were used to hash the already hashed value.  To do so, we will borrow the idea of
prepending parameters for the hash function to the front of the output, similar to [bcrypt's approach](https://en.wikipedia.org/wiki/Bcrypt).

The format is as follows:

    $4s$salt$N$r$p$b64(h(password))

Here, `$4s$` is a special prefix that will identify this library, and the salt, `N`, `r`, and `p` are prepended
directly to the output in that order. Each value is separated by the `$` character and none of the
values are encoded further (e.g. to hex/base64). Finally, the output of the scrypt KDF, `h(password)`
is appended to the output following the final `$` separator. `h(password)` *will be encoded to base64*.

### Parsing

Below are a list of guidelines for implementing functions to parse the output format above.

* No assumptions should be made about any fields except for the `$4s$` prefix
* Use your language's standard library's string splitting function to split pieces on the `$` character
* Use a standard library function to check that `N` is a power of 2, e.g. using log(base=2, N)
* Check that `r * p > 0` to prevent incorrect behavior resulting from multiplying large `r` and `p`
* Check that `r * p < 1073741824` (`1073741824` = `2^30`)
* Derive the `keyLen` parameter from the length of the decoded `h(password)`, i.e. `keyLen = len(b64_decode(b64(h(password))))`
* Implement a *constant time comparison* between the hash of the input password and the previously hashed value
