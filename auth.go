package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/scrypt"
	"math"
	"strconv"
)

type HashParameter int

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

/**
 * A container for the parameters required to be provided to GenerateFromPassword.
 */
type HashConfiguration struct {
	N       HashParameter
	R       HashParameter
	P       HashParameter
	SaltLen HashParameter
	KeyLen  HashParameter
}

/**
 * Test that the parameters provided to scrypt will satisfy all its requirements.
 */
func verifyParameterValidity(parameters HashConfiguration) error {
	// Check that N is in the allowed range and a power of 2
	exponent := math.Log2(float64(parameters.N))
	isWhole := exponent == math.Trunc(exponent)
	if parameters.N < MinN || parameters.N > MaxN || !isWhole {
		return ErrInvalidNValue
	}
	// Check that r and p are positive integers less than 2^30 and that r * p < 2^30
	if parameters.R < MinR || parameters.R > MaxR {
		return ErrInvalidRValue
	}
	if parameters.P < MinP || parameters.P > MaxP {
		return ErrInvalidPValue
	}
	product := parameters.R * parameters.P
	if product <= 0 || product > MaxP {
		return ErrInvalidRPValues
	}
	// Check that the salt is long enough
	if parameters.SaltLen < MinSaltLen {
		return ErrSaltTooShort
	}
	// Check that the key length is large enough
	if parameters.KeyLen < MinKeyLen {
		return ErrKeyTooShort
	}
	return nil
}

func encodeParameters(hashedValue, salt []byte, parameters HashConfiguration) []byte {
	sep := byte('$')
	// encoded will grow as we call append.
	encoded := make([]byte, 0)
	encoded = append(encoded, []byte("$4s$")...)
	encSalt := []byte(base64.StdEncoding.EncodeToString(salt))
	encoded = append(encoded, encSalt...)
	encN := []byte(strconv.Itoa(int(parameters.N)))
	encR := []byte(strconv.Itoa(int(parameters.R)))
	encP := []byte(strconv.Itoa(int(parameters.P)))
	encoded = append(encoded, sep)
	encoded = append(encoded, encN...)
	encoded = append(encoded, sep)
	encoded = append(encoded, encR...)
	encoded = append(encoded, sep)
	encoded = append(encoded, encP...)
	encHashedValue := []byte(base64.StdEncoding.EncodeToString(hashedValue))
	encoded = append(encoded, sep)
	encoded = append(encoded, encHashedValue...)
	return encoded
}

func decodeParameters(hashedPassword []byte) (HashConfiguration, []byte, error) {
	// Guarantee the expected prefix is present
	if len(hashedPassword) < 4 || !bytes.Equal(hashedPassword[:4], []byte("$4s$")) {
		return HashConfiguration{}, nil, ErrMissingPrefix
	}
	// Guarantee that the salt, N, r, p, and hash are all present.
	parts := bytes.Split(hashedPassword[4:], []byte("$"))
	if len(parts) != 5 {
		return HashConfiguration{}, nil, ErrInvalidHashFormat
	}
	// Extract and decode the salt back into its raw []byte format.
	salt := make([]byte, base64.StdEncoding.DecodedLen(len(parts[0])))
	saltBytesRead, decodeErr := base64.StdEncoding.Decode(salt, parts[0])
	if decodeErr != nil {
		return HashConfiguration{}, nil, ErrInvalidHashFormat
	}
	salt = salt[:saltBytesRead]
	// Parse the numeric values out into actual numeric types.
	nParam, parseErr1 := strconv.Atoi(string(parts[1]))
	rParam, parseErr2 := strconv.Atoi(string(parts[2]))
	pParam, parseErr3 := strconv.Atoi(string(parts[3]))
	if parseErr1 != nil || parseErr2 != nil || parseErr3 != nil {
		return HashConfiguration{}, nil, ErrInvalidHashFormat
	}
	// check that the hashed value at the end is properly base64 encoded.
	decodedHash := make([]byte, base64.StdEncoding.DecodedLen(len(parts[4])))
	hashBytesRead, decodeErr := base64.StdEncoding.Decode(decodedHash, parts[4])
	if decodeErr != nil {
		return HashConfiguration{}, nil, ErrInvalidHashFormat
	}
	// Finally put the parameters parsed into a HashConfiguration and check
	// that they all satisfy the requirements on each parameter.
	params, validityErr := NewHashConfiguration(
		nParam,
		rParam,
		pParam,
		saltBytesRead,
		hashBytesRead)
	if validityErr != nil {
		return HashConfiguration{}, nil, validityErr
	}
	return params, salt, nil
}

/**
 * Produce a HashConfiguration with the most simple, basic recommended values.
 */
func DefaultHashConfiguration() HashConfiguration {
	return HashConfiguration{
		DefaultN,
		DefaultR,
		DefaultP,
		DefaultSaltLen,
		DefaultKeyLen,
	}
}

/**
 * Create a new HashConfiguration and verify that the fields provided meet scrypt's
 * requirements.  It is highly recommended that this function be used rather than creating
 * a configuration by hand.  Accepts `int`s as input for user convenience
 */
func NewHashConfiguration(n, r, p, saltLen, keyLen int) (HashConfiguration, error) {
	parameters := HashConfiguration{
		HashParameter(n),
		HashParameter(r),
		HashParameter(p),
		HashParameter(saltLen),
		HashParameter(keyLen),
	}
	paramErr := verifyParameterValidity(parameters)
	if paramErr != nil {
		return HashConfiguration{}, paramErr
	}
	return parameters, nil
}

/**
 * Creates an encoded sequence of bytes containing all of the parameters passed to
 * scrypt and the hash itself.  Presented with a very similar interface to that of
 * golang.org/x/crypto/bcrypt.
 */
func GenerateFromPassword(password []byte, parameters HashConfiguration) ([]byte, error) {
	// Do an extra check on the input to make sure it meets our standards.
	paramErr := verifyParameterValidity(parameters)
	if paramErr != nil {
		return nil, paramErr
	}
	// Pull some random bytes to use as a salt and make sure we got as much as expected.
	salt := make([]byte, parameters.SaltLen)
	bytesRead, randSrcErr := rand.Read(salt)
	if HashParameter(bytesRead) != parameters.SaltLen {
		return nil, ErrInsufficientRandomData
	}
	if randSrcErr != nil {
		return nil, randSrcErr
	}
	// Invoke the scrypt library and augment the hashed value with the hash parameters.
	hashedValue, hashErr := scrypt.Key(
		password,
		salt,
		int(parameters.N),
		int(parameters.R),
		int(parameters.P),
		int(parameters.KeyLen))
	if hashErr != nil {
		return nil, hashErr
	}
	return encodeParameters(hashedValue, salt, parameters), nil
}

/**
 * Hash the provided password with the already hashed password using the same parameters
 * used to hash the latter.  A constant time comparison between the encoded result of the
 * hash operation and existing hashed value tells us if the passwords match.
 */
func CompareHashAndPassword(hashedPassword, password []byte) error {
	// Extract the parameters and salt encoded in the hashed value.
	parameters, salt, decodeErr := decodeParameters(hashedPassword)
	if decodeErr != nil {
		return decodeErr
	}
	// Hash the input password with the same parameters used for the already hashed value.
	hashedValue, hashErr := scrypt.Key(
		password,
		salt,
		int(parameters.N),
		int(parameters.R),
		int(parameters.P),
		int(parameters.KeyLen))
	if hashErr != nil {
		return hashErr
	}
	// Encode the newly hashed password the same way as the previously encoded one.
	encoded := encodeParameters(hashedValue, salt, parameters)
	// Use a constant time comparison from crypto/subtle to ensure the values match.
	areEqual := subtle.ConstantTimeCompare(hashedPassword, encoded) == 1
	if !areEqual {
		return ErrMismatchedHashAndPassword
	}
	return nil
}
