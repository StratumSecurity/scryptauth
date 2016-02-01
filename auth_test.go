package auth

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"testing"
)

/**
 * Unit tests
 */

func TestNewHashConfiguration(t *testing.T) {
	t.Log("function NewHashConfiguration")

	t.Log("\tIt should not produce any errors for valid sets of parameters")
	// Use the container type directly instead of redeclaring a struct here.
	passingTests := []HashConfiguration{
		// N, r, p, saltLen, keyLen
		{16384, 8, 1, 4, 32},       // Recommended values in 2009
		{32, 100, 10, 32, 64},      // Arbitrary
		{8, 1073741823, 1, 5, 128}, // r = MaxR
		{16, 1, 1073741823, 4, 32}, // p = MaxP
		{128, 32768, 32767, 4, 32}, // r * p = 2^30 - 1
	}
	for i, test := range passingTests {
		_, err := NewHashConfiguration(
			test.N, test.R, test.P, test.SaltLen, test.KeyLen)
		if err != nil {
			t.Errorf("\t\tError in test #%d: %v", i, err)
		}
	}

	t.Log("\tIt should produce errors for parameters that don't satisfy the requirements")
	failingTests := []HashConfiguration{
		// N, r, p, saltLen, keyLen
		{33, 8, 1, 4, 32},         // N not quite a power of 2
		{32, -10, 1, 4, 32},       // r < 0
		{32, 8, -10, 4, 32},       // p < 0
		{32, 32768, 32768, 4, 32}, // r * p == 2^30
		{32, 8, 1, 2, 32},         // saltLen < MinSaltLen
		{32, 8, 1, 4, 16},         // keyLen < MinKeyLen
	}
	for i, test := range failingTests {
		_, err := NewHashConfiguration(
			test.N, test.R, test.P, test.SaltLen, test.KeyLen)
		if err == nil {
			t.Errorf("\t\tExpected error in test #%d\n", i)
		}
	}
}

func TestEncodeParameters(t *testing.T) {
	t.Log("function encodeParameters")

	t.Log("\tIt should prefix output with $4s$")
	testParams := DefaultHashConfiguration()
	testSalt := []byte{255, 254, 253, 252}
	testHash := make([]byte, 32)
	for i := 0; i < 32; i++ {
		testHash[i] = byte(i)
	}
	encoded := encodeParameters(testHash, testSalt, testParams)
	if !bytes.HasPrefix(encoded, []byte("$4s$")) {
		t.Error("\t\tExpected encoded value to be prefixed with bytes $4s$")
	}

	t.Log("\tIt should contain a total of five $-separated parts after the prefix")
	encoded = encoded[4:]
	parts := bytes.Split(encoded, []byte("$"))
	if len(parts) != 5 { // salt, N, r, p, hash
		t.Error("\t\tExpected encoded value to consist of five parts")
	}

	t.Log("\tIt should have base64-encoded the salt")
	if bytes.Equal(testSalt, parts[0]) {
		t.Error("\t\tThe encoded salt is the same as the test data; it should be encoded")
	}
	salt := make([]byte, 4)
	base64.StdEncoding.Decode(salt, parts[0])
	if !bytes.Equal(testSalt, salt) {
		t.Error("\t\tThe decoded salt does not equal the original")
	}

	t.Log("\tIt should have encoded N, r, and p directly as strings")
	_, parseErr := strconv.Atoi(string(parts[1]))
	if parseErr != nil {
		t.Error("\t\tN was not encoded as a string")
	}
	_, parseErr = strconv.Atoi(string(parts[2]))
	if parseErr != nil {
		t.Error("\t\tr was not encoded as a string")
	}
	_, parseErr = strconv.Atoi(string(parts[3]))
	if parseErr != nil {
		t.Error("\t\tp was not encoded as a string")
	}

	t.Log("\tIt should have base64-encoded the hashed value")
	if bytes.Equal(testHash, parts[4]) {
		t.Error("\t\tThe encoded hash is the same as the test data; it should be encoded")
	}
	hash := make([]byte, 32)
	base64.StdEncoding.Decode(hash, parts[4])
	if !bytes.Equal(testHash, hash) {
		t.Error("\t\tThe decoded hash does not equal the original")
	}
}

func TestDecodeParameters(t *testing.T) {
	t.Log("function decodeParameters")

	t.Log("\tIt should return ErrMissingPrefix if the input does not start with $4s$")
	_, _, err := decodeParameters([]byte("salt$16384$8$1$ABCDEFABCDEFABCDEFABCDEFABCDEF01"))
	if err != ErrMissingPrefix {
		t.Error("\t\tExpected to get ErrMissingPrefix, got %v", err)
	}

	t.Log("\tIt should return ErrInvalidHashFormat if any parts are missing")
	_, _, err = decodeParameters([]byte("$4s$16384$8$1$ABCDEFABCDEFABCDEFABCDEFABCDEF01")) // No salt
	if err != ErrInvalidHashFormat {
		t.Error("\t\tExpected to get ErrInvalidHashFormat, got %v", err)
	}

	// Not going to test that it handled base64-decoding salts or converting
	// N, r, and p to integers since those are just calls to the stdlib.

	t.Log("\tIt should return appropriate errors if encoded parameters are invalid")
	tests := []struct {
		Encoded     string
		ExpectedErr error
	}{
		{"$4s$ab$16384$8$1$ABCDEFABCDEFABCDEFABCDEFABCDEF01", ErrSaltTooShort},
		{"$4s$abcd$123$8$1$ABCDEFABCDEFABCDEFABCDEFABCDEF01", ErrInvalidNValue},
		{"$4s$abcd$16384$1073741824$1$ABCDEFABCDEFABCDEFABCDEFABCDEF01", ErrInvalidRValue},
		{"$4s$abcd$16384$1$1073741824$ABCDEFABCDEFABCDEFABCDEFABCDEF01", ErrInvalidPValue},
		{"$4s$abcd$16384$32768$32768$ABCDEFABCDEFABCDEFABCDEFABCDEF01", ErrInvalidRPValues},
		{"$4s$abcd$16384$8$1$tooshort", ErrKeyTooShort},
	}
	for i, test := range tests {
		_, _, decodeErr := decodeParameters([]byte(test.Encoded))
		if decodeErr != test.ExpectedErr {
			t.Errorf("\t\tExpected test #%d to produce %v, got %v", i, test.ExpectedErr, decodeErr)
		}
	}

	t.Log("\tIt should produce a valid HashConfiguration and salt if decoding succeeds")
	params, salt, err := decodeParameters([]byte("$4s$abcdef01$16384$8$1$ABCDEFABCDEFABCDEFABCDEFABCDEF01"))
	if err != nil {
		t.Error(err)
	} else {
		expectedSalt, _ := base64.StdEncoding.DecodeString("abcdef01")
		if !bytes.Equal(salt, expectedSalt) {
			t.Error("\t\tSalt was decoded incorrectly")
		}
		if params.N != 16384 {
			t.Error("\t\tN value was decoded incorrectly. Expected 16384, got %d", params.N)
		}
		if params.R != 8 {
			t.Error("\t\tr value was decoded incorrectly. Expected 8, got %d", params.R)
		}
		if params.P != 1 {
			t.Error("\t\tp value was decoded incorrectly. Expected 1, got %d", params.P)
		}
	}
}

func TestGenerateFromPassword(t *testing.T) {
	t.Log("function GenerateFromPassword")

	t.Log("\tIt should return an error if a parameter is invalid")
	failingTests := []HashConfiguration{
		// N, r, p, saltLen, keyLen
		{33, 8, 1, 4, 32},         // N not quite a power of 2
		{32, -10, 1, 4, 32},       // r < 0
		{32, 8, -10, 4, 32},       // p < 0
		{32, 32768, 32768, 4, 32}, // r * p == 2^30
		{32, 8, 1, 2, 32},         // saltLen < MinSaltLen
		{32, 8, 1, 4, 16},         // keyLen < MinKeyLen
	}
	for i, test := range failingTests {
		_, err := GenerateFromPassword([]byte("t3st!nG12345"), test)
		if err == nil {
			t.Errorf("\t\tExpected error for failing test %d\n", i)
		}
	}

	t.Log("\tIt should not produce any errors if the provided parameters are valid")
	passingTests := []HashConfiguration{
		// N, r, p, saltLen, keyLen
		{16384, 8, 1, 4, 32},       // Recommended values in 2009
		{32, 100, 10, 32, 64},      // Arbitrary
		{8, 1073741823, 1, 5, 128}, // r = MaxR
		{16, 1, 1073741823, 4, 32}, // p = MaxP
		{128, 32768, 32767, 4, 32}, // r * p = 2^30 - 1
	}
	for i, test := range passingTests {
		_, err := GenerateFromPassword([]byte("t3st!nG12345"), test)
		if err != nil {
			t.Errorf("\t\tExpected no error for passing test %d. Got %v\n", i, err)
		}
	}
}

func TestCompareHashAndPassword(t *testing.T) {
	t.Log("function CompareHashAndPassword")

	t.Log("\tIt should return an error if the hashed password is not encoded properly")
	decodeFailTests := []string{
		"4s$SALTSALT$16384$8$1$ABCDEF0123456789ABCDEF0123456789",           // Incorrect prefix
		"SALTSALT$16384$8$1$ABCDEF0123456789ABCDEF0123456789",              // Missing prefix
		"$4s$16384$8$1$ABCDEF0123456789ABCDEF0123456789",                   // Missing salt
		"$4s$SAL$16384$8$1$ABCDEF0123456789ABCDEF0123456789",               // Salt too short
		"$4s$SALTSALT$abcdef$8$1$ABCDEF0123456789ABCDEF0123456789",         // Non-numeric N
		"$4s$SALTSALT$1638$8$1$ABCDEF0123456789ABCDEF0123456789",           // Invalid N
		"$4s$SALTSALT$16384$r$1$ABCDEF0123456789ABCDEF0123456789",          // Non-numeric r
		"$4s$SALTSALT$16384$1073741824$1$ABCDEF0123456789ABCDEF0123456789", // Invalid r
		"$4s$SALTSALT$16384$8$p$ABCDEF0123456789ABCDEF0123456789",          // Non-numeric p
		"$4s$SALTSALT$16384$8$1073741824$ABCDEF0123456789ABCDEF0123456789", // Invalid p
		"$4s$SALTSALT$16384$8$1$ABCDEF0123456789",                          // Key too short
	}
	for i, test := range decodeFailTests {
		err := CompareHashAndPassword([]byte(test), []byte("t3st!nG12345"))
		if err == nil {
			t.Errorf("\t\tExpected test %d to produce an error, got nil\n", i)
		}
	}

	t.Log("\tIt should return ErrMismatchedHashAndPassword if passwords don't match")
	testEncoding := []byte("$4s$SALTSALT$16384$8$1$ABCDEF0123456789ABCDEF0123456789")
	compareErr := CompareHashAndPassword(testEncoding, []byte("t3st!nG12345"))
	if compareErr != ErrMismatchedHashAndPassword {
		t.Errorf("\t\tExpected ErrMismatchedHashAndPassword, got %v", compareErr)
	}

	// The case that passwords actually match will be tested in an integration test
	// with GenerateFromPassword.
}

/**
 * Integration tests
 */

func TestDecodingEncodedParameters(t *testing.T) {
	t.Log("integration encodeParameters <-> decodeParameters")

	t.Log("\tDecoding should be the inverse of encoding")
	testHashedValue := []byte("ABCDEF0123456789ABCDEF0123456789")
	testSalt := []byte("TESTSALT")
	testParams := HashConfiguration{16384, 8, 1, 8, 32} // N, r, p, saltLen, keyLen
	encoded := encodeParameters(testHashedValue, testSalt, testParams)
	decodedParams, decodedSalt, err := decodeParameters(encoded)
	if err != nil {
		t.Errorf("\t\tExpected decoding to not return an error. Got %v", err)
	} else {
		if !bytes.Equal(decodedSalt, testSalt) {
			t.Error("\t\tDecoded salt does not equal original")
		}
		if decodedParams.N != testParams.N {
			t.Errorf("\t\tDecoded N (%d) does not equal original (%d)\n", decodedParams.N, testParams.N)
		}
		if decodedParams.R != testParams.R {
			t.Errorf("\t\tDecoded r (%d) does not equal original (%d)\n", decodedParams.R, testParams.R)
		}
		if decodedParams.P != testParams.P {
			t.Errorf("\t\tDecoded p (%d) does not equal original (%d)\n", decodedParams.P, testParams.P)
		}
		if decodedParams.SaltLen != testParams.SaltLen {
			t.Errorf("\t\tDecoded saltLen (%d) does not equal original (%d)\n", decodedParams.SaltLen, testParams.SaltLen)
		}
		if decodedParams.KeyLen != testParams.KeyLen {
			t.Errorf("\t\tDecoded keyLen (%d) does not equal original (%d)\n", decodedParams.KeyLen, testParams.KeyLen)
		}
	}
}

func TestComparingGeneratedPasswords(t *testing.T) {
	t.Log("integration GenerateFromPassword <-> CompareHashAndPassword")

	t.Log("\tA generated hashed value should validate against the password provided")
	testPassword := []byte("t3st!nG12345")
	testParams := DefaultHashConfiguration()
	generated, generateErr := GenerateFromPassword(testPassword, testParams)
	if generateErr != nil {
		t.Errorf("\t\tExpected GenerateFromPassword to return no errors. Got %v", generateErr)
	} else {
		compareErr := CompareHashAndPassword(generated, testPassword)
		if compareErr != nil {
			t.Errorf("\t\tExpected CompareHashAndPassword to return no errors. Got %v", compareErr)
		}
	}

	t.Log("\tIncorrect passwords should not be validated without error")
	incorrectPassword := []byte("t4st!nG12345") // t4 instead of t3
	compareErr2 := CompareHashAndPassword(generated, incorrectPassword)
	if compareErr2 == nil {
		t.Error("\t\tExpected CompareHashAndPassword to return an error for incorrect passwords")
	}
}
