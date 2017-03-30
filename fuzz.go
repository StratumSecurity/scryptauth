package auth

func Fuzz(data []byte) int {
    // Setup initial values
    defaultHashConfiguration := DefaultHashConfiguration()
    hashedPassword, _ := GenerateFromPassword([]byte("t3st!nG12345"), defaultHashConfiguration)

    // Fuzz GenerateFromPassword function
    _, hashErr := GenerateFromPassword(data, defaultHashConfiguration)

    // Fuzz CompareHashAndPassword function
    compareErr := CompareHashAndPassword(hashedPassword, data)

    if hashErr == nil || compareErr == nil {
        return 1
    } else {
        return 0
    }
}
