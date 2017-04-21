 package auth

func Fuzz(data []byte) int {
    // Setup initial values
    defaultHashConfiguration := DefaultHashConfiguration()
    hashedPassword := []byte("$4s$WiBIb+gP0/I=$32768$8$1$NtuN5cEoCBIBpPHE3uUVoY+nFH2dHaG1Q9m2bLSzEGo=")

    // Fuzz CompareHashAndPassword function
    if compareErr := CompareHashAndPassword(hashedPassword, data); compareErr == nil {
        //panic("This corpus successfully compared to the hashedPassword")
        return -1
    }

    // Fuzz GenerateFromPassword function
    if _, hashErr := GenerateFromPassword(data, defaultHashConfiguration); hashErr != nil {
        return 0
    }

    return 1
}
