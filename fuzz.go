package auth


func Fuzz(data []byte) int  {

  testPassword := []byte("t3st!nG12345")
	testParams := DefaultHashConfiguration()
	generated, generateErr := GenerateFromPassword(data, testParams)

	if generateErr != nil {
		panic(generateErr)
	} else {
		compareErr := CompareHashAndPassword(generated, testPassword)
		if compareErr != nil {
			panic(compareErr)
		}
  return 0
	}
}
