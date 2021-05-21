package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"log"

	"golang.org/x/crypto/pbkdf2"
)

const iterCount = 1000

func HashPassword(password string) string {
	prf := byte(0x01)
	iterCount := iterCount
	saltSize := 128 / 8
	numBytesRequested := 256 / 8

	salt := make([]byte, saltSize)
	rand.Read(salt)

	subKey := pbkdf2.Key([]byte(password), salt, iterCount, numBytesRequested, resolvePRF(prf))

	// fmt.Printf("SL:\t%d\nSkL:\t%d\nSalt:\t%v\nHash:\t%v\n", len(salt), len(subKey), salt, subKey)

	outputBytes := make([]byte, 0)
	outputBytes = append(outputBytes, 0x01)
	outputBytes = append(outputBytes, toNetworkByteOrder(byte(prf))...)
	outputBytes = append(outputBytes, toNetworkByteOrder(byte(iterCount))...)
	outputBytes = append(outputBytes, toNetworkByteOrder(byte(saltSize))...)

	outputBytes = append(outputBytes, salt...)
	outputBytes = append(outputBytes, subKey...)

	return base64.StdEncoding.Strict().EncodeToString(outputBytes)
}

func VerifyPassword(hash string, password string) bool {

	hashedPassword, err := base64.StdEncoding.Strict().DecodeString(hash)

	if err != nil {
		log.Fatal("Could not decode the hash")
	}

	prf := readNetworkByteOrder(hashedPassword, 1)
	iterCount := readNetworkByteOrder(hashedPassword, 5)
	saltLength := readNetworkByteOrder(hashedPassword, 9)

	// Read the salt: must be >= 128 bits
	if saltLength < 128/8 {
		return false
	}

	salt := hashedPassword[13 : 13+saltLength]

	// Read the subkey (the rest of the payload): must be >= 128 bits
	subkeyLength := len(hashedPassword) - 13 - int(saltLength)

	if subkeyLength < 128/8 {
		return false
	}

	baseHashPos := 13 + len(salt)
	expectedSubkey := hashedPassword[baseHashPos : baseHashPos+subkeyLength]

	actualSubkey := pbkdf2.Key([]byte(password), salt, int(iterCount), subkeyLength, resolvePRF(prf))

	// fmt.Printf("Algo:\t%v, iterCount:\t%v, saltLength:\t%v\nSalt:\t%v\nHash:\t%v\nAHas:\t%v\n",
	// 	prf, iterCount, saltLength, salt,
	// 	expectedSubkey,
	// 	actualSubkey,
	// )

	return bytes.Compare(actualSubkey, expectedSubkey) == 1
}

func resolvePRF(prf byte) func() hash.Hash {
	switch int(prf) {
	case 0:
		return sha1.New
	case 1:
		return sha256.New
	case 2:
		return sha512.New
	}
	return nil
}

func readNetworkByteOrder(buffer []byte, offset int) byte {
	return buffer[offset]<<24 | buffer[offset+1]<<16 | buffer[offset+2]<<8 | buffer[offset+3]
}

func toNetworkByteOrder(value byte) string {

	return string([]byte{
		byte(value >> 24),
		byte((value >> 16) & 0xFF),
		byte((value >> 8) & 0xFF),
		byte(value & 0xFF),
	})
}
