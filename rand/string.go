package rand

import (
	"math/rand"
	"time"
)

// IDGenerator returns a function to generate a random
// ID of given length.
func IDGenerator(length int) func() string {
	generator := StringGenerator()
	return func() string {
		return generator(length)
	}
}

// StringGenerator returns a func to generate random string
// of given length.
func StringGenerator() func(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	src := rand.NewSource(time.Now().UnixNano())
	return func(length int) string {
		b := make([]byte, length)
		for i := range b {
			b[i] = letters[src.Int63()%int64(len(letters))]
		}
		return string(b)
	}
}
