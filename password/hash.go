package password

import "golang.org/x/crypto/bcrypt"

func Hash(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
}

func MatchHash(pw string, hash []byte) bool {
	err := bcrypt.CompareHashAndPassword(hash, []byte(pw))
	return err == nil
}
