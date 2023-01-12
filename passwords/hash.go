package passwords

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

type Argon2Config struct {
	format  string
	version int
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
	saltLen uint32
}

var HashManager = &Argon2Config{
	format:  "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
	version: argon2.Version,
	time:    1,
	memory:  64 * 1024,
	threads: 4,
	keyLen:  32,
	saltLen: 16,
}

func (a2c *Argon2Config) Hash(value string) (string, error) {
	// Generate a Salt
	salt := make([]byte, a2c.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(value), salt, a2c.time, a2c.memory, a2c.threads, a2c.keyLen)

	hashed := fmt.Sprintf(a2c.format, a2c.version, a2c.memory, a2c.time, a2c.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return hashed, nil
}

func (a2c *Argon2Config) Verify(hash string, plain string) (bool, error) {
	hashParts := strings.Split(hash, "$")

	salt, err := base64.RawStdEncoding.DecodeString(hashParts[4])
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(hashParts[5])
	if err != nil {
		return false, err
	}

	hashCompare := argon2.IDKey([]byte(plain), salt, a2c.time, a2c.memory, a2c.threads, a2c.keyLen)

	return subtle.ConstantTimeCompare(decodedHash, hashCompare) == 1, nil
}
