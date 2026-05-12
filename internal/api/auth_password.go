package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory      uint32 = 64 * 1024
	argon2Iterations  uint32 = 3
	argon2Parallelism uint8  = 2
	argon2SaltLength         = 16
	argon2KeyLength          = 32
)

var passwordEncoding = base64.RawStdEncoding

func hashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLength)
	return fmt.Sprintf(
		"argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory,
		argon2Iterations,
		argon2Parallelism,
		passwordEncoding.EncodeToString(salt),
		passwordEncoding.EncodeToString(key),
	), nil
}

func verifyPassword(password, encoded string) bool {
	if !strings.HasPrefix(encoded, "argon2id$") {
		return false
	}
	return verifyArgon2IDPassword(password, encoded)
}

func passwordNeedsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return true
	}
	memory, iterations, parallelism, ok := parseArgon2Params(parts[2])
	return !ok || memory != argon2Memory || iterations != argon2Iterations || parallelism != argon2Parallelism
}

func verifyArgon2IDPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	memory, iterations, parallelism, ok := parseArgon2Params(parts[2])
	if !ok || memory < 19*1024 || iterations < 1 || parallelism < 1 || memory > 1024*1024 || iterations > 10 || parallelism > 16 {
		return false
	}
	salt, err := passwordEncoding.DecodeString(parts[3])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return false
	}
	want, err := passwordEncoding.DecodeString(parts[4])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parseArgon2Params(encoded string) (memory uint32, iterations uint32, parallelism uint8, ok bool) {
	values := map[string]string{}
	for _, part := range strings.Split(encoded, ",") {
		key, value, found := strings.Cut(part, "=")
		if !found {
			return 0, 0, 0, false
		}
		values[key] = value
	}
	parsedMemory, err := strconv.ParseUint(values["m"], 10, 32)
	if err != nil {
		return 0, 0, 0, false
	}
	parsedIterations, err := strconv.ParseUint(values["t"], 10, 32)
	if err != nil {
		return 0, 0, 0, false
	}
	parsedParallelism, err := strconv.ParseUint(values["p"], 10, 8)
	if err != nil {
		return 0, 0, 0, false
	}
	return uint32(parsedMemory), uint32(parsedIterations), uint8(parsedParallelism), true
}
