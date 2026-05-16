package migrations

import (
	"crypto/sha256"
	"encoding/hex"
)

func Checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
