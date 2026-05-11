package entstore

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	coreent "github.com/plystra/plystra/ent"
)

func isNotFound(err error) bool {
	return coreent.IsNotFound(err)
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func nilIfEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func nonNilMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	return value
}

func setNullableString[T any](set func(string) T, clear func() T, value string) {
	if value == "" {
		clear()
		return
	}
	set(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func newID(prefix string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return prefix + "_" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	}
	return prefix + "_" + hex.EncodeToString(buf[:])
}
