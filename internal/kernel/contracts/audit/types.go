package audit

import (
	"errors"
	"fmt"
	"strings"
)

const TraceVersion = "1.0"

var ErrSensitiveField = errors.New("sensitive audit field")

func RejectSensitiveFields(metadata map[string]any) error {
	return rejectSensitiveValue("", metadata)
}

func rejectSensitiveValue(path string, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if sensitiveKey(key) {
				return fmt.Errorf("%w: %s", ErrSensitiveField, joinPath(path, key))
			}
			if err := rejectSensitiveValue(joinPath(path, key), nested); err != nil {
				return err
			}
		}
	case []any:
		for i, nested := range typed {
			if err := rejectSensitiveValue(fmt.Sprintf("%s[%d]", path, i), nested); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func sensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "api_key") ||
		strings.Contains(normalized, "authorization")
}
