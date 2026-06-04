package api

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

const (
	maxGovernedJSONDepth       = 12
	maxGovernedJSONObjectKeys  = 256
	maxGovernedJSONArrayItems  = 1024
	maxGovernedJSONTotalNodes  = 5000
	maxGovernedMetadataBytes   = 16 << 10
	maxAppDataModelSchemaBytes = 64 << 10
	maxAppDataRecordDataBytes  = 256 << 10
	maxPluginSettingValueBytes = 64 << 10
)

var sensitiveConfigKeyMarkers = []string{
	"api_key",
	"apikey",
	"auth_token",
	"credential",
	"password",
	"private_key",
	"secret",
	"token",
}

type governedJSONPolicy struct {
	MaxBytes      int
	RejectSecrets bool
}

func validateGovernedMetadata(field string, value map[string]any) error {
	return validateGovernedJSONValue(field, value, governedJSONPolicy{MaxBytes: maxGovernedMetadataBytes, RejectSecrets: true})
}

func validateGovernedJSONValue(field string, value any, policy governedJSONPolicy) error {
	if value == nil {
		return nil
	}
	if policy.MaxBytes > 0 {
		raw, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("%s must be valid JSON", field)
		}
		if len(raw) > policy.MaxBytes {
			return fmt.Errorf("%s must be %d bytes or fewer", field, policy.MaxBytes)
		}
	}
	nodes := 0
	if err := validateGovernedJSONNode(field, value, 0, policy.RejectSecrets, &nodes); err != nil {
		return err
	}
	return nil
}

func validateGovernedJSONNode(path string, value any, depth int, rejectSecrets bool, nodes *int) error {
	*nodes = *nodes + 1
	if *nodes > maxGovernedJSONTotalNodes {
		return fmt.Errorf("%s has too many JSON nodes", path)
	}
	if depth > maxGovernedJSONDepth {
		return fmt.Errorf("%s exceeds maximum JSON depth %d", path, maxGovernedJSONDepth)
	}
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) > maxGovernedJSONObjectKeys {
			return fmt.Errorf("%s has too many object keys", path)
		}
		for key, child := range typed {
			key = strings.TrimSpace(key)
			if key == "" {
				return fmt.Errorf("%s contains an empty object key", path)
			}
			if len(key) > 128 {
				return fmt.Errorf("%s contains an object key longer than 128 characters", path)
			}
			if strings.ContainsAny(key, "\x00\r\n\t") {
				return fmt.Errorf("%s contains an object key with control characters", path)
			}
			if rejectSecrets && sensitiveConfigLikeKey(key) {
				return fmt.Errorf("%s must not contain secret-like key %q", path, key)
			}
			if err := validateGovernedJSONNode(path+"."+key, child, depth+1, rejectSecrets, nodes); err != nil {
				return err
			}
		}
	case []any:
		if len(typed) > maxGovernedJSONArrayItems {
			return fmt.Errorf("%s has too many array items", path)
		}
		for i, child := range typed {
			if err := validateGovernedJSONNode(fmt.Sprintf("%s[%d]", path, i), child, depth+1, rejectSecrets, nodes); err != nil {
				return err
			}
		}
	case string:
		if len(typed) > 8192 {
			return fmt.Errorf("%s contains a string longer than 8192 bytes", path)
		}
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return fmt.Errorf("%s contains a non-finite number", path)
		}
	case float32:
		value := float64(typed)
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return fmt.Errorf("%s contains a non-finite number", path)
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return nil
	case nil, bool:
		return nil
	default:
		return fmt.Errorf("%s contains unsupported JSON value type %T", path, value)
	}
	return nil
}

func sensitiveConfigLikeKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, ".", "_")
	for _, marker := range sensitiveConfigKeyMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
