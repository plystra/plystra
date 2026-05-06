package authz

import "encoding/json"

func (d Decision) MarshalTraceJSON() ([]byte, error) {
	return json.Marshal(d)
}
