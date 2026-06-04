package audit

import (
	"net/http"

	"github.com/plystra/core/internal/kernel/contracts"
	kcap "github.com/plystra/core/internal/kernel/contracts/capability"
)

func RegisterRoutes(routes contracts.RouteRegistry) error {
	for _, route := range []contracts.Route{
		{Method: http.MethodGet, Path: "/api/v1/audit/logs", Service: kcap.ServiceAudit, Operation: "Query", CapabilityID: ID},
		{Method: http.MethodGet, Path: "/api/v1/audit/logs/{audit_log_id}", Service: kcap.ServiceAudit, Operation: "Get", CapabilityID: ID},
	} {
		if err := routes.Register(route); err != nil {
			return err
		}
	}
	return nil
}
