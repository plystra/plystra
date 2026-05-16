package admin

import (
	"net/http"

	"github.com/plystra/plystra/internal/kernel/contracts"
	kcap "github.com/plystra/plystra/internal/kernel/contracts/capability"
)

func RegisterRoutes(routes contracts.RouteRegistry) error {
	for _, route := range []contracts.Route{
		{Method: http.MethodGet, Path: "/api/v1/admin/me", Service: kcap.ServiceAdmin, Operation: "AdminMe", CapabilityID: ID},
		{Method: http.MethodGet, Path: "/api/v1/admin/grants", Service: kcap.ServiceAdmin, Operation: "ListGrants", CapabilityID: ID},
		{Method: http.MethodPost, Path: "/api/v1/admin/grants", Service: kcap.ServiceAdmin, Operation: "GrantAdmin", CapabilityID: ID},
	} {
		if err := routes.Register(route); err != nil {
			return err
		}
	}
	return nil
}
