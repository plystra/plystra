package authz

import (
	"net/http"

	"github.com/plystra/plystra/internal/kernel/contracts"
	kcap "github.com/plystra/plystra/internal/kernel/contracts/capability"
)

func RegisterRoutes(routes contracts.RouteRegistry) error {
	for _, route := range []contracts.Route{
		{Method: http.MethodPost, Path: "/api/v1/authz/check", Service: kcap.ServiceAuthorization, Operation: "Check", CapabilityID: ID},
		{Method: http.MethodPost, Path: "/api/v1/authz/explain", Service: kcap.ServiceAuthorization, Operation: "Explain", CapabilityID: ID},
	} {
		if err := routes.Register(route); err != nil {
			return err
		}
	}
	return nil
}
