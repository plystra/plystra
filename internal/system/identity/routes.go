package identity

import (
	"net/http"

	"github.com/plystra/core/internal/kernel/contracts"
	kcap "github.com/plystra/core/internal/kernel/contracts/capability"
)

func RegisterRoutes(routes contracts.RouteRegistry) error {
	for _, route := range []contracts.Route{
		{Method: http.MethodGet, Path: "/api/v1/users", Service: kcap.ServiceIdentity, Operation: "ListUsers", CapabilityID: ID},
		{Method: http.MethodPost, Path: "/api/v1/users", Service: kcap.ServiceIdentity, Operation: "CreateUser", CapabilityID: ID},
		{Method: http.MethodGet, Path: "/api/v1/spaces", Service: kcap.ServiceIdentity, Operation: "ListSpaces", CapabilityID: ID},
		{Method: http.MethodPost, Path: "/api/v1/spaces", Service: kcap.ServiceIdentity, Operation: "CreateSpace", CapabilityID: ID},
		{Method: http.MethodGet, Path: "/api/v1/actor/context", Service: kcap.ServiceIdentity, Operation: "ResolveActor", CapabilityID: ID},
	} {
		if err := routes.Register(route); err != nil {
			return err
		}
	}
	return nil
}
