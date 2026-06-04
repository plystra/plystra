package resource_registry

import (
	"net/http"

	"github.com/plystra/core/internal/kernel/contracts"
	kcap "github.com/plystra/core/internal/kernel/contracts/capability"
)

func RegisterRoutes(routes contracts.RouteRegistry) error {
	for _, route := range []contracts.Route{
		{Method: http.MethodGet, Path: "/api/v1/resource-types", Service: kcap.ServiceResourceRegistry, Operation: "ListResourceTypes", CapabilityID: ID},
		{Method: http.MethodPost, Path: "/api/v1/resource-types", Service: kcap.ServiceResourceRegistry, Operation: "RegisterResourceType", CapabilityID: ID},
		{Method: http.MethodGet, Path: "/api/v1/resources", Service: kcap.ServiceResourceRegistry, Operation: "ListResources", CapabilityID: ID},
		{Method: http.MethodPost, Path: "/api/v1/resources", Service: kcap.ServiceResourceRegistry, Operation: "RegisterResource", CapabilityID: ID},
	} {
		if err := routes.Register(route); err != nil {
			return err
		}
	}
	return nil
}
